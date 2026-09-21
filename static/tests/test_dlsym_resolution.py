"""Regression checks for global dlsym resolution and coordinated cleanup."""

from collections import defaultdict
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from code_analyser import CodeAnalyser
from library_analyser import Library, LibraryUsageAnalyser
import utils


class DlsymResolutionTests(unittest.TestCase):
    def setUp(self):
        self.libraries = {}
        self.effects = {}
        self.found = set()
        patches = [
            patch.object(LibraryUsageAnalyser,
                         '_LibraryUsageAnalyser__libraries', self.libraries),
            patch.object(LibraryUsageAnalyser,
                         '_LibraryUsageAnalyser__analysed_functions', set()),
            patch.object(LibraryUsageAnalyser,
                         '_LibraryUsageAnalyser__get_function_insns',
                         side_effect=lambda function: function),
        ]
        patches.extend(patch.object(utils, name, value) for name, value in (
            ('logging', False), ('show_errors', False),
            ('show_warnings', False), ('analyse_linker', False),
            ('all_imported_functions', False), ('cur_depth', -1)))
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.main = self.make_analyser('main', register=False)
        self.coordinator = self.main._CodeAnalyser__lib_analyser

    def make_analyser(self, name, pending=(), used=(), symbols=(), register=True):
        analyser = CodeAnalyser.__new__(CodeAnalyser)
        analyser.elf_analyser = SimpleNamespace(binary=SimpleNamespace(
            path=name, has_dyn_libraries=True))
        analyser._CodeAnalyser__dlsym_f_names = set(pending)
        owner = LibraryUsageAnalyser.__new__(LibraryUsageAnalyser)
        owner.elf_analyser = analyser.elf_analyser
        owner._LibraryUsageAnalyser__used_libraries = list(used)
        owner._LibraryUsageAnalyser__potentially_used_libraries = []
        owner._LibraryUsageAnalyser__used_libraries_aliases = defaultdict(list)
        analyser._CodeAnalyser__lib_analyser = owner
        analyser.get_used_syscalls_all_executable_sections = Mock()
        analyser.analyse_imported_functions = Mock()

        def analyse_body(function, found, called):
            effect = self.effects.get((name, function.name))
            if effect is not None:
                effect(found)

        analyser.analyse_code = Mock(side_effect=analyse_body)
        if register:
            self.libraries[name] = Library(
                path=name, code_analyser=analyser,
                callable_fun_boundaries={symbol: (16 * index, 16 * index + 8)
                                         for index, symbol in enumerate(symbols, 1)})
        return analyser

    def test_local_resolution_retains_missing_names_until_explicit_cleanup(self):
        self.make_analyser('provider', symbols=('target',))
        analyser = self.make_analyser('caller', pending=('target', 'missing', 'syscall'),
                                     used=('provider',))
        self.effects['provider', 'target'] = lambda found: found.add('getpid')
        self.assertTrue(analyser.analyse_detected_dlsym_functions(self.found))
        self.assertEqual(self.found, {'getpid'})
        self.assertEqual(analyser._CodeAnalyser__dlsym_f_names, {'missing'})
        self.assertFalse(analyser.analyse_detected_dlsym_functions(self.found))
        self.assertEqual(analyser._CodeAnalyser__dlsym_f_names, {'missing'})
        analyser.clean_dlsym_f_names()
        self.assertEqual(analyser._CodeAnalyser__dlsym_f_names, set())

    def test_launch_resolves_names_from_main_or_only_from_dependency(self):
        for source in ('main', 'dependency'):
            with self.subTest(source=source):
                target = 'target_' + source
                provider = 'provider_' + source
                self.make_analyser(provider, symbols=(target,))
                caller = self.main if source == 'main' else self.make_analyser(source)
                caller._CodeAnalyser__dlsym_f_names.add(target)
                caller._CodeAnalyser__lib_analyser._LibraryUsageAnalyser__used_libraries.append(provider)
                self.effects[provider, target] = lambda found: found.add(target)
                self.main.launch_analysis(self.found)
                self.assertIn(target, self.found)
                self.assertEqual(caller._CodeAnalyser__dlsym_f_names, set())

    def test_later_library_registration_retries_earlier_unresolved_names(self):
        self.main._CodeAnalyser__dlsym_f_names.add('target')
        self.coordinator._LibraryUsageAnalyser__used_libraries.append('payload')
        earlier = self.make_analyser('earlier', pending=('target',), used=('payload',))
        self.make_analyser('loader', pending=('load',), used=('loader',), symbols=('load',))

        def load_payload(found):
            self.assertEqual(self.main._CodeAnalyser__dlsym_f_names, {'target'})
            self.assertEqual(earlier._CodeAnalyser__dlsym_f_names, {'target'})
            self.make_analyser('payload', symbols=('target',))

        self.effects['loader', 'load'] = load_payload
        self.effects['payload', 'target'] = lambda found: found.add('getppid')
        self.main.launch_analysis(self.found)
        self.assertEqual(self.found, {'getppid'})
        self.libraries['payload'].code_analyser.analyse_code.assert_called_once()
        self.assertEqual(earlier._CodeAnalyser__dlsym_f_names, set())

    def test_retry_after_owner_gains_access_to_an_existing_library(self):
        earlier = self.make_analyser('earlier', pending=('target',), symbols=('load',))
        self.make_analyser('later', pending=('load',), used=('earlier',))
        self.make_analyser('payload', symbols=('target',))
        used = earlier._CodeAnalyser__lib_analyser._LibraryUsageAnalyser__used_libraries
        self.effects['earlier', 'load'] = lambda found: used.append('payload')
        self.effects['payload', 'target'] = lambda found: found.add('getppid')
        self.main.launch_analysis(self.found)
        self.assertEqual(self.found, {'getppid'})

    def test_library_added_during_snapshot_is_processed_on_next_pass(self):
        self.make_analyser('loader', pending=('load',), used=('loader',), symbols=('load',))
        self.effects['loader', 'load'] = lambda found: self.make_analyser(
            'new', pending=('target',), used=('new',), symbols=('target',))
        self.effects['new', 'target'] = lambda found: found.add('getpid')
        self.assertTrue(self.coordinator.analyse_detected_dlsym_for_all_libs(self.found))
        self.assertEqual(self.found, set())
        self.assertEqual(self.libraries['new'].code_analyser._CodeAnalyser__dlsym_f_names,
                         {'target'})
        self.main.launch_analysis(self.found)
        self.assertEqual(self.found, {'getpid'})

    def test_new_library_keeps_global_loop_running_without_local_progress(self):
        discoverer = Mock()

        def discover(found):
            if 'new' not in self.libraries:
                self.make_analyser('new', pending=('target',), used=('new',),
                                   symbols=('target',))
            return False

        discoverer.analyse_detected_dlsym_functions.side_effect = discover
        self.libraries['discoverer'] = SimpleNamespace(code_analyser=discoverer)
        self.effects['new', 'target'] = lambda found: found.add('getpid')
        self.main.launch_analysis(self.found)
        self.assertEqual(self.found, {'getpid'})
        discoverer.clean_dlsym_f_names.assert_called_once()

    def test_library_pass_visits_every_available_analyser(self):
        for name in ('first', 'second'):
            self.make_analyser(name, pending=(name,), used=(name,), symbols=(name,))
            self.effects[name, name] = lambda found, name=name: found.add(name)
        self.libraries['unavailable'] = SimpleNamespace(code_analyser=None)
        self.assertTrue(self.coordinator.analyse_detected_dlsym_for_all_libs(self.found))
        self.assertEqual(self.found, {'first', 'second'})
        self.assertFalse(self.coordinator.analyse_detected_dlsym_for_all_libs(self.found))

    def test_dlsym_cycle_analyzes_each_function_only_once(self):
        first = self.make_analyser('first', pending=('second',), used=('second',),
                                   symbols=('first',))
        second = self.make_analyser('second', used=('first',), symbols=('second',))
        self.effects['second', 'second'] = lambda found: second._CodeAnalyser__dlsym_f_names.add('first')
        self.effects['first', 'first'] = lambda found: first._CodeAnalyser__dlsym_f_names.add('second')
        self.main.launch_analysis(self.found)
        first.analyse_code.assert_called_once()
        second.analyse_code.assert_called_once()
        self.assertEqual(first._CodeAnalyser__dlsym_f_names, set())
        self.assertEqual(second._CodeAnalyser__dlsym_f_names, set())

    def test_unresolved_names_are_cleared_only_after_a_complete_idle_pass(self):
        self.main._CodeAnalyser__dlsym_f_names.add('missing_main')
        dependency = self.make_analyser('dependency', pending=('missing_dependency',))
        observer = Mock()

        def observe(found):
            self.assertEqual(self.main._CodeAnalyser__dlsym_f_names, {'missing_main'})
            self.assertEqual(dependency._CodeAnalyser__dlsym_f_names, {'missing_dependency'})
            return False

        observer.analyse_detected_dlsym_functions.side_effect = observe
        self.libraries['observer'] = SimpleNamespace(code_analyser=observer)
        self.libraries['unavailable'] = SimpleNamespace(code_analyser=None)
        self.main.launch_analysis(self.found)
        observer.analyse_detected_dlsym_functions.assert_called_once()
        observer.clean_dlsym_f_names.assert_called_once()
        self.assertEqual(self.main._CodeAnalyser__dlsym_f_names, set())
        self.assertEqual(dependency._CodeAnalyser__dlsym_f_names, set())

    def test_global_resolution_preserves_each_owners_library_scope(self):
        self.main._CodeAnalyser__dlsym_f_names.add('target')
        unrelated = self.make_analyser('unrelated', symbols=('target',))
        self.main.launch_analysis(self.found)
        unrelated.analyse_code.assert_not_called()

    def test_static_binary_needs_no_library_analyser(self):
        self.main.elf_analyser.binary.has_dyn_libraries = False
        del self.main._CodeAnalyser__lib_analyser
        self.main.launch_analysis(self.found)
        self.main.get_used_syscalls_all_executable_sections.assert_called_once_with(self.found)


if __name__ == '__main__':
    unittest.main()
