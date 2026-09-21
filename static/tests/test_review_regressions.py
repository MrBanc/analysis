"""Regression cases found while reviewing the existing analyser features."""

from collections import defaultdict
from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import asm_code_utils
from code_analyser import CodeAnalyser
from custom_exception import StaticAnalyserException
from elf_analyser import ELFAnalyser
import library_analyser
from library_analyser import LibFunction, LibraryUsageAnalyser
import static_analyser
import syscalls
import utils


ROOT = Path(__file__).resolve().parents[1]


class OutputAndInputTests(unittest.TestCase):
    def test_fadvise_wrapper_symbol_uses_existing_syscall_name(self):
        analyser = ELFAnalyser.__new__(ELFAnalyser)
        analyser.binary = SimpleNamespace(lief_binary=SimpleNamespace(
                dynamic_symbols=[SimpleNamespace(name='posix_fadvise64')],
                symtab_symbols=[], symbols=[]))
        found = set()
        with patch.object(syscalls, 'syscalls_map', {221: 'fadvise64'}):
            analyser.get_syscalls_from_symbols(found)
        self.assertEqual(found, {'fadvise64'})

    def test_csv_contains_syscall_names(self):
        output = io.StringIO()
        with patch.object(syscalls, 'syscalls_map', {0: 'read', 60: 'exit'}), \
                patch.object(utils, 'display_csv', True), \
                patch.object(utils, 'display_syscalls', False), \
                patch.object(utils, 'display_nb_syscalls', False), \
                redirect_stdout(output):
            static_analyser.display_results({'exit'})
        self.assertEqual(output.getvalue(), '# syscall, used\nread,N\nexit,Y\n')

    def test_map_reload_replaces_previous_entries(self):
        for content in ('0 read\n1 write\n', 'read 0\nwrite 1\n',
                        '# comment\n0 common read sys_read\n1 common write sys_write\n'):
            with self.subTest(content=content), TemporaryDirectory() as folder, \
                    patch.object(syscalls, 'syscalls_map', {99: 'old'}):
                path = Path(folder) / 'map'
                path.write_text(content, encoding='utf-8')
                syscalls.initialise_syscalls_map(path)
                self.assertEqual(syscalls.syscalls_map, {0: 'read', 1: 'write'})

    def test_invalid_maps_raise_recoverable_errors_without_partial_updates(self):
        for content in (b'', b'0 read\n1\n', b'0 read\nx write\n', b'\xff'):
            with self.subTest(content=content), TemporaryDirectory() as folder, \
                    patch.object(syscalls, 'syscalls_map', {99: 'old'}):
                path = Path(folder) / 'map'
                path.write_bytes(content)
                with self.assertRaises(StaticAnalyserException):
                    syscalls.initialise_syscalls_map(path)
                self.assertEqual(syscalls.syscalls_map, {99: 'old'})

    def test_default_map_is_independent_of_working_directory(self):
        with TemporaryDirectory() as folder:
            result = subprocess.run(
                    [sys.executable, '-c',
                     f'import sys; sys.path.insert(0, {str(ROOT)!r}); '
                     'import utils, syscalls; '
                     'syscalls.initialise_syscalls_map(utils.sys_map); '
                     'assert syscalls.syscalls_map[60] == "exit"'],
                    cwd=folder, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_map_cli_error_has_no_traceback(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'map'
            path.write_text('0 read\n1\n', encoding='utf-8')
            result = subprocess.run(
                    [sys.executable, str(ROOT / 'static_analyser.py'),
                     '-a', 'unused', '-s', str(path)],
                    cwd=folder, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('line 2', result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_logging_creates_missing_directory_and_resets_files(self):
        with TemporaryDirectory() as folder, \
                patch.object(utils, 'log_dir_path', str(Path(folder) / 'logs')), \
                patch.object(utils, 'logging', True), \
                patch.object(utils, 'use_log_file', True):
            utils.clean_logs()
            utils.log('message', 'backtrack.log')
            path = Path(utils.log_dir_path) / 'backtrack.log'
            self.assertEqual(path.read_text(), 'message\n')
            utils.clean_logs()
            self.assertEqual(path.read_text(), '')

    def test_logging_initialisation_error_is_recoverable(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'file'
            path.touch()
            with patch.object(utils, 'log_dir_path', str(path)):
                with self.assertRaises(StaticAnalyserException):
                    utils.clean_logs()


class BacktrackingTests(unittest.TestCase):
    def setUp(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.analyser = SimpleNamespace(
                binary=SimpleNamespace(path='fixture'),
                resolve_address_stored_at=lambda *_: None)

    def backtrack(self, code, focus='eax'):
        insns = list(self.md.disasm(bytes.fromhex(code), 0x1000))
        with patch.object(utils, 'app', 'other'), \
                patch.object(utils, 'show_warnings', False), \
                patch.object(utils, 'show_errors', False):
            return asm_code_utils.value_backtracker(focus, insns, self.analyser)

    def test_byte_register_writes_continue_with_warning(self):
        for instruction, expected in (('b027', 39), ('b427', 39),
                                      ('30c0', 0), ('30e4', 0)):
            with self.subTest(instruction=instruction), \
                    patch.object(utils, 'print_warning') as warning:
                self.assertEqual(self.backtrack(
                        'b83c000000' + instruction + '0f05'), expected)
                warning.assert_called_once()
                self.assertIn('may be incorrect', warning.call_args.args[0])
        self.assertEqual(self.backtrack('41b83c00000041b0270f05', 'r8d'), 39)

    def test_writes_of_at_least_sixteen_bits_remain_supported(self):
        for instruction in ('66b83c00', 'b83c000000', '48c7c03c000000'):
            with self.subTest(instruction=instruction), \
                    patch.object(utils, 'print_warning') as warning:
                self.assertEqual(self.backtrack(instruction + '0f05'), 60)
                warning.assert_not_called()

    def test_byte_memory_write_continues_with_warning(self):
        with patch.object(utils, 'print_warning') as warning, \
                patch.object(utils, 'log') as log:
            self.assertEqual(self.backtrack('c745fc3c120000c645fc018b45fc0f05'), 1)
        warning.assert_called_once()
        message = warning.call_args.args[0]
        self.assertIn('may be incorrect', message)
        log.assert_any_call(message, 'backtrack.log', indent=2)

    def test_signed_register_moves_use_operand_widths(self):
        cases = (
                ('b1800fbec10f05', 0xffffff80),
                ('b9800000000fbec10f05', 0xffffff80),
                ('b97f0000000fbec10f05', 0x7f),
                ('b9008000000fbfc10f05', 0xffff8000),
                ('b9ff7f00000fbfc10f05', 0x7fff),
                ('b9000000804863c10f05', 0xffffffff80000000),
                ('b9ffffff7f4863c10f05', 0x7fffffff),
                ('b980000000480fbec10f05', 0xffffffffffffff80),
                ('b900800000480fbfc10f05', 0xffffffffffff8000),
                ('b980000000660fbec10f05', 0xff80),
                ('b9008000000fbec50f05', 0xffffff80),
                ('b9ff7f00000fbec50f05', 0x7f),
                ('48b93c000000010000000fbec10f05', 60),
        )
        for code, expected in cases:
            with self.subTest(code=code):
                self.assertEqual(self.backtrack(code), expected)

    def test_signed_memory_moves_use_operand_widths(self):
        for code, value, width, expected in (
                ('0fbe05000000000f05', 0x80, 1, 0xffffff80),
                ('480fbe05000000000f05', 0x80, 1, 0xffffffffffffff80),
                ('0fbf05000000000f05', 0x8000, 2, 0xffff8000),
                ('486305000000000f05', 0x80000000, 4, 0xffffffff80000000)):
            with self.subTest(code=code):
                resolver = Mock(return_value=asm_code_utils.Address(value, True))
                with patch.object(self.analyser, 'resolve_address_stored_at', resolver):
                    self.assertEqual(self.backtrack(code), expected)
                resolver.assert_called_once_with(0x1000 + len(bytes.fromhex(code)) - 2, width)

    def test_signed_moves_preserve_unresolved_sources(self):
        self.assertIsNone(self.backtrack('0fbec10f05'))
        resolver = Mock(return_value=asm_code_utils.Address(0, False, 'external'))
        with patch.object(self.analyser, 'resolve_address_stored_at', resolver):
            self.assertIsNone(self.backtrack('0fbe05000000000f05'))

    def test_partial_write_does_not_abort_the_remaining_code(self):
        analyser = CodeAnalyser.__new__(CodeAnalyser)
        analyser.elf_analyser = self.analyser
        self.analyser.binary.has_dyn_libraries = False
        code = bytes.fromhex('b83c000000b03c0f05b8270000000f05')
        found = set()
        with patch.object(utils, 'app', 'other'), \
                patch.object(utils, 'print_warning') as warning, \
                patch.object(syscalls, 'syscalls_map', {39: 'getpid', 60: 'exit'}):
            count = analyser.analyse_code(self.md.disasm(code, 0x1000), found)
        self.assertEqual(found, {'exit', 'getpid'})
        self.assertEqual(count, len(code))
        warning.assert_called_once()

    def test_rsp_stack_store_is_found(self):
        # mov [rsp], 60; mov eax, [rsp]; syscall
        self.assertEqual(self.backtrack('c704243c0000008b04240f05'), 60)

    def test_read_only_memory_operands_do_not_hide_prior_store(self):
        # mov [rbp-4], 60; cmp/test [rbp-4], 0; mov eax, [rbp-4]; syscall
        for read in ('837dfc00', 'f745fc00000000'):
            with self.subTest(read=read):
                self.assertEqual(self.backtrack(
                        'c745fc3c000000' + read + '8b45fc0f05'), 60)

    def test_absolute_memory_backtracking(self):
        # mov dword ptr [0x2000], 60; mov eax, dword ptr [0x2000]; syscall
        with patch.object(utils, 'backtrack_memory', True):
            self.assertEqual(self.backtrack(
                    'c70425002000003c0000008b0425002000000f05'), 60)

    def test_stack_backtracking_can_still_be_disabled(self):
        with patch.object(utils, 'backtrack_stack', False):
            self.assertIsNone(self.backtrack('c704243c0000008b04240f05'))

    def test_register_alias_is_accepted(self):
        self.assertEqual(self.backtrack('b83c0000000f05', 'rax'), 60)

    def test_empty_instruction_list_is_unresolved(self):
        with patch.object(utils, 'app', 'fixture'):
            self.assertIsNone(asm_code_utils.value_backtracker(
                    'eax', [], self.analyser))

    def test_invalid_first_byte_recovers_at_next_known_function(self):
        analyser = CodeAnalyser.__new__(CodeAnalyser)
        analyser._CodeAnalyser__md = self.md
        analyser.elf_analyser = self.analyser
        self.analyser.binary.has_dyn_libraries = False
        self.analyser.find_next_function_addr = lambda _: 0x1001
        self.analyser.find_next_symbol_addr = lambda _: 0x1001
        section = SimpleNamespace(size=8, virtual_address=0x1000,
                                  content=bytes.fromhex('06b83c0000000f05'), name='.text')
        found = set()
        with patch.object(utils, 'app', 'other'), \
                patch.object(utils, 'show_errors', False), \
                patch.object(utils, 'show_warnings', False), \
                patch.object(syscalls, 'syscalls_map', {60: 'exit'}):
            analyser.get_used_syscalls_of_section(section, found)
        self.assertEqual(found, {'exit'})

    def test_unresolved_local_plt_target_is_removed_from_library_targets(self):
        local = LibFunction('', 'fixture', (0x1000, -1))
        external = LibFunction('write', 'lib.so', (0x2000, 0x2100))
        source, target = [local, external], []
        analyser = Mock()
        analyser.get_local_function_called.return_value = None
        with patch.object(utils, 'show_errors', False):
            asm_code_utils.mov_local_funs_to(target, source, analyser)
        self.assertEqual(source, [external])
        self.assertEqual(target, [])


class LibraryResolutionTests(unittest.TestCase):
    def setUp(self):
        self.analyser = LibraryUsageAnalyser.__new__(LibraryUsageAnalyser)
        self.analyser.elf_analyser = SimpleNamespace(
                binary=SimpleNamespace(path='fixture'))
        self.analyser._LibraryUsageAnalyser__used_libraries = []
        self.analyser._LibraryUsageAnalyser__potentially_used_libraries = []
        self.analyser._LibraryUsageAnalyser__used_libraries_aliases = defaultdict(list)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.analyser._LibraryUsageAnalyser__md = self.md
        self.analyser._LibraryUsageAnalyser__plt_section = None
        self.analyser._LibraryUsageAnalyser__plt_sec_section = None
        self.cache_patch = patch.object(
                LibraryUsageAnalyser, '_LibraryUsageAnalyser__libraries', {})
        self.libraries = self.cache_patch.start()
        self.addCleanup(self.cache_patch.stop)

    def section(self, address, code):
        content = bytes.fromhex(code)
        return SimpleNamespace(virtual_address=address, size=len(content), content=content)

    def got_address(self, address, **kwargs):
        return self.analyser._LibraryUsageAnalyser__get_got_rel_address(address, **kwargs)

    def test_plt_displacement_sign_and_zero(self):
        for displacement, expected in (('faffffff', 0x1000),
                                       ('00000000', 0x1006),
                                       ('10000000', 0x1016)):
            with self.subTest(displacement=displacement):
                self.analyser._LibraryUsageAnalyser__plt_section = self.section(
                        0x1000, 'ff25' + displacement)
                self.assertEqual(self.got_address(0x1000), expected)

    def test_both_plt_sections_are_resolved(self):
        self.analyser._LibraryUsageAnalyser__plt_section = self.section(0x1000, 'ff2500000000')
        self.analyser._LibraryUsageAnalyser__plt_sec_section = self.section(
                0x2000, 'f30f1efaff2500000000')
        self.assertTrue(self.analyser.is_call_to_plt(0x1000))
        self.assertTrue(self.analyser.is_call_to_plt(0x2000))
        self.assertFalse(self.analyser.is_call_to_plt(0x200a))
        self.assertEqual(self.got_address(0x1000), 0x1006)
        self.assertEqual(self.got_address(0x2000), 0x200a)

    def test_truncated_or_unexpected_plt_entries_are_unresolved(self):
        for code in ('ff', 'f30f1efa', '90', '0000'):
            with self.subTest(code=code):
                self.analyser._LibraryUsageAnalyser__plt_section = self.section(0x1000, code)
                self.assertIsNone(self.got_address(0x1000))

    def test_plt_resolver_skips_push(self):
        self.analyser._LibraryUsageAnalyser__plt_section = self.section(
                0x1000, 'ff3500000000ff2500000000')
        self.assertEqual(self.got_address(0x1000, is_first_plt_entry=True), 0x100c)

    def test_gnu_script_does_not_include_delimiters_in_paths(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / 'lib.so'
            path.write_text('GROUP (/tmp/a.so AS_NEEDED (/tmp/b.so))\n'
                            'INPUT (/tmp/c.so, /tmp/d.so);\n', encoding='utf-8')
            self.assertEqual(self.analyser.get_lib_from_GNU_ld_script(path),
                             ['/tmp/a.so', '/tmp/b.so', '/tmp/c.so', '/tmp/d.so'])

    def test_manual_library_lookup_rejects_directories_and_keeps_file_symlinks(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'lib.so').write_text('INPUT (/tmp/target.so)\n', encoding='utf-8')
            (root / 'alias.so').symlink_to(root / 'lib.so')
            (root / 'directory.so').mkdir()
            (root / 'directory-link.so').symlink_to(root / 'directory.so')
            names = ['.', '', 'directory.so', 'directory-link.so', 'missing.so',
                     'lib.so', 'alias.so']
            with patch.object(library_analyser, 'LIB_DIRS', [folder + '/']):
                paths = self.analyser.get_libraries_paths_manually(names)
            self.assertEqual(paths, [str(root / 'lib.so'), str(root / 'alias.so')])
            self.assertEqual(names, ['.', '', 'directory.so', 'directory-link.so',
                                     'missing.so'])

    def test_gnu_script_directory_or_missing_path_is_recoverable(self):
        with TemporaryDirectory() as folder:
            for path in (folder, str(Path(folder) / 'missing.so')):
                with self.subTest(path=path), patch.object(utils, 'print_error') as error:
                    self.assertEqual(self.analyser.get_lib_from_GNU_ld_script(path), [])
                    error.assert_called_once()
                    self.assertIn(path, error.call_args.args[0])

    def test_gnu_script_permission_error_is_recoverable(self):
        with patch('builtins.open', side_effect=PermissionError('denied')), \
                patch.object(utils, 'print_error') as error:
            self.assertEqual(self.analyser.get_lib_from_GNU_ld_script('/lib.so'), [])
        error.assert_called_once()

    def test_missing_versioned_library_falls_back_to_available_libraries(self):
        self.analyser._LibraryUsageAnalyser__used_libraries_aliases['VERSION'] = ['missing.so']
        self.analyser._LibraryUsageAnalyser__used_libraries = ['available.so']
        self.libraries['available.so'] = SimpleNamespace(
                path='/available.so', callable_fun_boundaries={'write': (1, 2)})
        functions = self.analyser.get_function_with_name('write', lib_alias='VERSION')
        self.assertEqual([f.library_path for f in functions], ['/available.so'])

    def test_repeated_ldd_dependency_stays_potential_until_explicitly_used(self):
        self.libraries['lib.so'] = SimpleNamespace(path='/lib.so')
        with patch('library_analyser.exists', return_value=True):
            self.analyser.add_used_library('/lib.so', added_by_ldd=True)
            self.analyser.add_used_library('/lib.so', added_by_ldd=True)
            self.assertEqual(self.analyser._LibraryUsageAnalyser__used_libraries, [])
            self.assertEqual(self.analyser._LibraryUsageAnalyser__potentially_used_libraries,
                             ['lib.so'])
            self.analyser.add_used_library('/lib.so')
        self.assertEqual(self.analyser._LibraryUsageAnalyser__used_libraries, ['lib.so'])
        self.assertEqual(self.analyser._LibraryUsageAnalyser__potentially_used_libraries, [])

    def test_missing_ldd_uses_manual_lookup(self):
        with patch.object(utils, 'app', 'fixture'), \
                patch.object(utils, 'show_warnings', False), \
                patch('library_analyser.subprocess.run', side_effect=FileNotFoundError), \
                patch.object(self.analyser, '_LibraryUsageAnalyser__find_used_libraries_manually') as fallback:
            self.analyser._LibraryUsageAnalyser__find_used_libraries()
        fallback.assert_called_once()

    def test_empty_ldd_lines_are_ignored(self):
        with patch.object(utils, 'app', 'fixture'), \
                patch('library_analyser.subprocess.run', return_value=SimpleNamespace(stdout=b'\n \n')):
            self.analyser._LibraryUsageAnalyser__find_used_libraries()

    def test_invalid_manual_library_is_removed(self):
        self.analyser._LibraryUsageAnalyser__used_libraries = ['lib.so']
        self.analyser.elf_analyser.is_valid_binary_path = Mock(return_value=False)
        with TemporaryDirectory() as folder, \
                patch.object(library_analyser, 'LIB_DIRS', [folder + '/']), \
                patch.object(utils, 'show_errors', False):
            (Path(folder) / 'lib.so').write_text('not an ELF', encoding='utf-8')
            self.analyser._LibraryUsageAnalyser__find_used_libraries_manually()
        self.assertEqual(self.analyser._LibraryUsageAnalyser__used_libraries, [])

    def test_invalid_library_does_not_poison_registry(self):
        with patch('library_analyser.exists', return_value=True), \
                patch('library_analyser.ea.ELFAnalyser', side_effect=StaticAnalyserException('invalid ELF')), \
                patch.object(utils, 'show_errors', False):
            self.analyser.add_used_library('/invalid/lib.so')
        self.assertEqual(self.libraries, {})
        self.assertEqual(self.analyser._LibraryUsageAnalyser__used_libraries, [])

    def test_unavailable_library_analyser_raises_recoverable_error(self):
        function = LibFunction('write', '/lib.so', (1, 2))
        for library in (None, SimpleNamespace(code_analyser=None)):
            with self.subTest(library=library):
                self.libraries['lib.so'] = library
                with self.assertRaises(StaticAnalyserException):
                    self.analyser._LibraryUsageAnalyser__get_function_insns(function)

    def test_unknown_size_uses_either_available_symbol_source(self):
        for missing in ('symbol', 'function', None):
            with self.subTest(missing=missing):
                elf = Mock()
                elf.binary.lief_binary.functions = [SimpleNamespace(
                        name='start', address=0x1000, size=0)]
                elf.find_next_symbol_addr.return_value = 0x1020
                elf.find_next_function_addr.return_value = 0x1040
                if missing:
                    getattr(elf, 'find_next_' + missing + '_addr').side_effect = StaticAnalyserException('missing')
                self.libraries['lib.so'] = SimpleNamespace(
                        path='/lib.so', code_analyser=SimpleNamespace(elf_analyser=elf))
                function = self.analyser._LibraryUsageAnalyser__get_local_function(0x1000, 'lib.so')
                self.assertEqual(function.boundaries, (0x1000, 0x1040 if missing == 'symbol' else 0x1020))

    def test_prioritised_linker_folder_does_not_need_trailing_slash(self):
        self.analyser.elf_analyser.binary.lief_binary = SimpleNamespace(
                has_interpreter=True, interpreter='/system/ld.so')
        with TemporaryDirectory() as folder, \
                patch.object(utils, 'prioritised_library_folder', folder), \
                patch.object(self.analyser, '_LibraryUsageAnalyser__register_library') as register:
            path = Path(folder) / 'ld.so'
            path.touch()
            self.analyser._LibraryUsageAnalyser__register_linker()
        register.assert_called_once_with(str(path))

    def test_hardcoded_linker_function_uses_registered_path(self):
        self.analyser.elf_analyser.binary.lief_binary = SimpleNamespace(
                interpreter='/system/ld-linux-x86-64.so.2')
        self.libraries['ld-linux-x86-64.so.2'] = SimpleNamespace(path='/priority/ld-linux-x86-64.so.2')
        linker = SimpleNamespace(functions=[SimpleNamespace(
                name='_dl_runtime_resolve_xsavec', address=0x1000, size=4)])
        with patch.object(utils, 'user_input', 'y'), patch.object(utils, 'show_errors', False):
            functions = self.analyser._LibraryUsageAnalyser__get_relocation_function_hardcoded(linker)
        self.assertEqual(functions[0].library_path, '/priority/ld-linux-x86-64.so.2')


if __name__ == '__main__':
    unittest.main()
