"""Regression checks for analysis correctness and recoverable errors."""

import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import asm_code_utils
from elf_analyser import ELFAnalyser
from code_analyser import CodeAnalyser
from custom_exception import StaticAnalyserException
from library_analyser import LibFunction, LibraryUsageAnalyser
import utils


ROOT = Path(__file__).resolve().parents[1]


class ELFRegressionTests(unittest.TestCase):
    def setUp(self):
        self.analyser = ELFAnalyser.__new__(ELFAnalyser)
        self.text = SimpleNamespace(virtual_address=0x1000, size=4,
                                    content=b'\x01\x02\x03\x04')
        self.rodata = SimpleNamespace(virtual_address=0x1004, size=4,
                                      content=b'abc\x00')
        self.binary = Mock()
        self.binary.get_relocation.return_value = None
        self.binary.section_from_virtual_address.return_value = None
        self.analyser.binary = SimpleNamespace(
                text_sect=self.text, rodata_sect=self.rodata,
                lief_binary=self.binary, path='fixture')

    def test_missing_function_start_falls_back_to_containing_section(self):
        for mapping in ({}, {0x2000: None}):
            with self.subTest(mapping=mapping):
                self.analyser._ELFAnalyser__address_to_fun_map = mapping
                with patch.object(utils, 'print_warning') as warning:
                    self.assertEqual(
                            self.analyser.find_function_start_addr(0x1002), 0x1000)
                warning.assert_called_once()
                message = warning.call_args.args[0]
                for expected in ('0x1002', '0x1000', 'fixture', 'overestimate'):
                    self.assertIn(expected, message)

    def test_known_function_start_does_not_fall_back(self):
        self.analyser._ELFAnalyser__address_to_fun_map = {
                0x1000: None, 0x1001: None, 0x1003: None}
        with patch.object(utils, 'print_warning') as warning:
            for address in (0x1001, 0x1002):
                self.assertEqual(self.analyser.find_function_start_addr(address), 0x1001)
        warning.assert_not_called()

    def test_missing_function_and_section_remains_an_error(self):
        self.analyser._ELFAnalyser__address_to_fun_map = {}
        with self.assertRaises(StaticAnalyserException):
            self.analyser.find_function_start_addr(0x3000)

    def test_section_interiors_and_adjacent_boundary(self):
        self.assertIs(self.analyser.get_section_from_address(0x1002), self.text)
        self.assertIs(self.analyser.get_section_from_address(0x1004), self.rodata)
        with self.assertRaises(StaticAnalyserException):
            self.analyser.get_section_from_address(0x1008)

    def test_failed_parse_does_not_validate_original_binary(self):
        with patch('elf_analyser.lief.parse', return_value=None), patch.object(
                self.analyser, '_ELFAnalyser__is_valid_binary', return_value=True):
            self.assertFalse(self.analyser.is_valid_binary_path('missing'))

    def test_raw_read_uses_byte_width(self):
        with patch.object(utils, 'search_raw_data', True):
            for width, expected in ((1, 1), (2, 0x0201), (4, 0x04030201)):
                with self.subTest(width=width):
                    result = self.analyser.resolve_address_stored_at(0x1000, width)
                    self.assertEqual(result.value, expected)
            with self.assertRaises(StaticAnalyserException):
                self.analyser.resolve_address_stored_at(0x1003, 2)

    def test_string_failures_are_recoverable(self):
        self.assertEqual(self.analyser.get_string_at_address(0x1004), 'abc')
        for content in (b'abcd', b'\xff\x00ab'):
            self.rodata.content = content
            with self.assertRaises(StaticAnalyserException):
                self.analyser.get_string_at_address(0x1004)


class CodeRegressionTests(unittest.TestCase):
    def test_consecutive_local_functions_are_all_moved(self):
        local = [LibFunction('', 'lib', (1, -1)), LibFunction('', 'lib', (2, -1))]
        external = LibFunction('external', 'lib', (3, 4))
        source = local + [external]
        target = []
        analyser = Mock()
        analyser.get_local_function_called.side_effect = local
        asm_code_utils.mov_local_funs_to(target, source, analyser)
        self.assertEqual(source, [external])
        self.assertEqual(target, local)

    def test_backtrack_limit_is_exact(self):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        insns = list(md.disasm(bytes.fromhex('b83c000000900f05'), 0x1000))
        analyser = SimpleNamespace(binary=SimpleNamespace(path='fixture'))
        with patch.object(utils, 'app', 'different'), patch.object(
                utils, 'max_backtrack_insns', 1):
            self.assertIsNone(asm_code_utils.value_backtracker('eax', insns, analyser))
        with patch.object(utils, 'app', 'different'), patch.object(
                utils, 'max_backtrack_insns', 2):
            self.assertEqual(asm_code_utils.value_backtracker('eax', insns, analyser), 60)

    def test_backtrack_restores_state_on_error(self):
        analyser = Mock()
        analyser.binary.path = utils.app
        analyser.find_function_start_addr.side_effect = StaticAnalyserException('missing')
        with patch.object(utils, 'currently_backtracking', False):
            with self.assertRaises(StaticAnalyserException):
                asm_code_utils.value_backtracker('eax', [Mock()], analyser)
            self.assertFalse(utils.currently_backtracking)

    def test_recovery_when_no_following_function_or_symbol(self):
        analyser = CodeAnalyser.__new__(CodeAnalyser)
        analyser.elf_analyser = Mock()
        analyser.elf_analyser.find_next_function_addr.side_effect = StaticAnalyserException('missing')
        analyser.elf_analyser.find_next_symbol_addr.side_effect = StaticAnalyserException('missing')
        analyser.analyse_code = Mock(return_value=1)
        analyser._CodeAnalyser__md = Cs(CS_ARCH_X86, CS_MODE_64)
        section = SimpleNamespace(size=2, virtual_address=0x1000,
                                  content=b'\x90\x0f', name='.text')
        with patch.object(utils, 'show_errors', False), patch.object(utils, 'show_warnings', False):
            analyser.get_used_syscalls_of_section(section, set())
        analyser.analyse_code.assert_called_once()

    def test_runtime_loading_backtrack_errors_are_recoverable(self):
        analyser = CodeAnalyser.__new__(CodeAnalyser)
        analyser.elf_analyser = Mock()
        with patch.object(asm_code_utils, 'value_backtracker',
                          side_effect=StaticAnalyserException('missing')), patch.object(
                              utils, 'show_errors', False), patch.object(utils, 'show_warnings', False):
            for name in ('dlopen', 'dlmopen', 'dlsym'):
                getattr(analyser, '_CodeAnalyser__backtrack_' + name)([])

    def test_runtime_loading_can_register_libraries_during_iteration(self):
        analyser = LibraryUsageAnalyser.__new__(LibraryUsageAnalyser)
        libraries = {}
        callback = Mock()
        callback.analyse_detected_dlsym_functions.side_effect = lambda _: libraries.update(
                new=SimpleNamespace(code_analyser=None))
        libraries['first'] = SimpleNamespace(code_analyser=callback)
        with patch.object(LibraryUsageAnalyser, '_LibraryUsageAnalyser__libraries', libraries):
            analyser.analyse_detected_dlsym_for_all_libs(set())
        self.assertIn('new', libraries)


class ProcessRegressionTests(unittest.TestCase):
    def test_modules_import_independently_with_empty_library_path_entries(self):
        for module in ('elf_analyser', 'library_analyser', 'code_analyser'):
            with self.subTest(module=module):
                result = subprocess.run(
                        [sys.executable, '-c', f'import {module}'], cwd=ROOT,
                        env={**os.environ, 'LD_LIBRARY_PATH': ':/tmp:'},
                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_reports_failure_via_exit_status(self):
        result = subprocess.run(
                [sys.executable, 'static_analyser.py', '-a', 'missing',
                 '-s', '/dev/null', '-w', 'false'], cwd=ROOT,
                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('cannot be parsed', result.stderr)


if __name__ == '__main__':
    unittest.main()
