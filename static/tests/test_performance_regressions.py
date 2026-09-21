"""Correctness checks for the backtracking performance fixes."""

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import asm_code_utils
from elf_analyser import ELFAnalyser
import utils


class FunctionBoundaryLookupTests(unittest.TestCase):
    def test_unsorted_functions_and_nonsequential_queries_keep_same_boundaries(self):
        analyser = ELFAnalyser.__new__(ELFAnalyser)
        addresses = [0x3000, 0x1000, 0x2100, 0x2000]
        analyser.binary = SimpleNamespace(path='fixture', lief_binary=SimpleNamespace(
            functions=[SimpleNamespace(address=address, name=str(address), size=8)
                       for address in addresses]))
        analyser._ELFAnalyser__address_to_fun_map = None
        for query in (0x3001, 0x1000, 0x209f, 0x2000, 0x2100, 0x4000, 0x1001):
            with self.subTest(query=query):
                self.assertEqual(analyser.find_function_start_addr(query),
                                 max(address for address in addresses if address <= query))

    def test_reinitialized_function_map_discards_previous_boundary_index(self):
        analyser = ELFAnalyser.__new__(ELFAnalyser)
        binary = SimpleNamespace(functions=[SimpleNamespace(
            address=0x1000, name='old', size=8)])
        analyser.binary = SimpleNamespace(path='fixture', lief_binary=binary)
        analyser._ELFAnalyser__address_to_fun_map = None
        self.assertEqual(analyser.find_function_start_addr(0x2000), 0x1000)
        binary.functions = [SimpleNamespace(address=0x1800, name='new', size=8)]
        analyser._ELFAnalyser__address_to_fun_map = None
        self.assertEqual(analyser.find_function_start_addr(0x2000), 0x1800)


class BacktrackingDisassemblerTests(unittest.TestCase):
    def test_register_and_stack_backtracking_reuse_decoded_instructions(self):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        analyser = SimpleNamespace(binary=SimpleNamespace(path='fixture'))
        fixtures = (
            ('b83c0000000f05', 'eax'),
            ('48c74424083c000000488b4424080f05', 'eax'),
        )
        for code, focus in fixtures:
            with self.subTest(code=code):
                instructions = list(md.disasm(bytes.fromhex(code), 0x1000))
                with patch.object(Cs, '__init__', side_effect=AssertionError(
                        'Backtracking must reuse the existing disassembler')), \
                        patch.object(utils, 'app', 'other'), \
                        patch.object(utils, 'backtrack_stack', True), \
                        patch.object(utils, 'logging', False):
                    self.assertEqual(asm_code_utils.value_backtracker(
                        focus, instructions, analyser), 60)


if __name__ == '__main__':
    unittest.main()
