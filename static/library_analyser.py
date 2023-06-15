"""
Contains the LibraryUsageAnalyser class and the LibFunction and Library
dataclasses.

Analyses the library usage of a binary.
"""

import subprocess
import sys

from copy import copy
from os.path import exists
from dataclasses import dataclass
from typing import Dict, Tuple, Any

import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import utils
import code_analyser as ca
from custom_exception import StaticAnalyserException
from elf_analyser import is_valid_binary, PLT_SECTION, PLT_SEC_SECTION
from syscalls import get_inverse_syscalls_map


LIB_PATHS = ['/lib64/', '/usr/lib64/', '/usr/local/lib64/',
             '/lib/',   '/usr/lib/',   '/usr/local/lib/']


@dataclass
class LibFunction:
    """Represents a library function. Stores information related to the context
    of the function inside the library.

    Attributes
    ----------
    name : str
        name of the function
    library_path : str
        absolute path of the library in which the function is
    boundaries : tuple of two int
        the start address and the end address (start + size) of the function
        within the library binary
    """

    name: str
    library_path: str
    boundaries: Tuple[int]

    def __hash__(self):
        return hash((self.name, self.library_path))


@dataclass
class Library:
    """Represents a library. Stores information related to the content of the
    library and its location in the file system. It also contains the
    CodeAnalyser of the library.

    Attributes
    ----------
    path : str
        absolute path of the library within the file system
    callable_fun_boundaries : dict(str -> tuple of two int)
        dictionary containing the boundaries of the exportable functions of the
        library
    code_analyser : CodeAnalyser
        code analyser instance associated with the library. It will only be
        instanciated if needed.
    """

    path: str
    callable_fun_boundaries: Dict[str, Tuple[int]]
    code_analyser: Any


class LibraryUsageAnalyser:
    """LibraryUsageAnalyser(binary[, max_backtrack_insns]) -> CodeAnalyser

    Class use to store information about and analyse the shared libraries
    used by an ELF executable.

    Public Methods
    --------------
    is_call_to_plt(self, operand) -> bool
        Supposing that the operand given is used for a jmp or call instruction,
        returns true if the result of this instruction is to lead to the `.plt`
        or the `.plt.sec` sections.
    get_function_called(self, operand) -> called_functions
        Returns the function that would be called by jumping to the address
        given in the `.plt` section.
    get_used_syscalls(self, syscalls_set, functions)
        Updates the syscall set passed as argument after analysing the given
        function(s).
    """

    # set of LibFunction
    __analysed_functions = set()

    # dict: name -> Library
    __libraries = {}


    def __init__(self, binary, max_backtrack_insns=None):

        if not is_valid_binary(binary):
            raise StaticAnalyserException("The given binary is not a CLASS64 "
                                          "ELF file.")

        self.__plt_sec_section = binary.get_section(PLT_SEC_SECTION)
        if self.__plt_sec_section is None:
            self.__plt_section = binary.get_section(PLT_SECTION)
            if self.__plt_section is None:
                raise StaticAnalyserException(".plt and .plt.sec sections not "
                                              "found.")

        self.__got_rel = binary.pltgot_relocations
        if self.__got_rel is None:
            raise StaticAnalyserException(".got relocations not found.")
        self.__got_rel = {rel.address: rel
                          for rel in self.__got_rel}

        self.__binary_path = binary.name
        self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.__md.detail = True
        # This may lead to errors. So a warning is throwed if indeed data is
        # found.
        self.__md.skipdata = utils.skip_data
        self.__max_backtrack_insns = (max_backtrack_insns
                                      if max_backtrack_insns is not None
                                      else 20)

        self.__used_libraries = binary.libraries
        # if utils.DEBUG and "libc.so.6" in self.__used_libraries:
        #     self.__used_libraries.remove("libc.so.6")
        #     self.__used_libraries.append("my_stripped_libc.so.6")
        self.__find_used_libraries()

    def is_call_to_plt(self, operand):
        """Supposing that the operand given is used for a jmp or call
        instruction, returns true if the result of this instruction is to lead
        to the `.plt` or the `.plt.sec` sections.

        This enables detecting library function calls.

        Parameters
        ----------
        operand : str
            the operand of a jmp or call instruction

        Returns
        -------
        is_call_to_plt : bool
            True if the result of the instruction is a library function call
        """

        if utils.is_hex(operand):
            operand = int(operand, 16)
            if self.__plt_sec_section:
                plt_boundaries = (self.__plt_sec_section.virtual_address,
                                  self.__plt_sec_section.virtual_address
                                            + self.__plt_sec_section.size)
            else:
                plt_boundaries = (self.__plt_section.virtual_address,
                                  self.__plt_section.virtual_address
                                            + self.__plt_section.size)
            return plt_boundaries[0] <= operand < plt_boundaries[1]
        else:
            #TODO: support indirect operands
            return False

    def get_function_called(self, operand):
        """Returns the function that would be called by jumping to the address
        given in the `.plt` section.

        If the function detected is a function exported from a library, the
        LibFunction entry will be completed. If on the other hand it is a local
        function call, the name of the function will be missing as well as the
        end address.

        Note that the return value is a list in case multiple functions are
        detected to correspond to this `.plt` entry and the exact function that
        will be called in the list is not known.

        Parameters
        ----------
        operand : str
            address in the .plt section in hexadecimal

        Returns
        -------
        called_functions : list of LibFunction
            function(s) that would be called
        """

        operand = int(operand, 16)

        got_rel_addr = self.__get_got_rel_address(operand)

        rel = self.__got_rel[got_rel_addr]
        if (lief.ELF.RELOCATION_X86_64(rel.type)
            == lief.ELF.RELOCATION_X86_64.JUMP_SLOT):
            return self.__find_function_with_name(rel.symbol.name)
        if (lief.ELF.RELOCATION_X86_64(rel.type)
            == lief.ELF.RELOCATION_X86_64.IRELATIVE):
            if rel.addend:
                return [LibFunction(name="", library_path=self.__binary_path,
                                    boundaries=(rel.addend, -1))]
            return []

        sys.stderr.write(f"[WARNING] A function name couldn't be found for "
                         f"the .plt slot at address {hex(operand)}\n")
        return []

    def get_used_syscalls(self, syscalls_set, functions):
        """Main method of the Library Analyser. Updates the syscall set
        passed as argument after analysing the given function(s).

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed
        functions : list of LibFunction
            functions to analyse
        """

        # to avoid modifying the parameter given by the caller
        funs_to_analyse = functions.copy()

        self.__get_used_syscalls_recursive(syscalls_set, funs_to_analyse)

    def __get_used_syscalls_recursive(self, syscalls_set, functions):
        """Updates the syscall set passed as argument after analysing the given
        function(s).

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed
        functions : list of LibFunction
            functions to analyse
        """

        utils.cur_depth += 1
        for f in functions:
            funs_called = []
            function_syscalls = set()
            if f in LibraryUsageAnalyser.__analysed_functions:
                utils.log(f"D-{utils.cur_depth}: {f.name}@"
                          f"{utils.f_name_from_path(f.library_path)} - at "
                          f"{hex(f.boundaries[0])} - done",
                          "lib_functions.log", utils.cur_depth)
                continue
            LibraryUsageAnalyser.__analysed_functions.add(f)

            utils.log(f"D-{utils.cur_depth}: {f.name}@"
                      f"{utils.f_name_from_path(f.library_path)} - at "
                      f"{hex(f.boundaries[0])}",
                      "lib_functions.log", utils.cur_depth)

            # Get syscalls and functions used directly in the function code
            lib_name = utils.f_name_from_path(f.library_path)
            insns = self.__get_function_insns(f)
            if insns is None:
                continue

            (LibraryUsageAnalyser.__libraries[lib_name].code_analyser
             .analyse_code(insns, function_syscalls,
                           get_inverse_syscalls_map(), funs_called))

            # Get all the syscalls used by the called function
            self.__get_used_syscalls_recursive(function_syscalls, funs_called)

            # Update syscalls set
            syscalls_set.update(function_syscalls)

        utils.cur_depth -= 1

    def __get_got_rel_address(self, int_operand):

        jmp_to_got_ins = next_ins = None

        if not self.__plt_sec_section:
            # The instruction at the address pointed to by the int_operand is a
            # jump to a `.got` entry. With the address of this `.got`
            # relocation entry, it is possible to identify the function that
            # will be called. The jump instruction is of the form 'qword ptr
            # [rip + 0x1234]', so the next instruction is also stored in order
            # to have the value of the instruction pointer.
            plt_offset = int_operand - self.__plt_section.virtual_address
            insns = self.__md.disasm(
                    bytearray(self.__plt_section.content)[plt_offset:],
                    int_operand)
            jmp_to_got_ins = next(insns)
            next_ins = next(insns)
        else:
            # The same remark holds but the first instruction is now the
            # instruction right after the address pointed by the int_operand
            # and we work with the .plt.sec section instead.
            plt_sec_offset = (int_operand
                              - self.__plt_sec_section.virtual_address)
            insns = self.__md.disasm(
                    bytearray(self.__plt_sec_section.content)[plt_sec_offset:],
                    int_operand)
            next(insns) # skip the first instruction
            jmp_to_got_ins = next(insns)
            next_ins = next(insns)

        return (int(jmp_to_got_ins.op_str.split()[-1][:-1], 16)
                + next_ins.address)

    def __find_function_with_name(self, f_name):

        functions = []
        for lib_name in self.__used_libraries:
            lib = LibraryUsageAnalyser.__libraries[lib_name]
            if f_name not in lib.callable_fun_boundaries:
                continue
            if (len(lib.callable_fun_boundaries[f_name]) != 2
                or lib.callable_fun_boundaries[f_name][0] >=
                   lib.callable_fun_boundaries[f_name][1]):
                continue
            to_add = LibFunction(name=f_name, library_path=lib.path,
                            boundaries=lib.callable_fun_boundaries[f_name])
            # sometimes there are duplicates.
            if to_add not in functions:
                functions.append(to_add)

        if not functions:
            sys.stderr.write(f"[WARNING] No library function was found for "
                             f"{f_name}. Continuing...\n")
        elif len(functions) > 1:
            sys.stderr.write(f"[WARNING] Multiple possible library functions "
                             f"were found for {f_name}: {functions}.\n"
                             f"All of them will be considered.\n")

        return functions

    def __add_used_library(self, lib_path, show_warnings=True):

        # if utils.DEBUG and lib_path == "/lib64/libc.so.6":
        #     self.__add_used_library(
        #             "/home/ben/codes/misc/my_stripped_libc.so.6")
        #     return
        if not exists(lib_path):
            # Does not need to print an error message as if a library is really
            # not found, it will be noticed elsewhere with more information
            # than here.
            return
        lib_name = utils.f_name_from_path(lib_path)
        if lib_name not in self.__used_libraries:
            self.__used_libraries.append(lib_name)
            if show_warnings:
                utils.print_verbose(f"[WARNING]: The library path "
                                    f"{utils.f_name_from_path(lib_path)} was "
                                    f"added for {self.__binary_path}, which is"
                                    f" a library that was not detected by "
                                    f"`lief`.")

        if lib_name in LibraryUsageAnalyser.__libraries:
            return

        lib_binary = lief.parse(lib_path)
        callable_fun_boundaries = {}
        for item in lib_binary.dynamic_symbols:
            # I could use `item.is_function` to only store functions but it
            # seem to be unaccurate (for example strncpy is not considered a
            # function). Anyway, the memory footprint wouldn't have been much
            # different.
            callable_fun_boundaries[item.name] = (item.value,
                                                  item.value + item.size)

        # The entry needs to be added to the __libraries class variable
        # *before* creating the CodeAnalyser because calling the CodeAnalyser
        # constructor will bring us back in this function and if the
        # __libraries variable does not contain the entry, an infinite loop
        # may occur.
        LibraryUsageAnalyser.__libraries[lib_name] = Library(
                path=lib_path, callable_fun_boundaries=callable_fun_boundaries,
                code_analyser=None)
        code_analyser = ca.CodeAnalyser(lib_path, self.__max_backtrack_insns)
        LibraryUsageAnalyser.__libraries[lib_name].code_analyser = \
                code_analyser

    def __find_used_libraries(self):

        # A binary sometimes uses the .plt section to call one of its own
        # functions
        self.__add_used_library(self.__binary_path, show_warnings=False)

        try:
            ldd_output = subprocess.run(["ldd", self.__binary_path],
                                        check=True, capture_output=True)
            for line in ldd_output.stdout.splitlines():
                parts = line.decode("utf-8").split()
                if "=>" in parts:
                    self.__add_used_library(parts[parts.index("=>") + 1])
                elif utils.f_name_from_path(parts[0]) in self.__used_libraries:
                    self.__add_used_library(parts[0])
            if not set(self.__used_libraries).issubset(LibraryUsageAnalyser
                                                       .__libraries.keys()):
                utils.print_verbose("[WARNING] The `ldd` command didn't find "
                                    "all the libraries used.\nTrying to find "
                                    "the remaining libraries' path manually..."
                                    )
                self.__find_used_libraries_manually()
        except subprocess.CalledProcessError as e:
            utils.print_verbose("[WARNING] ldd command returned with an error:"
                                " " + e.stderr.decode("utf-8") + "Trying to "
                                "find the libraries' path manually...")
            self.__find_used_libraries_manually()

    def __find_used_libraries_manually(self):

        lib_names = [lib for lib in self.__used_libraries
                     if lib not in LibraryUsageAnalyser.__libraries]

        # TODO: also look in environment variable `LD_LIBRARY_PATH` and
        # possibly look which path the linker used by the binary uses. Can also
        # add more paths to `LIB_PATHS` and use a subprocess to use `locate`
        for path in LIB_PATHS:
            lib_names_copy = copy(lib_names)
            for name in lib_names_copy:
                if exists(path + name):
                    self.__add_used_library(path + name)
                    lib_names.remove(name)

        if len(lib_names) > 0:
            sys.stderr.write(f"[ERROR] The following libraries couldn't be "
                             f"found and therefore won't be analysed: "
                             f"{lib_names}\n")
            self.__used_libraries = [l for l in self.__used_libraries
                                     if l not in lib_names]

    def __get_function_insns(self, function):
        """Return the instructions of a function.

        Parameters
        ----------
        function : LibFunction
            the function to return instructions from

        Returns
        -------
        insns : class generator of capstone
            the instructions of the function
        """

        lib_name = utils.f_name_from_path(function.library_path)

        text_section = (LibraryUsageAnalyser.__libraries[lib_name]
                        .code_analyser.get_text_section())
        if function.boundaries[1] > text_section.size:
            # TODO: detect in which section it is and fetch it
            sys.stderr.write(f"[WARNING] Library function "
                             f"{function.name}@{lib_name} is located outside "
                             f"the .text section and was therefore not "
                             f"analysed. Continuing...\n")
            return None
        f_start_offset = function.boundaries[0] - text_section.virtual_address
        f_end_offset = function.boundaries[1] - text_section.virtual_address
        return self.__md.disasm(
                bytearray(text_section.content)[f_start_offset:f_end_offset],
                text_section.virtual_address + f_start_offset)
