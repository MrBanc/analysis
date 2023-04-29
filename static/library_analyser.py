import subprocess

from copy import copy
from os.path import exists
from dataclasses import dataclass
from typing import Dict

import lief
from capstone import *

import utils
from custom_exception import StaticAnalyserException
from elf_analyser import is_valid_binary, PLT_SECTION
from code_analyser import CodeAnalyser
from syscalls import get_inverse_syscalls_map
from call_graph import CallGraph


LIB_PATHS = ['/lib64/']


@dataclass
class Library:
    path: str
    callable_fun_addresses: Dict[str, int]
    code_analyser: CodeAnalyser

@dataclass
class FunLibInfo:
    name: str
    library_path: str
    address: int

class LibraryAnalyser:
    """Class use to store information about and analyse the shared libraries
    used by the ELF executable.
    """
    # TODO:
    # Class docstrings should contain the following information:

    # A brief summary of its purpose and behavior
    # Any public methods, along with a brief description
    # Any class properties (attributes)
    # Anything related to the interface for subclassers, if the class is intended to be subclassed

    def __init__(self, binary):
        if not is_valid_binary(binary):
            raise StaticAnalyserException("The given binary is not a CLASS64 "
                                          "ELF file.")

        self.__plt_section = binary.get_section(PLT_SECTION)
        if self.__plt_section is None:
            raise StaticAnalyserException(".plt section not found.")

        self.__got_rel = binary.pltgot_relocations
        if self.__got_rel is None:
            raise StaticAnalyserException(".got relocations not found.")

        self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.__md.detail = True

        # dict: name -> Library
        self.__used_libraries = dict.fromkeys(binary.libraries)
        self.__find_used_libraries()

        self.__call_graph = CallGraph()

    def is_lib_call(self, operand):
        if utils.is_hex(operand):
            operand = int(operand, 16)
            plt_boundaries = [self.__plt_section.virtual_address,
                              self.__plt_section.virtual_address
                                        + self.__plt_section.size]
            return plt_boundaries[0] <= operand < plt_boundaries[1]
        else:
            #TODO
            pass

        # TODO: it is here temporarily while the else is not implemented
        return False

    def get_function_called(self, operand):
        """Returns the function that would be called by jumping to the address
        given in the .plt section.

        Note that the return value is a list in case multiple functions are
        detected to correspond to this .plt entry and the exact function that
        will be called in the list is not known.

        Parameters
        ----------
        operand : str
            address in the .plt section in hexadecimal

        Returns
        -------
        called_functions : list of FunLibInfo
            function(s) that would be called
        """

        operand = int(operand, 16)

        got_rel_addr = self.__get_got_rel_address(operand)

        for rel in self.__got_rel:
            if got_rel_addr == rel.address:
                return self.__find_function_with_name(rel.symbol.name)

    def get_used_syscalls(self, syscalls_set, functions):
        """Main method of the Library Analyser. Updates the syscall set
        passed as argument after analysing the given function(s).

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analyzed
        functions : list of FunLibInfo
            functions to analyze
        """

        # to avoid modifying the parameter given by the caller
        funs_to_analyze = functions.copy()

        funs_called = []
        function_syscalls = set()
        for f in funs_to_analyze:
            utils.print_debug(f"Function {f} is present in "
                              f"{f.library_path} at address "
                              f"{hex(f.address)}")

            if not self.__call_graph.need_to_analyze_deeper(f):
                syscalls_set.update(self.__call_graph
                                    .get_registered_syscalls(f))
                continue

            # get syscalls and functions used directly in the function code
            if self.__call_graph.calls_registered(f):
                funs_called = self.__call_graph.get_called_funs(f)
                syscalls_set.update(self.__call_graph.
                                    get_registered_syscalls(f))
            else:
                # Initialize the CodeAnalyser if not done already
                lib_name = utils.f_name_from_path(f.library_path)
                if self.__used_libraries[lib_name].code_analyser is None:
                    self.__used_libraries[lib_name].code_analyser = (
                            CodeAnalyser(f.library_path))

                insns = self.__get_function_insns(f)
                CodeAnalyser.disassemble(insns, function_syscalls,
                                         get_inverse_syscalls_map(),
                                         funs_called)
                self.__call_graph.register_calls(f, funs_called)

            # get all the syscalls used by the called function (until maximum
            # depth reached)
            self.get_used_syscalls(function_syscalls, funs_called)
            self.__call_graph.register_syscalls(f, function_syscalls)

            # TODO: update analyzed_to_depth pour f. ça peut se faire avec une
            # nouvelle fct dans call_graph en plus ou encore mieux, que le call
            # graph le fasse tout seul. Je pourrais aussi faire en sorte que le
            # call graph vérifie la valeur que quand on appelle
            # `need_to_analyze_deeper`. prblm c'est qu'il ferait bc de travail
            # pour r donc peut-être qu'il faudrait remplacer cette fonction par
            # genre "get fct not fully analyzed" ou un truc du genre. à voir

            syscalls_set.update(function_syscalls)

    def __get_got_rel_address(self, int_operand):
        # The instruction at the address pointed to by the int_operand is a
        # jump to a `.got` entry. With the address of this `.got` relocation
        # entry, it is possible to identify the function that will be called.
        # The jump instruction is of the form 'qword ptr [rip + 0x1234]', so
        # the next instruction is also stored in order to have the value of the
        # instruction pointer.
        instr_at_address = instr_next = None
        plt_offset = int_operand - self.__plt_section.virtual_address
        for instr in self.__md.disasm(
                bytearray(self.__plt_section.content)[plt_offset:],
                int_operand):
            if instr_at_address is None:
                instr_at_address = instr
            elif instr_next is None:
                instr_next = instr
            else:
                break

        return (int(instr_at_address.op_str.split()[-1][:-1], 16)
                + instr_next.address)

    def __find_function_with_name(self, f_name):
        functions = []
        for lib in self.__used_libraries.values():
            if f_name in lib.callable_fun_addresses:
                to_add = FunLibInfo(name=f_name, library_path=lib.path,
                                    address=lib.callable_fun_addresses[f_name])
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

    def __add_used_library(self, lib_path):
        lib_name = utils.f_name_from_path(lib_path)
        if lib_name not in self.__used_libraries:
            utils.print_verbose("[WARNING] A library path was added for a "
                                "library that was not detected by `lief`.")

        lib_binary = lief.parse(lib_path)
        callable_fun_addresses = {}
        for item in lib_binary.dynamic_symbols:
            callable_fun_addresses[item.name] = item.value
        self.__used_libraries[lib_name] = Library(
                path=lib_path, callable_fun_addresses=callable_fun_addresses,
                code_analyser=None)


    def __find_used_libraries(self):
        # print_debug("Using a stripped version of libc.so.6 without taking "
        #             "into account the actual library used by the binary.")
        # add_used_library('/home/ben/codes/misc/my_stripped_libc.so.6')
        # return
        try:
            ldd_output = subprocess.run(["ldd", utils.app],
                                        check=True, capture_output=True)
            for line in ldd_output.stdout.splitlines():
                parts = line.decode("utf-8").split()
                # TODO: sometimes lib path is not after "=>" (see todo.md)
                if "=>" in parts:
                    self.__add_used_library(parts[parts.index("=>") + 1])
            if not all(self.__used_libraries.values()):
                utils.print_verbose("[ERROR] The `ldd` command didn't find all"
                                    "the libraries used.\nTrying to find the "
                                    "remaining libraries' path manually...")
                self.__find_used_libraries_manually()
        except subprocess.CalledProcessError as e:
            utils.print_verbose("[ERROR] ldd command returned with an error: "
                          + e.stderr.decode("utf-8")
                          + "Trying to find the libraries' path manually...")
            self.__find_used_libraries_manually()

    def __find_used_libraries_manually(self):
        lib_names = [name for name,
                     lib in self.__used_libraries.items() if lib is None]

        # TODO: also look in environment variable `LD_LIBRARY_PATH` and possibly
        # look which path the linker used by the binary uses.
        for path in LIB_PATHS:
            lib_names_copy = copy(lib_names)
            for name in lib_names_copy:
                if exists(path + name):
                    self.__add_used_library(path + name)
                    lib_names.remove(name)

        # TODO: either add more paths in LIB_PATHS or use subprocess to run `locate` (and maybe let the user choose?)
        if len(lib_names) > 0:
            sys.stderr.write(f"[ERROR] The following libraries couldn't be "
                             f"found: {lib_names}\nDo you want to continue "
                             f"without analysing these linked libraries? "
                             f"(Y/n) ")
            ans = input()
            while ans.lower() != "y":
                if ans.lower() == "n":
                    sys.exit(1)
                else:
                    ans = input("Please answer with y or n\n")

    def __get_function_insns(self, function):
        """Return the instructions of a function.

        Parameters
        ----------
        function : FunLibInfo
            the function to return instructions from

        Returns
        -------
        insns : class generator of capstone
            the instructions of the function
        """

        # TODO: omg je peux directement avec la fonction avec lief...
        # mais alors il faut que je stoque la taille bref c'est chiant en fait c'est peut-être plus facile de faire sans et de regarder où est la suivante ? Jsp
        lib_name = utils.f_name_from_path(function.library_path)

        text_section = (self.__used_libraries[lib_name].code_analyser
                        .get_text_section())
        text_offset = function.address - text_section.virtual_address
        # TODO: c'est faux ! Il faut s'arrêter avant la prochaine fonction (ou la fin de la section .text)
        utils.print_debug("fonction __get_function_insns est pas terminée.")
        return self.__md.disasm(bytearray(text_section.content)[text_offset:],
                                   text_section.virtual_address + text_offset)
