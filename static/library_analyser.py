"""
Contains the LibraryUsageAnalyser class and the LibFunction and Library
"""

import subprocess
import re

from os.path import exists
from os import environ as environment_var
from dataclasses import dataclass
from typing import Dict, Tuple, Any
from collections import defaultdict

import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
try:
    from r2pipe import open as r2_open
    import json
except ImportError:
    r2_open = None

import utils
import code_analyser as ca
import elf_analyser as ea
from custom_exception import StaticAnalyserException
from elf_analyser import PLT_SECTION, PLT_SEC_SECTION


# Ordered so that the first should be checked before the other
DEFAULT_LIB_DIRS = ['/lib64/', '/usr/lib64/', '/usr/local/lib64/',
                     '/lib/',   '/usr/lib/',   '/usr/local/lib/']
LD_LIB_DIRS = (list(environment_var.get("LD_LIBRARY_PATH").split(":"))
                if "LD_LIBRARY_PATH" in environment_var else [])
for path in LD_LIB_DIRS:
    if path[-1] != '/':
        path += '/'
LIB_DIRS = LD_LIB_DIRS + DEFAULT_LIB_DIRS

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

    # In the two following functions, it is important that it is the boundaries
    # and the library path that are looked at and not the name and the library
    # path because:
    # - some function names aren't available
    # - they may be multiple name leading to the same function (ex: open and
    #   open64)
    def __hash__(self):
        return hash((self.library_path, self.boundaries[0]))
    def __eq__(self, other):
        return (isinstance(other, LibFunction)
                and self.library_path == other.library_path
                and self.boundaries[0] == other.boundaries[0])


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
        library. The key is the name of the function
    code_analyser : CodeAnalyser
        code analyser instance associated with the library. It will only be
        instanciated if needed.
    """

    path: str
    callable_fun_boundaries: Dict[str, Tuple[int]]
    code_analyser: Any


class LibraryUsageAnalyser:
    """LibraryUsageAnalyser(elf_analyser) -> CodeAnalyser

    Class used to store information about and analyse the shared libraries
    used by an ELF executable.

    Public Methods
    --------------
    is_call_to_plt(self, address) -> bool
        Supposing that the address given is used as a destination for a jmp or
        call instruction, returns true if the result of this instruction is to
        lead to one of the slots inside the `.plt` or the `.plt.sec` sections.
    get_plt_function_called(self, f_address) -> called_functions
        Returns the function that would be called by jumping to the address
        given in the `.plt` section.
    get_libraries_paths_manually(self, lib_names) -> list of str
        elper function to obtain the path of a library from its name.
    get_lib_from_GNU_ld_script(self, script_path) -> list of str
        Parses a GNU ld script and returns the library paths it leads to.
    get_function_with_name(self, f_name, lib_alias=None,
                           use_potential_libs=False) -> list of LibFunction
        Returns the LibFunction dataclass corresponding to the function with
        the given name by looking at the functions available in the libraries
        used by the analysed binary (self).
    add_used_library(self, lib_path, added_by_ldd=False):
        Adds the library name associated with the library path provided to
        the list of used libraries of the binary and register the library's
        information (in self.__libraries) if it was not already done beforehand
        in the program's execution.
    analyse_linker_functions(self, syscalls_set):
        Analyse the linker (aka dynamic linker, loader or interpreter)
        functions. The linker is generally `ld-linux-x86-64.so.2`.
    get_used_syscalls(self, syscalls_set, functions)
        Updates the syscall set passed as argument after analysing the given
        function(s).
    """

    # set of LibFunction
    __analysed_functions = set()

    # dict: name -> Library
    __libraries = {}


    def __init__(self, elf_analyser):

        self.elf_analyser = elf_analyser

        lb = self.elf_analyser.binary.lief_binary

        self.__plt_sec_section = lb.get_section(PLT_SEC_SECTION)
        self.__plt_section = lb.get_section(PLT_SECTION)
        if self.__plt_section is None:
            utils.print_warning(f"[WARNING] .plt section not found for "
                                f"{self.elf_analyser.binary.path}")

        self.__got_rel = lb.pltgot_relocations
        if self.__got_rel is None:
            utils.print_warning(f"[WARNING] .got relocations not found for "
                                f"{self.elf_analyser.binary.path}")
        else:
            self.__got_rel = {rel.address: rel
                              for rel in self.__got_rel}

        self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.__md.detail = True
        # This may lead to errors. So a warning is throwed if indeed data is
        # found.
        self.__md.skipdata = utils.skip_data

        self.__used_libraries = lb.libraries
        # contains libraries detected by ldd but not by lief (so they may be
        # libraries that are not directly used by the binaries as ldd shows
        # dependencies of dependencies)
        self.__potentially_used_libraries = []
        self.__find_used_libraries()

        self.__used_libraries_aliases = defaultdict(list)
        self.__find_used_libraries_aliases(lb.symbols_version_requirement)

    def is_call_to_plt(self, address):
        """Supposing that the address given is used as a destination for a jmp
        or call instruction, returns true if the result of this instruction is
        to lead to one of the slots inside the `.plt` or the `.plt.sec`
        sections.

        This enables detecting library function calls.

        Note that the .plt.sec section contains endbr64 instructions
        specifically to check if the destination address is indeed an address
        that the program can jump to. This is not the case for the .plt section
        so instead, this function just look if the offset from the beginning of
        the section is a multiple of the slots' length.

        Parameters
        ----------
        address : str
            the destination address of a jmp or call instruction

        Returns
        -------
        is_call_to_plt : bool
            True if the result of the instruction is a library function call
        """

        if self.__plt_sec_section:
            plt_boundaries = (self.__plt_sec_section.virtual_address,
                              self.__plt_sec_section.virtual_address
                                        + self.__plt_sec_section.size)
            plt_sec_offset = address - plt_boundaries[0]
            endbr64_bytes = b"\xf3\x0f\x1e\xfa"
            if (bytearray(self.__plt_sec_section.content)
                           [plt_sec_offset:plt_sec_offset+4] != endbr64_bytes):
                return False
        elif self.__plt_section:
            plt_boundaries = (self.__plt_section.virtual_address,
                              self.__plt_section.virtual_address
                                        + self.__plt_section.size)
            slots_length = 16
            if (address - plt_boundaries[0]) % slots_length:
                return False
        else:
            return False
        return plt_boundaries[0] <= address < plt_boundaries[1]

    def get_plt_function_called(self, f_address):
        """Returns the function that would be called by jumping to the address
        given in the `.plt` section.

        Return value:
        If the function detected is a function exported from a library, the
        LibFunction entry will be completed. If on the other hand it is a local
        function call, the name of the function will be missing as well as the
        end address.

        Note that the return value is a list in case multiple functions are
        detected to correspond to this `.plt` entry and the exact function that
        will be called in the list is not known.

        Parameters
        ----------
        f_address : int
            address of the .plt slot corresponding to the function

        Returns
        -------
        called_functions : list of LibFunction
            function(s) that would be called
        """

        called_functions = []

        got_rel_addr = self.__get_got_rel_address(f_address)

        if (self.__got_rel is None or got_rel_addr is None
                                   or got_rel_addr not in self.__got_rel):
            rel = None
        else:
            rel = self.__got_rel[got_rel_addr]

        # if it is a call to a library function, this if will be true
        if (rel and lief.ELF.RELOCATION_X86_64(rel.type)
                    == lief.ELF.RELOCATION_X86_64.JUMP_SLOT):
            # auxiliary version seem to indicate the library from which the
            # function come (example value: 'GLIBC_2.2.5')
            # In some (rare) cases, the symbol version is not available
            if (rel.symbol.symbol_version is not None
                    and rel.symbol.symbol_version.has_auxiliary_version):
                called_functions.extend(self.get_function_with_name(
                    rel.symbol.name,
                    lib_alias=rel.symbol.symbol_version
                                 .symbol_version_auxiliary.name))
                return called_functions
            called_functions.extend(self
                                    .get_function_with_name(rel.symbol.name))
            return called_functions
        # if it is a call to a local function, this if will be true
        if (rel and lief.ELF.RELOCATION_X86_64(rel.type)
                    == lief.ELF.RELOCATION_X86_64.IRELATIVE):
            if rel.addend:
                called_functions.append(
                        LibFunction(name="",
                                    library_path=self.elf_analyser.binary.path,
                                    boundaries=(rel.addend, -1)))
            return called_functions

        utils.print_error(f"[WARNING] A function name couldn't be found for "
                          f"the .plt slot at address {hex(f_address)} in "
                          f"{self.elf_analyser.binary.path}.")
        return called_functions

    def get_libraries_paths_manually(self, lib_names):
        """Helper function to obtain the path of a library from its name.

        Parameters
        ----------
        lib_names : list of str
            list of libraries names

        Returns
        -------
        lib_paths : list of str
            list of the libraries paths that were found
        """

        lib_paths = []
        lib_names_copy = lib_names.copy()

        for l_dir in LIB_DIRS:
            for name in lib_names_copy:
                if exists(l_dir + name):
                    lib_paths.append(l_dir + name)
                    if name in lib_names:
                        lib_names.remove(name)

        return lib_paths

    def get_lib_from_GNU_ld_script(self, script_path):
        """Parses a GNU ld script and returns the library paths it leads to.

        Note: The order of the libraries is preserved but the AS_NEEDED
        information is lost

        Parameters
        ----------
        script_path : str
            path to the GNU ld script

        Returns
        -------
        lib_paths : list of str
            list of the libraries paths that were pointed to by the script
        """

        lib_paths = []

        try:
            with open(script_path, 'r', encoding="utf-8") as file:
                for line in file:
                    if (line.strip().startswith("GROUP")
                        or line.strip().startswith("INPUT")):
                        path_pattern = r'[\(\s](/[^\s]*)'
                        lib_paths.extend(re.findall(path_pattern, line))
        except FileNotFoundError:
            utils.print_error(f"There is no GNU ld script at {script_path}")

        return lib_paths

    def get_function_with_name(self, f_name, lib_alias=None,
                               use_potential_libs=False, lib_to_check=None):
        """Returns the LibFunction dataclass corresponding to the function with
        the given name by looking at the functions available in the libraries
        used by the analysed binary (self).

        Parameters
        ----------
        f_name : str
            the name of the function to be obtained
        lib_alias : str or None
            an alias name for the library this function is probably located in.
            If it isn't found there, it will anyway look at the other libraries
            used by the analyzed binary
        use_potential_libs : bool or None
            whether to (only) use the potentially used libraries detected by
            ldd but not by other means or to (only) use the used libraries
            detected by other means.
            When set to False, if no function is found in the used libraries,
            the potentially used libraries will be looked into in a second
            attempt.
        lib_to_check : list of str or None
            list of libraries (names) to look into.
            ! Use with caution ! This is a way to hardcode the list of
            libraries to look into, which should normally be filled by the
            function itself, depending on the value of the other arguments. If
            this argument is not None, the other arguments related to libraries
            will be ignored and nothing will be returned if the function is not
            found in the libraries provided.

        Returns
        -------
        functions : list of LibFunction
            the list of functions found
        """

        hardcoded = False
        functions = []

        if lib_to_check is not None:
            hardcoded = True
        elif lib_alias is not None:
            lib_to_check = self.__used_libraries_aliases[lib_alias]
        elif not use_potential_libs:
            lib_to_check = self.__used_libraries
        else:
            lib_to_check = self.__potentially_used_libraries

        for lib_name in lib_to_check:
            lib = self.__libraries[lib_name]
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
            if hardcoded:
                utils.print_error(f"[ERROR] No library function was found for "
                                  f"{f_name} in the libraries {lib_to_check}."
                                  f" Continuing...")
                return functions
            if lib_alias is not None:
                return self.get_function_with_name(f_name)
            if not use_potential_libs:
                return self.get_function_with_name(f_name,
                                                   use_potential_libs=True)
            utils.print_error(f"[WARNING] No library function was found for "
                              f"{f_name}. Continuing...")
        elif len(functions) > 1:
            utils.print_error(f"[WARNING] Multiple possible library functions "
                              f"were found for {f_name} in "
                              f"{self.elf_analyser.binary.path}: "
                              f"{functions}.\n"
                              f"All of them will be considered.")

        if functions and use_potential_libs:
            utils.print_warning(
                    f"[WARNING]: The library function {f_name} used by "
                    f"{self.elf_analyser.binary.path}, couldn't be found in "
                    f"the libraries detected by `lief` (or `dlopen` etc) but "
                    f"was found in a library detected by `ldd`. This one will "
                    f"be considered.")

        return functions

    def add_used_library(self, lib_path, added_by_ldd=False):
        """Adds the library name associated with the library path provided to
        the list of used libraries of the binary and register the library's
        information (in self.__libraries) if it was not already done beforehand
        in the program's execution.

        Note: If the library has already been added via a different path, it
        will not be added a second time and only the first path will be
        considered. It is considered that when two libraries with the same name
        but located at different places are the same.
        It is therefore also crucial to verify that the library path lead to a
        valid binary (for example using `is_valid_library_path`) before calling
        this function, or the provided invalid library will block future
        attempt to add a valid library with the same name.

        Parameters
        ----------
        lib_path : str
            library's path
        added_by_ldd : bool
            whether or not it was added by `ldd`
        """

        if not exists(lib_path):
            # Does not need to print an error message as if a library is really
            # not found, it will be noticed elsewhere with more information
            # than here.
            return
        lib_name = utils.f_name_from_path(lib_path)
        if lib_name not in self.__used_libraries:
            if (added_by_ldd
                and lib_name not in self.__potentially_used_libraries):
                self.__potentially_used_libraries.append(lib_name)
            else:
                self.__used_libraries.append(lib_name)

        if lib_name in self.__libraries:
            return

        self.__register_library(lib_path)

    def analyse_detected_dlsym_for_all_libs(self, syscalls_set):
        """Calls the `analyse_detected_dlsym_functions` of CodeAnalyser on all
        libraries.

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed
        """

        for lib in self.__libraries.values():
            lib.code_analyser.analyse_detected_dlsym_functions(syscalls_set)

    def analyse_linker_functions(self, syscalls_set):
        """Analyse the linker (aka dynamic linker, loader or interpreter)
        functions. The linker is generally `ld-linux-x86-64.so.2`.

        The first function to analyse is actually the first piece of code
        executed when launching the program, as the linker is called first.

        The second function to analyse is the function called when doing a
        relocation (in .plt).

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed, which will be
            updated by this function
        """

        try:
            self.__register_linker()
            linker_ca = self.__get_linker_code_analyser()
        except StaticAnalyserException as e:
            utils.print_error(f"[ERROR] Error while retrieving the linker's "
                              f"code analyser: {e}.")
            return

        linker_bin = linker_ca.elf_analyser.binary.lief_binary

        # 1. Analyse first function called of the linker

        linker_entrypoint = self.__get_linker_entrypoint(linker_bin)

        if linker_entrypoint is not None:
            self.get_used_syscalls(syscalls_set, [linker_entrypoint])

        # 2. Analyse function that is called when doing a relocation (in .plt)

        if not self.__lazy_binding_used():
            # If lazy binding is not used, the relocation function is not used
            # and there is no need to analyse it.
            return

        reloc_fun = None

        try:
            # It is necessary to use dynamic analysis to find the relocation
            # function (see __get_relocation_function_dynamically documentation
            # for more details)
            reloc_fun = [self.__get_relocation_function_dynamically()]
        except StaticAnalyserException as e:
            utils.print_error(f"[ERROR] The dynamic analysis of the linker's "
                              f"relocation function address failed: {e}\n")

            reloc_fun = self.__get_relocation_function_hardcoded(linker_bin)

        if reloc_fun is not None:
            self.get_used_syscalls(syscalls_set, reloc_fun)

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
            if f in self.__analysed_functions:
                utils.log(f"D-{utils.cur_depth}: {f.name}@"
                          f"{utils.f_name_from_path(f.library_path)} - at "
                          f"{hex(f.boundaries[0])} - done",
                          "lib_functions.log", utils.cur_depth)
                continue
            self.__analysed_functions.add(f)

            utils.log(f"D-{utils.cur_depth}: {f.name}@"
                      f"{utils.f_name_from_path(f.library_path)} - at "
                      f"{hex(f.boundaries[0])}",
                      "lib_functions.log", utils.cur_depth)

            # Get syscalls and functions used directly in the function code
            lib_name = utils.f_name_from_path(f.library_path)
            try:
                insns = self.__get_function_insns(f)
                (self.__libraries[lib_name].code_analyser
                 .analyse_code(insns, function_syscalls, funs_called))
            except StaticAnalyserException as e:
                utils.print_error(f"[ERROR] Error while analysing the function"
                                  f" {f.name} in {f.library_path}: {e}.")
                continue

            # Get all the syscalls used by the called function
            self.__get_used_syscalls_recursive(function_syscalls, funs_called)

            # Update syscalls set
            syscalls_set.update(function_syscalls)

        utils.cur_depth -= 1

    def __register_linker(self):

        if not self.elf_analyser.binary.lief_binary.has_interpreter:
            raise StaticAnalyserException(f"The binary "
                                f"{self.elf_analyser.binary.path} does not "
                                f"have a linker/interpreter/loader. Their "
                                f"functions won't be analysed.")

        linker_path = self.elf_analyser.binary.lief_binary.interpreter
        linker_name = utils.f_name_from_path(linker_path)

        if (linker_name in self.__libraries
            and linker_path != self.__libraries[linker_name].path):

            utils.print_warning(f"[WARNING]: {linker_name} is in the libraries"
                                f" but the path is different: {linker_path} vs"
                                f" {self.__libraries[linker_name].path}. The "
                                f"former will be used.")
        if (linker_name not in self.__libraries
            or linker_path != self.__libraries[linker_name].path):

            self.__register_library(linker_path)

    def __get_linker_code_analyser(self):

        linker_path = self.elf_analyser.binary.lief_binary.interpreter
        linker_name = utils.f_name_from_path(linker_path)

        linker_ca = self.__libraries[linker_name].code_analyser

        if linker_ca is None:
            raise StaticAnalyserException(f"The code analyser for the linker "
                                          f"{linker_name} has not been "
                                          f"instanciated yet.")
        return linker_ca

    def __get_linker_entrypoint(self, linker_bin):

        linker_path = self.elf_analyser.binary.lief_binary.interpreter
        linker_name = utils.f_name_from_path(linker_path)

        try:
            return self.__get_local_function(linker_bin.entrypoint,
                                             linker_name)
        except StaticAnalyserException as e:
            utils.print_error(f"[ERROR] The linker's entrypoint function could"
                              f" not be found: {e}.")
            return None

    def __lazy_binding_used(self):

        for e in self.elf_analyser.binary.lief_binary.dynamic_entries:
            if (e.tag == lief.ELF.DYNAMIC_TAGS.FLAGS
                and e.has(lief.ELF.DYNAMIC_FLAGS.BIND_NOW)):

                # This could for example be the result of compiling with "-z
                # now" or using musl
                return False

        ld_bind_now = environment_var.get("LD_BIND_NOW")
        if ld_bind_now is not None and ld_bind_now != "":
            return False

        return True

    def __get_relocation_function_dynamically(self):
        """Get the relocation function of the linker dynamically.

        The relocation function is the function called when doing a relocation
        (in .plt). It is generally `_dl_runtime_resolve_xsavec` for the linker
        `ld-linux-x86-64.so.2`. But this is not the only possibility, thus this
        function is used to find it automatically.

        The function is called through the generic entry of the .plt section by
        jumping to its address, which is located in the .got section. The
        problem is that this address is not known statically and is only known
        at runtime. Thus, the address is found using dynamic analysis.

        Returns
        -------
        reloc_fun : LibFunction
            the relocation function found

        Raises
        ------
        StaticAnalyserException
            if the dynamic analysis fails
        """

        # The following code is commented as the address obtained sometimes
        # corresponds to the virtual address and sometimes to the offset from
        # the beginning of the mapping. Thus instead, this address is found
        # using r2 instead.

        # # Find the address of the .got entry where the relocation function's
        # # address will be stored

        # reloc_got_addr = self.__get_got_rel_address(
        #        self.__plt_section.virtual_address, is_first_plt_entry=True)

        # The relocation function address is found using dynamic
        # analysis as it will only be known at runtime.

        if r2_open is None:
            raise StaticAnalyserException("r2pipe is not installed.")
        try:
            r2_bin = r2_open(self.elf_analyser.binary.path, flags=["-d", "-2"])
        except Exception as e: # r2pipe raises generic exceptions...
            if "Cannot find radare2 in PATH" in str(e):
                raise StaticAnalyserException(
                        "Cannot find radare2 in PATH.") from e
            raise e

        try:
            # Note: I cannot find the meaning ot entry0 in the r2 documentation
            # but it seems to be an alias for the entrypoint. If in the future,
            # this does not work, an alternative is to obtain the address of
            # the entrypoint from the command "ie". It is also possible that
            # the "aaa" command needs to be called to find entry0 sometimes,
            # but it is rather slow, thus I do not use it here as it works
            # without it. Another possibility is to compute it with the offset.
            r2_bin.cmd('db entry0') # (set breakpoint to entrypoint)
            r2_bin.cmd('dc') # (continue until breakpoint)
            # Get where the linker is mapped in memory and compare it to the
            # address of relocation function address to find the offset.

            memory_mappings = json.loads(r2_bin.cmd('dmj'))

            linker_path = self.elf_analyser.binary.lief_binary.interpreter
            linker_name = utils.f_name_from_path(linker_path)
            # binary_path = self.elf_analyser.binary.path
            # binary_name = utils.f_name_from_path(binary_path)
            linker_mappings = self.__grep_file_mappings(memory_mappings,
                                                        linker_name)
            # binary_mappings = self.__grep_file_mappings(memory_mappings,
            #                                             binary_name)

            if (self.__mappings_not_contiguous(linker_mappings)
                # or self.__mappings_not_contiguous(binary_mappings)
                or len(linker_mappings) < 1): # or len(binary_mappings) < 1):
                # Could be possible to find the offset even if they aren't
                # contiguous but it is not implemented (yet?).
                raise StaticAnalyserException("The mappings of the linker or "
                                              "binary are not contiguous or "
                                              "have not been found.")

            linker_mapped_address = linker_mappings[0]['addr']
            # binary_mapped_address = binary_mappings[0]['addr']

            sections_info = r2_bin.cmd('iS')
            plt_section_addr = self.__get_plt_addr_from_r2_info(sections_info)

            # reloc_got_loaded_addr = binary_mapped_address + reloc_got_addr
            # r2_bin.cmd(f's {hex(reloc_got_loaded_addr)}')
            # got_entry_content = r2_bin.cmd('p8 6') # (print 6 bytes)
            # # convert to big endian
            # reloc_fun_addr = int.from_bytes(bytes.fromhex(got_entry_content),
            #                                 byteorder='little')

            r2_bin.cmd(f's {hex(plt_section_addr)}') # (focus on the address)
            dis_inst = r2_bin.cmd('pd 2') # (disassemble two instructions)
        finally:
            r2_bin.cmd('doc') # close debugger (Otherwise, the process can stay
                              # alive, even after killing r2)
            r2_bin.quit()
        second_instr_pattern = (r"jmp *qword *\[(0x)?[a-fA-F0-9]+\] *; *"
                             r"\[(0x)?[a-fA-F0-9]+(:\d+)?\]=(0x)?[a-fA-F0-9]+")
        # need to use -2 because there may be comment lines beforehand and
        # there is an empty line at the end
        if re.search(second_instr_pattern, dis_inst.split('\n')[-2]) is None:
            raise StaticAnalyserException("The second instruction of the .plt "
                                          "section has not the expected "
                                          "format.")

        got_entry_content = re.search(r"=((0x)?[a-fA-F0-9]+)",
                                      dis_inst.split('\n')[-2]).group(1)
        reloc_fun_addr = utils.str2int(got_entry_content)

        if reloc_fun_addr is None or reloc_fun_addr == 0:
            raise StaticAnalyserException("The relocation function address "
                                          "could not be found.")

        reloc_fun_offset = reloc_fun_addr - linker_mapped_address

        # Get the function name from the linker's symbols by looking at
        # the offset found.

        try:
            reloc_fun = self.__get_local_function(reloc_fun_offset,
                                                  linker_name)
        except StaticAnalyserException as e:
            raise StaticAnalyserException(f"The relocation function could not "
                                          f" be found: {e}") from e

        if reloc_fun is None:
            raise StaticAnalyserException("The relocation function could not "
                                          "be found.")

        return reloc_fun

    def __grep_file_mappings(self, memory_mappings, file_name):

        return [m for m in memory_mappings if (
            ('name' in m and file_name == utils.f_name_from_path(m['name']))
            or
            ('file' in m and file_name == utils.f_name_from_path(m['file'])))]

    def __mappings_not_contiguous(self, linker_mappings):

        contiguous = True
        for i in range(len(linker_mappings) - 1):
            end_address_current = linker_mappings[i]['addr_end']
            start_address_next = linker_mappings[i+1]['addr']

            if end_address_current != start_address_next:
                contiguous = False
                break

        return not contiguous

    def __get_plt_addr_from_r2_info(self, sections_info):

        for line in sections_info.split('\n'):
            if line.split() and ".plt" == line.split()[-1]:
                return int(line.split()[3], 16)

        raise StaticAnalyserException("The .plt section could not be found.")

    def __get_relocation_function_hardcoded(self, linker_bin):

        linker_path = self.elf_analyser.binary.lief_binary.interpreter
        linker_name = utils.f_name_from_path(linker_path)

        reloc_fun_name = None

        if linker_name == "ld-linux-x86-64.so.2":
            reloc_fun_name = "_dl_runtime_resolve_xsavec"
        elif linker_name == "ld-linux.so.2":
            reloc_fun_name = "_dl_runtime_resolve"
        elif "musl" in linker_name:
            # musl does not use lazy binding
            return None

        if reloc_fun_name is None:
            return None
            # Not sure it is a good idea to propose this. I let it here for
            # now but it is not used.
            # utils.print_error(
            #         f"The linker used by {self.elf_analyser.binary.path} is "
            #         f"{linker_name}. No relocation function is hardcoded for "
            #         f"this linker. Would you like to analyse the hardcoded "
            #         f"function for ld-linux-x86-64.so.2 "
            #         f"(_dl_runtime_resolve_xsavec) instead? [y/N]")
            # reloc_fun_name = "_dl_runtime_resolve_xsavec"
            # # TODO: add linker to libraries in the static analyser
        utils.print_error(
                    f"The linker used by {self.elf_analyser.binary.path} is "
                    f"{linker_name}. The relocation function for that linker "
                    f"is hardcoded to be{reloc_fun_name}. Would you like to "
                    f"analyse it instead? [y/N]")
        if utils.user_input.lower() == 'a':
            if input().lower() != 'y':
                return None
        elif utils.user_input.lower() != 'y':
            return None

        # get_function_with_name is not used because:
        # - it only looks at the exported functions and this one is not
        #   exported,
        # - it only looks at the libraries used by the binary.
        reloc_fun = None
        for f in linker_bin.functions:
            if f.name == reloc_fun_name:
                reloc_fun = [LibFunction(name=f.name,
                                         library_path=linker_path,
                                         boundaries=(f.address, f.address
                                                                 + f.size))]
                break
        if not reloc_fun:
            for f in linker_bin.symbols:
                if f.name == reloc_fun_name:
                    reloc_fun = [LibFunction(name=f.name,
                                             library_path=linker_path,
                                             boundaries=(f.value, f.value
                                                                   + f.size))]
                    break

        if not reloc_fun:
            utils.print_warning(f"[WARNING] The relocation function "
                                f"{reloc_fun_name} could not be found in "
                                f"{linker_name}.")
            return None

        if len(reloc_fun) > 1:
            utils.print_warning(f"[WARNING] Multiple possible relocation "
                                f"functions were found for {reloc_fun_name} "
                                f"in {linker_name}: {reloc_fun}.\n"
                                f"All of them will be considered.")

        return reloc_fun

    def __get_local_function(self, f_address, lib_name):

        lib = self.__libraries[lib_name]
        lib_bin = lib.code_analyser.elf_analyser.binary.lief_binary

        # If the f_address is in the functions, then we can easily get the
        # function boundaries
        local_function = None
        for f in lib_bin.functions:
            if f.address == f_address:
                local_function = LibFunction(name=f.name,
                                         library_path=lib.path,
                                         boundaries=(f.address, f.address
                                                                 + f.size))
                break

        # If not, the symbols of the libraries are searched. If it is not in
        # the symbols, just print a warning but it still can be analysed.
        shndx = None
        if local_function is None:
            for s in lib_bin.symbols:
                if s.value == f_address:
                    local_function = LibFunction(name=s.name,
                                                 library_path=lib.path,
                                                 boundaries=(s.value,
                                                             s.value + s.size))
                    shndx = s.shndx
                    break
            if local_function is None:
                utils.print_warning(f"[WARNING] The function at address "
                                    f"{hex(f_address)} of the library "
                                    f"{lib.path} is not in the symbols table.")
                local_function = LibFunction(name="[function name not found]",
                                    library_path=lib.path,
                                    boundaries=(0, 0))

        if local_function.boundaries[0] == 0:
            raise StaticAnalyserException("The function boundaries could not "
                                          "be found")

        # Sometimes, it is equal to 0, even if it was in the symbols table.
        if local_function.boundaries[1] <= local_function.boundaries[0]:
            # The boundaries can still be guessed by looking at the next entry
            # in the symbols table and verifying it indeed is in the same
            # section by using shndx. (may leed to overestimation)
            try:
                local_function.boundaries = (
                    f_address,
                    lib.code_analyser.elf_analyser.find_next_symbol_addr(
                        f_address, shndx))
            except StaticAnalyserException as e:
                raise StaticAnalyserException(f"The function boundaries "
                                          f"could not be found: {e}") from e

        return local_function

    def __get_got_rel_address(self, int_operand, is_first_plt_entry=False):

        jmp_to_got_ins = None

        if self.__plt_section and (not self.__plt_sec_section
                                   or is_first_plt_entry):
            # The instruction at the address pointed to by the int_operand is a
            # jump to a `.got` entry. With the address of this `.got`
            # relocation entry, it is possible to identify the function that
            # will be called. The jump instruction is of the form 'qword ptr
            # [rip + 0x1234]'.
            plt_offset = int_operand - self.__plt_section.virtual_address
            insns = self.__md.disasm(
                    bytearray(self.__plt_section.content)[plt_offset:],
                    int_operand)
            # If we try to get the linker call (i.e. we are looking in the
            # first plt entry), the second instruction is the one we want, so
            # the first is skipped.
            if is_first_plt_entry:
                next(insns)
            jmp_to_got_ins = next(insns)
        elif self.__plt_sec_section and not is_first_plt_entry:
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
        else:
            return None

        return (int(jmp_to_got_ins.op_str.split()[-1][:-1], 16)
                + utils.compute_rip(jmp_to_got_ins))

    def __find_used_libraries(self):

        if self.elf_analyser.binary.path != utils.app:
            # A binary sometimes uses the .plt section to call one of its own
            # functions. It isn't necessary to do it for the main app as
            # function calls aren't relevant there.
            self.add_used_library(self.elf_analyser.binary.path)

        try:
            ldd_output = subprocess.run(["ldd", self.elf_analyser.binary.path],
                                        check=True, capture_output=True)
            for line in ldd_output.stdout.splitlines():
                parts = line.decode("utf-8").split()
                if "=>" in parts:
                    self.add_used_library(parts[parts.index("=>") + 1],
                                          added_by_ldd=True)
                elif utils.f_name_from_path(parts[0]) in self.__used_libraries:
                    self.add_used_library(parts[0], added_by_ldd=True)
            if not set(self.__used_libraries).issubset(self
                                                       .__libraries.keys()):
                utils.print_warning("[WARNING] The `ldd` command didn't find "
                                    "all the libraries used.\nTrying to find "
                                    "the remaining libraries' path manually..."
                                    )
                self.__find_used_libraries_manually()
        except subprocess.CalledProcessError as e:
            utils.print_warning("[WARNING] ldd command returned with an error:"
                                " " + e.stderr.decode("utf-8") + "Trying to "
                                "find the libraries' path manually...")
            self.__find_used_libraries_manually()

    def __find_used_libraries_manually(self):

        lib_names = [lib for lib in self.__used_libraries
                     if lib not in self.__libraries]

        # If this is still not enough, adding a subprocess to use `locate` for
        # the other libraries is a possibility.

        lib_paths = self.get_libraries_paths_manually(lib_names)
        for path in lib_paths:
            if self.elf_analyser.is_valid_binary_path(path):
                self.add_used_library(path)

        if len(lib_names) > 0:
            utils.print_error(f"[ERROR] The following libraries couldn't be "
                              f"found and therefore won't be analysed: "
                              f"{lib_names}")
            self.__used_libraries = [l for l in self.__used_libraries
                                     if l not in lib_names]

    def __find_used_libraries_aliases(self, symbols_version_requirement):

        for svr in symbols_version_requirement:
            for aux_sym in svr.get_auxiliary_symbols():
                self.__used_libraries_aliases[aux_sym.name].append(svr.name)

    def __register_library(self, lib_path):

        # Beware before using this function:
        # - It only register the library in the __libraries variable, i.e. for
        #   the global scope. It does not register it for the current instance
        #   of the LibraryUsageAnalyser (use the add_used_library function for
        #   that).
        # - If the library has already been added via a different path, it will
        #   be overwritten.

        lib_name = utils.f_name_from_path(lib_path)

        lib_binary = lief.parse(lib_path)
        callable_fun_boundaries = {}
        for item in lib_binary.dynamic_symbols:
            # I could use `item.is_function` to only store functions or even
            # iterate over `lib_binary.exported_functions` but for some reason
            # they do not provide correct results. (for example strncpy is not
            # considered a function). Anyway, the memory footprint wouldn't
            # have been much different.
            # (Note that it is indeed dynamic_symbols and not symbols that
            # need to be used in this case!)
            callable_fun_boundaries[item.name] = (item.value,
                                                  item.value + item.size)

        # The entry needs to be added to the __libraries class variable
        # *before* creating the CodeAnalyser because calling the CodeAnalyser
        # constructor will bring us back in this function and if the
        # __libraries variable does not contain the entry, an infinite loop
        # may (will) occur.
        self.__libraries[lib_name] = Library(
                path=lib_path, callable_fun_boundaries=callable_fun_boundaries,
                code_analyser=None)
        code_analyser = None
        try:
            elf_analyser = ea.ELFAnalyser(lib_path)
            code_analyser = ca.CodeAnalyser(elf_analyser)
        except StaticAnalyserException as e:
            utils.print_error(f"[ERROR] Error during the creation of the code "
                              f"analyser for the library {lib_path}: {e}")
        self.__libraries[lib_name].code_analyser = code_analyser

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

        Raises
        ------
        StaticAnalyserException
            If no section could be obtained from the function's start address
            or if capstone disasm returned None
        """

        lib_name = utils.f_name_from_path(function.library_path)

        target_section = (self.__libraries[lib_name].code_analyser.elf_analyser
                          .get_section_from_address(function.boundaries[0]))
        f_start_offset = (function.boundaries[0]
                          - target_section.virtual_address)
        f_end_offset = function.boundaries[1] - target_section.virtual_address

        if f_end_offset < 0 or f_start_offset < 0:
            insns = None
        else:
            insns = self.__md.disasm(
                    bytearray(target_section.content)[f_start_offset:
                                                      f_end_offset],
                    target_section.virtual_address + f_start_offset)
        if insns is None:
            raise StaticAnalyserException(f"The instructions of the function "
                                          f"{function.name} could not be "
                                          f"found")

        return insns
