"""
Contains the CodeAnalyser class.

Disassembles and analyses the code to detect syscalls.
"""

from os.path import isfile

# CS_GRP_CALL is always used with CS_GRP_JUMP because some functions are
# called with a jump instruction not detected by the group CS_GRP_CALL
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP
from capstone.x86_const import X86_INS_INVALID, X86_INS_DATA16

import utils
import syscalls
import library_analyser
import asm_code_utils as code_utils
from custom_exception import StaticAnalyserException
from asm_code_utils import detect_syscall_type


class CodeAnalyser:
    """CodeAnalyser(elf_analyser) -> CodeAnalyser

    Class used to analyse the binary code to detect syscalls.

    This class directly analyse what is inside the executable sections of the
    ELF executable but it also uses `LibraryUsageAnalyser` to (indirectly)
    analyse syscalls used by shared library calls.

    Public Methods
    --------------
    launch_analysis(self, syscalls_set):
        Entry point of the Code Analyser. Updates the syscall set passed as
        argument after analysing the binary.
    get_used_syscalls_all_executable_sections(self, syscalls_set)
        Updates the syscall set passed as argument after analysing all the
        executable sections of the binary.
    get_used_syscalls_of_section(self, syscalls_set):
        Updates the syscall set passed as argument after analysing the given
        section of the binary.
    analyse_imported_functions(self, syscalls_set):
        Analyse the functions imported by the binary ,as specified within the
        ELF.
    analyse_code(self, insns, syscalls_set, f_called_list=None):
        Main function of the Code Analyser. Updates the syscall set and the
        list of functions called after analysing the given instructions.
    analyse_detected_dlsym_functions(self, syscalls_set):
        Analyse all the functions inside `self.__dlsym_f_names`. If new
        functions detected with dlsym are found or if a function in the list
        couldn't be analysed, they will be analysed in the next iteration.
    """

    def __init__(self, elf_analyser):

        self.elf_analyser = elf_analyser

        self.elf_analyser.binary.has_dyn_libraries = bool(
                self.elf_analyser.binary.lief_binary.libraries)

        self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.__md.detail = True
        # This may lead to errors. So a warning is throwed if indeed data is
        # found.
        self.__md.skipdata = utils.skip_data

        if self.elf_analyser.binary.has_dyn_libraries:
            try:
                self.__init_lib_analyser()
            except StaticAnalyserException as e:
                utils.print_error(f"[ERROR] library analyser of "
                                  f"{self.elf_analyser.binary.path} couldn't "
                                  f"be created: {e}")
                self.elf_analyser.binary.has_dyn_libraries = False

        self.__dlsym_f_names = set()

    # ------------------------------ Entry Point ------------------------------

    def launch_analysis(self, syscalls_set):
        """Entry point of the Code Analyser. Updates the syscall set
        passed as argument after analysing the binary.

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed
        """

        if self.elf_analyser.binary.has_dyn_libraries and utils.analyse_linker:
            # Analyse the first function of the linker, which is the one that
            # will be called when executing the program (before any instruction
            # of the main binary) and if there is a .plt section, also analyse
            # the linker function that performs .plt functions resolution
            self.__lib_analyser.analyse_linker_functions(syscalls_set)

        self.get_used_syscalls_all_executable_sections(syscalls_set)

        # Some of the function calls might not have been detected due to
        # informations that can only be obtained at runtime. Therefore, all the
        # imported functions are then analysed (if they haven't been already).
        # Be careful that it is possible to have imported functions that are
        # never used in the code. But because the goal of this program is to
        # have an upper bound, this function is called by default.
        if (utils.all_imported_functions
            and self.elf_analyser.binary.has_dyn_libraries):
            self.analyse_imported_functions(syscalls_set)

        while self.__dlsym_f_names:
            # The order of analysis of the code is not the order in which it
            # will be analysed. It is therefore possible to find a dlsym
            # instruction before the dlopen instruction that would have loaded
            # the library needed by dlsym. To avoid such cases, all the
            # functions called by dlsym are resolved and analysed only here.
            # The function that are analysed here can, once again, not be
            # analysed in the correct order, hence this while loop.
            self.analyse_detected_dlsym_functions(syscalls_set)
            # It is unlikely that libraries use runtime loading techniques, but
            # we never know
            self.__lib_analyser.analyse_detected_dlsym_for_all_libs(
                    syscalls_set)

    # -------------------------- Main Functionalities -------------------------

    def get_used_syscalls_all_executable_sections(self, syscalls_set):
        """Updates the syscall set passed as argument after analysing all the
        executable sections of the binary.

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed
        """

        for section in self.elf_analyser.binary.lief_binary.sections:
            if section.name in (".plt.sec", ".plt"):
                # All functions in the .plt section are analysed in the
                # `analyse_imported_functions` function
                continue
            if self.elf_analyser.is_executable_section(section):
                self.get_used_syscalls_of_section(section, syscalls_set)

    def get_used_syscalls_of_section(self, section, syscalls_set):
        """Updates the syscall set passed as argument after analysing the
        given section of the binary.

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed
        """

        bytes_to_analyse = section.size
        start_analyse_at = section.virtual_address

        while bytes_to_analyse > 0:
            to_analyse = bytearray(section.content)[section.size
                                                    - bytes_to_analyse:]
            # ---------------- Main part of the function here ----------------
            try:
                bytes_analysed = self.analyse_code(
                        self.__md.disasm(to_analyse, start_analyse_at),
                        syscalls_set)
            except StaticAnalyserException as e:
                utils.print_error(f"[ERROR] while analysing the code of "
                                  f"{section.name} section of "
                                  f"{self.elf_analyser.binary.path}: {e}")
                break
            # ----------------------------------------------------------------

            bytes_to_analyse -= bytes_analysed
            if not bytes_to_analyse:
                continue
            stopped_at = (section.virtual_address + section.size
                          - bytes_to_analyse)
            utils.print_error(f"[ERROR] analysis of `{section.name}` section "
                              f"of {self.elf_analyser.binary.path} stopped at "
                              f"{hex(stopped_at)} (probably due to some data "
                              f"found inside). Trying to continue the analysis"
                              f" at the next function...")
            start_analyse_at = (self.elf_analyser
                                .find_next_function_addr(stopped_at))
            bytes_to_skip = start_analyse_at - stopped_at
            utils.print_error(f"[ERROR] {bytes_to_skip} bytes skipped")

            bytes_to_analyse -= bytes_to_skip

    def analyse_imported_functions(self, syscalls_set):
        """Analyse the functions imported by the binary, as specified within
        the ELF.

        Note that functions already analysed won't be analysed again as
        designed by the library analyser.

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed
        """

        utils.log("\nStarting the analysis of imported functions from the main"
                  " binary that might not have been found.\n",
                  "lib_functions.log")
        utils.log("Starting the analysis of imported functions from the main "
                  "binary that might not have been found.\n", "backtrack.log")

        for f in self.elf_analyser.binary.lief_binary.imported_functions:
            if "@" in f.name:
                continue
            if (hasattr(f, "symbol_version")
                and f.symbol_version.has_auxiliary_version):
                funs = self.__lib_analyser.get_function_with_name(
                        f.name,
                        lib_alias=f.symbol.symbol_version
                                   .symbol_version_auxiliary.name)
            else:
                funs = self.__lib_analyser.get_function_with_name(f.name)
            self.__lib_analyser.get_used_syscalls(syscalls_set, funs)

    def analyse_code(self, insns, syscalls_set, f_called_list=None):
        """Main function of the Code Analyser. Updates the syscall set and the
        list of functions called after analysing the given instructions.

        Parameters
        ----------
        insns : class generator of capstone
            list of instructions to analyse
        syscalls_set : set of str
            set of syscalls used by the program analysed
        f_called_list : None or list of LibFunction, optional
            if a list is given, the functions called by the given instructions
            will be added in this list

        Returns
        -------
        bytes_analysed : int
            size (in bytes) of the code analysed (rarely used by the calling
            function)

        Raises
        ------
        StaticAnalyserException
            If the given instructions could not be analysed
        """

        list_inst = []
        for _, ins in enumerate(insns):
            list_inst.append(ins)

            # --- Error management ---
            if ins.id in (X86_INS_DATA16, X86_INS_INVALID):
                utils.print_error(f"[WARNING] data instruction found in "
                                  f"{self.elf_analyser.binary.path} at address"
                                  f" {hex(ins.address)}")
                continue

            # --- Syscalls detection ---
            if ins.mnemonic == "syscall":
                self.__backtrack_syscalls(list_inst, syscalls_set)
                continue

            # --- Function calls detection (until the end of the loop) ---
            dest_address, show_warnings = (
                    code_utils.extract_destination_address(list_inst,
                                                           self.elf_analyser))

            self.__analyse_destination_address(dest_address, list_inst,
                                             syscalls_set, f_called_list,
                                             show_warnings)

        if not list_inst:
            raise StaticAnalyserException("[ERROR] The given instructions "
                                          "could not be analysed", True)
        bytes_analysed = (list_inst[-1].address + list_inst[-1].size
                          - list_inst[0].address)
        return bytes_analysed

    # ---------------------------- Syscall Related ----------------------------

    def __analyse_syscall_functions(self, f_to_analyse, list_inst,
                                    syscalls_set):

        if not (list_inst[-1].group(CS_GRP_CALL)
                or list_inst[-1].group(CS_GRP_JUMP)):
            # The function is not called, it is just a function pointer
            # -> not supported
            return

        for f in f_to_analyse.copy():
            # There should be no need to check the address of the
            # function as the syscall function is public and therefore
            # should always provide its name
            if f.name == "syscall":
                self.__backtrack_syscalls(list_inst, syscalls_set, True)
                # The current implementation of libc's syscall function
                # does not call other syscalls than the one provided as
                # argument, and it is unlikely to change.
                f_to_analyse.remove(f)

    def __backtrack_syscalls(self, list_inst, syscalls_set,
                             is_function=False):

        if is_function:
            utils.log(f"syscall function called: {hex(list_inst[-1].address)} "
                      f"{list_inst[-1].mnemonic} {list_inst[-1].op_str} from "
                      f"{self.elf_analyser.binary.path}", "backtrack.log")
            nb_syscall = code_utils.backtrack_register("edi", list_inst,
                                                       self.elf_analyser)
        else:
            utils.log(f"{detect_syscall_type(list_inst[-1])}: "
                      f"{hex(list_inst[-1].address)} {list_inst[-1].mnemonic} "
                      f"{list_inst[-1].op_str} from "
                      f"{self.elf_analyser.binary.path}", "backtrack.log")
            nb_syscall = code_utils.backtrack_register("eax", list_inst,
                                                       self.elf_analyser)

        # the `syscall` instruction look into `eax` (32 bits), not `rax` (64
        # bits). Because `backtrack_register` returns a value on 64 bits, there
        # may have been an overflow on 32 bits (for example because of negative
        # values in 2-th complement).
        if isinstance(nb_syscall, int):
            nb_syscall %= 2**32

        if nb_syscall in syscalls.syscalls_map:
            name = syscalls.syscalls_map[nb_syscall]
            utils.print_verbose(f"Syscall found: {name}: {nb_syscall}")
            utils.log(f"Found: {name}: {nb_syscall}\n", "backtrack.log")
            syscalls_set.add(name)
        else:
            utils.log(f"Ignore {nb_syscall}\n", "backtrack.log")
            utils.print_verbose(f"Syscall instruction detected but syscall ID "
                                f"not found or invalid: {nb_syscall}")

    # -------------------- Libraries or Functions Related ---------------------

    def analyse_detected_dlsym_functions(self, syscalls_set):
        """Analyse all the functions inside `self.__dlsym_f_names`. If new
        functions detected with dlsym are found or if a function in the list
        couldn't be analysed, they will be analysed in the next iteration.
        (because new libraries could be found with dlopen during the current
        iteration)

        The loop stops when no functions could be analysed in an iteration
        (either because it wasn't found or because it has already been
        analysed).

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed
        """

        # analysing syscall functions is useless as the syscall ID is given as
        # an argument
        if "syscall" in self.__dlsym_f_names:
            self.__dlsym_f_names.remove("syscall")

        f_to_analyse = []
        for fun_name in self.__dlsym_f_names.copy():
            f = self.__lib_analyser.get_function_with_name(fun_name)
            if not f:
                # leave it in the set because it may need a library that will
                # be loaded (with dlopen) in the following analysis
                continue
            f_to_analyse.extend(f)
            self.__dlsym_f_names.remove(fun_name)

        if not f_to_analyse:
            # If no functions were found, no further analysis can be performed.
            # The content of __dlsym_f_names thus needs to be emptied to avoid
            # trying to continue the analysis indefinitely
            self.__dlsym_f_names.clear()
            return

        # loops in the call graph do not cause loops here because if a function
        # has already been analysed, it won't be analysed again and therefore
        # the functions it is calling won't be added to `__dlsym_f_names`
        self.__lib_analyser.get_used_syscalls(syscalls_set, f_to_analyse)

    def __init_lib_analyser(self):
        """
        Raises
        ------
        StaticAnalyserException
            If the library analyser couldn't be created
        """

        self.__lib_analyser = library_analyser.LibraryUsageAnalyser(
                self.elf_analyser)

    def __analyse_destination_address(self, dest_address, list_inst,
                                      syscalls_set, f_called_list,
                                      show_warnings):
        """Analyse the destination address and update the syscall set and the
        list of functions called.

        Parameters
        ----------
        dest_address : class Destination
            destination address to analyse
        list_inst : list of capstone instruction
            the instructions leading to the one to consider (included)
        syscalls_set : set of str
            set of syscalls used by the program analysed
        f_called_list : None or list of LibFunction, optional
            if a list is given, the functions called by the given instructions
            will be added in this list
        show_warnings : bool
            if True, warnings will be printed if the function called could not
            be found
        """

        if dest_address is None:
            return

        if f_called_list is None:
            detect_local_funs = False
        else:
            detect_local_funs = True

        if self.elf_analyser.binary.has_dyn_libraries:
            funs = None
            if (dest_address.f_name is not None
                and not dest_address.is_local):

                # In some (rare) cases, library functions can be called
                # without going through the .plt
                funs = self.__lib_analyser.get_function_with_name(
                        dest_address.f_name)
            elif (self.__lib_analyser.is_call_to_plt(dest_address.value)
                  and dest_address.is_local):

                funs = self.__get_called_plt_functions(dest_address.value,
                                                       f_called_list)
            self.__wrapper_analyse_lib_function(funs, list_inst,
                                                syscalls_set)
            if funs is not None:
                # Even if no function was found (funs == []), the address
                # did correspond to a library function, so the iteration
                # stops here
                return

        if detect_local_funs and (list_inst[-1].group(CS_GRP_CALL)
                                  or list_inst[-1].group(CS_GRP_JUMP)
                                  or utils.search_function_pointers):
            f = self.elf_analyser.get_local_function_called(
                    dest_address.value, show_warnings)
            if f is None:
                return
            if f.boundaries[0] >= f.boundaries[1]:
                # TODO: trouver une solution générale pour essayer
                # d'analyser la fonction même si on a pas la taille ?
                # TODO: dans tous les cas on devrait pas le hardcoder ici.
                if f.name == "__restore_rt":
                    # particular case where for some reason the ELF
                    # indicates that this function's size is 0
                    syscalls_set.add(syscalls.syscalls_map[0xf])
                return

            f_array = [f]
            self.__analyse_syscall_functions(f_array, list_inst,
                                             syscalls_set)
            if f_array and f not in f_called_list:
                f_called_list.append(f)

    def __get_called_plt_functions(self, plt_fun_addr, f_called_list):

        called_plt_funs = self.__lib_analyser.get_plt_function_called(
                plt_fun_addr)
        # Even if f_called_list is None, called_plt_f needs to be
        # cleaned from local functions
        code_utils.mov_local_funs_to(f_called_list, called_plt_funs,
                                     self.elf_analyser)
        return called_plt_funs

    def __wrapper_analyse_lib_function(self, lib_funs, list_inst,
                                       syscalls_set):

        if not lib_funs:
            return

        self.__detect_and_process_runtime_loading_functions(lib_funs,
                                                            list_inst)
        self.__analyse_syscall_functions(lib_funs, list_inst, syscalls_set)
        self.__lib_analyser.get_used_syscalls(syscalls_set, lib_funs)

    def __backtrack_dlopen(self, list_inst):

        try:
            # When calling dlopen, the first argument (in `edi`) contains a
            # pointer to the name of the library
            lib_name_address = code_utils.backtrack_register("edi", list_inst,
                                                             self.elf_analyser)
            self.__add_library_from_dlopen(lib_name_address)

        except StaticAnalyserException as e:
            utils.log(f"Ignore {lib_name_address}\n", "backtrack.log")
            if e.is_critical:
                utils.print_error(f"{e}")
            else:
                utils.print_warning(f"{e}")

    def __backtrack_dlmopen(self, list_inst):

        try:
            # When calling dlmopen, the second argument (in `esi`) contains a
            # pointer to the name of the library
            lib_name_address = code_utils.backtrack_register("esi", list_inst,
                                                             self.elf_analyser)
            # The procedure is the same as for dlopen, thus the function name
            self.__add_library_from_dlopen(lib_name_address)

        except StaticAnalyserException as e:
            utils.log(f"Ignore {lib_name_address}\n", "backtrack.log")
            if e.is_critical:
                utils.print_error(f"{e}")
            else:
                utils.print_warning(f"{e}\n")

    def __backtrack_dlsym(self, list_inst):

        try:
            fun_name_address = code_utils.backtrack_register("esi", list_inst,
                                                             self.elf_analyser)

            if fun_name_address is None or fun_name_address < 0:
                raise StaticAnalyserException(
                        f"[WARNING] A function loaded with dlsym in "
                        f"{self.elf_analyser.binary.path} could not be found")

            fun_name = self.elf_analyser.get_string_at_address(
                    fun_name_address)

            utils.log(f"Found: {fun_name}\n", "backtrack.log")

            self.__dlsym_f_names.add(fun_name)
        except StaticAnalyserException as e:
            utils.log(f"Ignore {fun_name_address}\n", "backtrack.log")
            utils.print_error(f"{e}")

    def __detect_and_process_runtime_loading_functions(self, called_plt_f,
                                                       list_inst):

        for f in called_plt_f:
            if (not utils.f_name_from_path(f.library_path).startswith("libc")
                or not (list_inst[-1].group(CS_GRP_CALL)
                        or list_inst[-1].group(CS_GRP_JUMP))):

                continue
            # No need to check if self.__lib_analyser is initialised because if
            # not, this function will never be called
            log_str_end = (f" instruction: {hex(list_inst[-1].address)} "
                           f"{list_inst[-1].mnemonic} {list_inst[-1].op_str}")
            if f.name == "dlopen":
                utils.log("dlopen" + log_str_end, "backtrack.log")
                self.__backtrack_dlopen(list_inst)
            elif f.name == "dlmopen":
                utils.log("dlmopen" + log_str_end, "backtrack.log")
                self.__backtrack_dlmopen(list_inst)
            elif f.name in ("dlsym", "dlvsym"):
                utils.log("dlsym" + log_str_end, "backtrack.log")
                self.__backtrack_dlsym(list_inst)

    def __add_library_from_dlopen(self, file_name_address):
        """
        Raises
        ------
        StaticAnalyserException
            If the library location cannot be found
        """

        if file_name_address == 0:
            # A NULL ptr means dlmopen was use to get a handle on the main
            # (current) executable
            return
        if file_name_address is None or  file_name_address < 0:
            raise StaticAnalyserException(
                    f"[WARNING] A library loaded with `dlopen` in "
                    f"{self.elf_analyser.binary.path} could not be found",
                    False)

        lib_name = self.elf_analyser.get_string_at_address(file_name_address)

        lib_paths = ([lib_name] if isfile(lib_name)
                     else self.__lib_analyser
                     .get_libraries_paths_manually([lib_name]))

        if not lib_paths:
            raise StaticAnalyserException(
                    f"[WARNING] The library (supposedly) named \"{lib_name}\" "
                    f"loaded with dlopen in {self.elf_analyser.binary.path} "
                    f"could not be found", False)

        self.__dlopen_paths_to_lib_paths(lib_paths)

        utils.log(f"Results: {lib_name} at {lib_paths}\n", "backtrack.log")
        # TODO: All the libraries pointed to by the GNU ld script are taken
        # into account, but they only should if the previous entries do not
        # contain the wanted function.
        for p in lib_paths:
            self.__lib_analyser.add_used_library(p)

    def __dlopen_paths_to_lib_paths(self, lib_paths):
        """Remove or transform entries of lib_paths into actual libraries
        paths.

        The library paths given by dlopen may lead to actual libraries, to GNU
        ld scripts or to nonexisting files.

        Raises
        ------
        StaticAnalyserException
            If no valid paths to libraries were found
        """

        lib_paths_copy = lib_paths.copy()
        for p in lib_paths_copy:
            if not self.elf_analyser.is_valid_binary_path(p):
                # dlopen (may) lead to a GNU ld script that points to the
                # actual libraries
                try:
                    lib_paths.extend(self.__lib_analyser
                                     .get_lib_from_GNU_ld_script(p))
                except FileNotFoundError:
                    utils.print_error(f"[ERROR] File not found at {p}")
                except UnicodeDecodeError:
                    pass
                finally:
                    lib_paths.remove(p)
        if lib_paths_copy and not lib_paths:
            raise StaticAnalyserException(
                    f"[ERROR] The library paths {lib_paths_copy} loaded with "
                    f"dlopen in {self.elf_analyser.binary.path} does not lead "
                    f"to valid binaries or scripts")
