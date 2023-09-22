"""
Contains the CodeAnalyser class.

Disassembles and analyses the code to detect syscalls.
"""

import sys

from dataclasses import dataclass
from copy import copy
from os.path import isfile

import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL
from capstone.x86_const import X86_INS_INVALID, X86_INS_DATA16

import utils
import library_analyser
from custom_exception import StaticAnalyserException
from elf_analyser import (is_valid_binary, is_valid_binary_path,
                          get_text_section, get_string_at_address)

@dataclass
class ELFBinary:
    """Represents an ELF binary.

    Attributes
    ----------
    path : str
        the path of the binary in the file system
    lief_binary : lief binary
        the lief representation of the binary
    rodata_sect : lief section
        the lief representation of the .rodata section
    text_sect : lief section
        the lief representation of the .text section
    has_dyn_libraries : bool
        false if the binary uses no dynamic libraries or if the library
        analyser associated to the binary couldn't be created
    """

    path: str
    lief_binary: lief._lief.ELF.Binary
    rodata_sect: lief._lief.ELF.Section
    text_sect: lief._lief.ELF.Section
    has_dyn_libraries: bool


class CodeAnalyser:
    """CodeAnalyser(path) -> CodeAnalyser

    Class use to store information about and analyse the binary code to detect
    syscalls.

    This class directly analyse what is inside the `.text` sectin of the ELF
    executable but it also uses `LibraryUsageAnalyser` to (indirectly) analyse
    syscalls used by shared library calls.

    Public Methods
    --------------
    get_used_syscalls_text_section(self, syscalls_set, inv_syscalls_map)
        Updates the syscall set passed as argument after analysing the `.text`
        of the binary.
    analyse_code(self, insns, syscalls_set, inv_syscalls_map[, f_called_list])
        Updates the syscall set passed as argument after analysing the given
        instructions.
    """


    # Used to detect the syscall identifier.
    # The "high byte" (for example 'ah') is not considered. It could be,
    # to be exhaustive, but it would be unlikely to store the syscall id using
    # this identifier (and the code should be modified).
    __registers = {'eax':  {'rax','eax','ax','al'},
                 'ebx':  {'rbx','ebx','bx','bl'},
                 'ecx':  {'rcx','ecx','cx','cl'},
                 'edx':  {'rdx','edx','dx','dl'},
                 'esi':  {'rsi','esi','si','sil'},
                 'edi':  {'rdi','edi','di','dil'},
                 'ebp':  {'rbp','ebp','bp','bpl'},
                 'esp':  {'rsp','esp','sp','spl'},
                 'r8d':  {'r8','r8d','r8w','r8b'},
                 'r9d':  {'r9','r9d','r9w','r9b'},
                 'r10d': {'r10','r10d','r10w','r10b'},
                 'r11d': {'r11','r11d','r11w','r11b'},
                 'r12d': {'r12','r12d','r12w','r12b'},
                 'r13d': {'r13','r13d','r13w','r13b'},
                 'r14d': {'r14','r14d','r14w','r14b'},
                 'r15d': {'r15','r15d','r15w','r15b'}}


    def __init__(self, path):

        lief_binary = lief.parse(path)
        if not is_valid_binary(lief_binary):
            raise StaticAnalyserException("The given binary is not a CLASS64 "
                                          "ELF file.")
        self.binary = ELFBinary(
                path = path,
                lief_binary = lief_binary,
                rodata_sect = None,
                text_sect = None,
                has_dyn_libraries = bool(lief_binary.libraries)
                )

        self.__md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.__md.detail = True
        # This may lead to errors. So a warning is throwed if indeed data is
        # found.
        self.__md.skipdata = utils.skip_data

        # may not be used
        self.__address_to_fun_map = None
        self.__f_name_to_addr_map = None

        if not self.binary.has_dyn_libraries:
            return

        try:
            self.__lib_analyser = library_analyser.LibraryUsageAnalyser(
                    self.binary.lief_binary, self.binary.path)
        except StaticAnalyserException as e:
            sys.stderr.write(f"[ERROR] library analyser of "
                             f"{self.binary.path} couldn't be created: {e}\n")
            self.binary.has_dyn_libraries = False

    def get_used_syscalls_text_section(self, syscalls_set, inv_syscalls_map):
        """Entry point of the Code Analyser. Updates the syscall set
        passed as argument after analysing the `.text` of the binary.

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed
        inv_syscalls_map : dict(int -> str)
            the syscall map defined in syscalls.py but with keys and values
            swapped
        """

        text_section = get_text_section(self.binary)

        self.analyse_code(self.__md.disasm(bytearray(text_section.content),
                                   text_section.virtual_address),
                         syscalls_set, inv_syscalls_map)

    def analyse_code(self, insns, syscalls_set, inv_syscalls_map,
                     f_called_list=None):
        """Main function of the Code Analyser. Updates the syscall set and the
        list of functions called after analysing the given instructions.

        Parameters
        ----------
        insns : class generator of capstone
            list of instructions to analyse
        syscalls_set : set of str
            set of syscalls used by the program analysed
        inv_syscalls_map : dict(int -> str)
            the syscall map defined in syscalls.py but with keys and values
            swapped
        f_called_list : None or list of LibFunction, optional
            if a list is given, the functions called by the given instructions
            will be added in this list
        """

        if f_called_list is None:
            detect_functions = False
        else:
            detect_functions = True

        list_inst = []
        for i, ins in enumerate(insns):
            list_inst.append(ins)

            if ins.id in (X86_INS_DATA16, X86_INS_INVALID):
                sys.stderr.write(f"[WARNING] data instruction found in "
                                 f"{self.binary.path} at address "
                                 f"{hex(ins.address)}\n")
                continue

            if self.__is_syscall_instruction(ins):
                self.__backtrack_syscalls(i, list_inst, syscalls_set,
                                                inv_syscalls_map)
                continue

            dest_address = None
            if ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL):
                dest_address = self.__get_destination_address(
                        ins.op_str, utils.compute_rip(ins))
                show_warnings = True
            elif ins.regs_access()[1]:
                # Check for function pointers. This slows down the process a
                # bit, is approximative and rarely brings results so one might
                # want to remove it
                assigned = self.__compute_assigned_value(ins)
                if isinstance(assigned, int) and assigned > 0:
                    dest_address = assigned
                show_warnings = False

            if dest_address is None:
                continue

            if (self.binary.has_dyn_libraries
                and self.__lib_analyser.is_call_to_plt(dest_address)):
                f_to_analyse = self.__wrapper_get_function_called(
                                            dest_address, i, list_inst)
                # Even if f_called_list is None, f_to_analyse needs to be
                # cleaned from local functions
                self.__mov_local_funs_to(f_called_list, f_to_analyse)
                self.__lib_analyser.get_used_syscalls(syscalls_set,
                                                      f_to_analyse)
            elif detect_functions and ins.group(CS_GRP_CALL):
                f = self.__get_local_function_called(dest_address,
                                                     show_warnings)
                if f and f not in f_called_list:
                    f_called_list.append(f)

    def __backtrack_register(self, focus_reg, index, list_inst):
        # Beware that it will be considered that the value is put inside the
        # register in one operation. For example, this type of code is not
        # supported:
        # mov rdi, 0x1234
        # shl rdi, 16
        # mov di, 0x5678

        last_ins_index = max(0, index-1-utils.max_backtrack_insns)
        for i in range(index-1, last_ins_index, -1):
            if list_inst[i].id in (X86_INS_DATA16, X86_INS_INVALID):
                continue

            utils.log(f"-> {hex(list_inst[i].address)}:{list_inst[i].mnemonic}"
                      f" {list_inst[i].op_str}", "backtrack.log", indent=1)

            regs_write = list_inst[i].regs_access()[1]
            for r in regs_write:
                if self.__md.reg_name(r) not in self.__registers[focus_reg]:
                    continue

                assigned_value = self.__compute_assigned_value(list_inst[i])

                ret = -1
                if assigned_value is None:
                    utils.log("[Operation not supported]",
                              "backtrack.log", indent=2)
                elif isinstance(assigned_value, int):
                    ret = assigned_value
                elif self.__is_reg(assigned_value):
                    focus_reg = assigned_value
                    utils.log(f"[Shifting focus to {focus_reg}]",
                              "backtrack.log", indent=2)
                    continue

                return ret

        return -1

    def __backtrack_dlopen(self, i, list_inst):

        try:
            # When calling dlopen, the first argument (in `edi`) contains a
            # pointer to the name of the library
            lib_name_address = self.__backtrack_register("edi", i, list_inst)
            self.__process_dlopen_filename_arg(lib_name_address)

        except StaticAnalyserException as e:
            utils.log(f"Ignore {hex(lib_name_address)}\n", "backtrack.log")
            if e.is_critical:
                sys.stderr.write(f"{e}\n")
            else:
                utils.print_warning(f"{e}\n")

    def __backtrack_dlmopen(self, i, list_inst):

        try:
            # When calling dlmopen, the second argument (in `esi`) contains a
            # pointer to the name of the library
            lib_name_address = self.__backtrack_register("esi", i, list_inst)
            # The procedure is the same as for dlopen, thus the function name
            self.__process_dlopen_filename_arg(lib_name_address)

        except StaticAnalyserException as e:
            utils.log(f"Ignore {hex(lib_name_address)}\n", "backtrack.log")
            if e.is_critical:
                sys.stderr.write(f"{e}\n")
            else:
                utils.print_warning(f"{e}\n")

    def __process_dlopen_filename_arg(self, file_name_address):
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
        if file_name_address < 0:
            raise StaticAnalyserException(
                    f"[WARNING] A library loaded with dlopen in "
                    f"{self.binary.path} could not be found", False)

        lib_name = get_string_at_address(self.binary, file_name_address)

        lib_paths = ([lib_name] if isfile(lib_name)
                     else self.__lib_analyser
                     .get_libraries_paths_manually([lib_name]))

        if not lib_paths:
            raise StaticAnalyserException(
                    f"[WARNING] The library (supposedly) named "
                    f"\"{lib_name}\" loaded with dlopen in "
                    f"{self.binary.path} could not be found", False)

        self.__process_lib_paths_by_dlopen(lib_paths)

        utils.log(f"Results: {lib_name} at {lib_paths}\n", "backtrack.log")
        # TODO: All the libraries pointed to by the script are taken into
        # account, but they only should if the previous entries do not
        # contain the wanted function
        for p in lib_paths:
            self.__lib_analyser.add_used_library(p)

    def __backtrack_dlsym(self, i, list_inst):

        try:
            fun_name_address = self.__backtrack_register("esi", i, list_inst)

            if fun_name_address < 0:
                raise StaticAnalyserException(
                        f"[WARNING] A function loaded with dlsym in "
                        f"{self.binary.path} could not be found")

            fun_name = get_string_at_address(self.binary, fun_name_address)

            utils.log(f"Found: {fun_name}\n", "backtrack.log")

            return self.__lib_analyser.get_function_with_name(fun_name)
        except StaticAnalyserException as e:
            utils.log(f"Ignore {hex(fun_name_address)}\n", "backtrack.log")
            sys.stderr.write(f"{e}\n")
            return []

    def __backtrack_syscalls(self, i, list_inst, syscalls_set,
                                     inv_syscalls_map):

        # utils.print_debug("syscall detected at instruction: "
        #                   + str(list_inst[-1]))
        nb_syscall = self.__backtrack_register("eax", i, list_inst)
        if nb_syscall != -1 and nb_syscall < len(inv_syscalls_map):
            name = inv_syscalls_map[nb_syscall]
            utils.print_verbose(f"Syscall found: {name}: {nb_syscall}")
            utils.log(f"Found: {name}: {nb_syscall}\n", "backtrack.log")
            syscalls_set.add(name)
        else:
            utils.log(f"Ignore {nb_syscall}\n", "backtrack.log")
            utils.print_verbose(f"Syscall instruction found but ignored: "
                                f"{nb_syscall}")

    def __is_syscall_instruction(self, ins):

        b = ins.bytes
        if b[0] == 0x0f and b[1] == 0x05:
            # Direct syscall SYSCALL
            utils.log(f"DIRECT SYSCALL (x86_64): {hex(ins.address)} "
                      f"{ins.mnemonic} {ins.op_str}", "backtrack.log")
            return True
        if b[0] == 0x0f and b[1] == 0x34:
            # Direct syscall SYSENTER
            utils.log(f"SYSENTER: {hex(ins.address)} {ins.mnemonic} "
                      f"{ins.op_str}", "backtrack.log")
            return True
        if b[0] == 0xcd and b[1] == 0x80:
            # Direct syscall int 0x80
            utils.log(f"DIRECT SYSCALL (x86): {hex(ins.address)} "
                      f"{ins.mnemonic} {ins.op_str}", "backtrack.log")
            return True
        return False

    def __get_destination_address(self, operand, rip_value):
        """Returns the destination address of the given operand of the call (or
        jmp).

        Parameters
        ----------
        operand : str
            operand of the call (or jump)
        rip_value : int
            the value of the rip register (address of next instruction)

        Returns
        -------
        address : int
            destination address of the given operand of the call (or jump)
        """

        address = None

        if utils.is_number(operand):
            address = utils.str2int(operand)
        elif (operand.startswith("qword ptr [rip +")
              and len(operand.split()) == 5):
            offset = operand.split()[4][:-1]
            if utils.is_number(offset):
                address_location = rip_value + utils.str2int(offset)
                rel = self.binary.lief_binary.get_relocation(address_location)
                if rel and rel.has_symbol and rel.symbol.name != "":
                    address = self.__get_local_function_address(
                            rel.symbol.name, False)
                if rel and address is None and rel.addend != 0:
                    address = rel.addend
        elif "rip" in operand:
            print(f"gougoug {operand}")

        if address is None:
            # TODO: Other things could be done to try obtaining the address
            utils.print_warning("[WARNING] A function may have been called but"
                                " couln't be found. This is probably due "
                                "to an indirect address call.")

        return address

    # TODO il y a des trucs qui font doublon avec
    # __get_local_function_called... En plus cette fonction ci est sensée être
    # déjà implémentée dans lief mais elle marche pas...
    def __get_local_function_address(self, f_name, show_warnings=True):
        """Returns the address of the local function with the given name
        Parameters
        ----------
        f_name : str
            name of the function that is to be found
        show_warnings : bool
            whether or not should a warning be thrown if no function was found

        Returns
        -------
        f_address : int
            address of the function
        """

        if self.__f_name_to_addr_map is None:
            self.__initialise_f_name_to_addr_map()

        if f_name not in self.__f_name_to_addr_map:
            if show_warnings:
                utils.print_warning(f"[WARNING] A function was called but "
                                    f"couln't be found with its name: "
                                    f"{f_name}")
            return None

        return self.__f_name_to_addr_map[f_name]

    def __initialise_f_name_to_addr_map(self):

        self.__f_name_to_addr_map = {}
        for item in self.binary.lief_binary.functions:
            self.__f_name_to_addr_map[item.name] = item.address


    def __get_local_function_called(self, f_address, show_warnings=True):
        """Returns the function that would be called by jumping to the address
        given.

        Parameters
        ----------
        f_address : int
            address of the called function
        show_warnings : bool
            Whether or not should a warning be thrown if no function was found

        Returns
        -------
        called_plt_f : LibFunction
            function that would be called
        """

        if self.__address_to_fun_map is None:
            self.__initialise_address_to_fun_map()

        if f_address not in self.__address_to_fun_map:
            if show_warnings:
                utils.print_warning(f"[WARNING] A function was called but "
                                    f"couln't be found with its address: "
                                    f"{f_address}")
            return None

        return self.__address_to_fun_map[f_address]

    def __initialise_address_to_fun_map(self):

        self.__address_to_fun_map = {}
        for item in self.binary.lief_binary.functions:
            self.__address_to_fun_map[item.address] = (
                    library_analyser.LibFunction(
                        name=item.name,
                        library_path=self.binary.path,
                        boundaries=(item.address,
                                    item.address + item.size)
                        )
                    )

    def __mov_local_funs_to(self, f_to, f_from):
        """Move the functions from .plt that lead to an IRELATIVE .got entry
        from `f_from` to `f_to`.

        These functions correspond to functions that are local to the currently
        analysed binary while other entries of the .got (with the type
        JUMP_SLOT) correspond to functions from other libraries, which should
        be treated differently. The purpose of this function is thus to
        separate them.

        If f_to is none, the IRELATIVE function are just removed from f_from.
        """

        for i, f in enumerate(f_from):
            # no name indicates it wasn't an JUMP_SLOT got entry
            if not f.name:
                if f_to is not None:
                    f_to.append(self.__get_local_function_called(
                        f.boundaries[0]))
                f_from.pop(i)

    def __wrapper_get_function_called(self, f_address, i, list_inst):

        called_plt_f = self.__lib_analyser.get_function_called(f_address)

        loaded_fun = []
        for f in called_plt_f:
            if not utils.f_name_from_path(f.library_path).startswith("libc"):
                continue
            if f.name == "dlopen":
                utils.log(f"dlopen instruction: {hex(list_inst[-1].address)} "
                          f"{list_inst[-1].mnemonic} {list_inst[-1].op_str}",
                          "backtrack.log")
                self.__backtrack_dlopen(i, list_inst)
            elif f.name == "dlmopen":
                utils.log(f"dlmopen instruction: {hex(list_inst[-1].address)} "
                          f"{list_inst[-1].mnemonic} {list_inst[-1].op_str}",
                          "backtrack.log")
                self.__backtrack_dlmopen(i, list_inst)
            elif f.name == "dlsym":
                utils.log(f"dlsym instruction: {hex(list_inst[-1].address)} "
                          f"{list_inst[-1].mnemonic} {list_inst[-1].op_str}",
                          "backtrack.log")
                loaded_fun.extend(self.__backtrack_dlsym(i, list_inst))

        return called_plt_f + loaded_fun

    def __process_lib_paths_by_dlopen(self, lib_paths):
        """
        Raises
        ------
        StaticAnalyserException
            If no valid paths to libraries were found
        """

        lib_paths_copy = copy(lib_paths)
        for p in lib_paths_copy:
            if not is_valid_binary_path(p):
                # dlopen (may) lead to a GNU ld script that points to the
                # actual libraries
                try:
                    lib_paths.extend(self.__lib_analyser
                                     .get_lib_from_GNU_ld_script(p))
                except FileNotFoundError:
                    sys.stderr.write(f"[ERROR] File not found at {p}")
                except UnicodeDecodeError:
                    pass
                finally:
                    lib_paths.remove(p)
        if lib_paths_copy and not lib_paths:
            raise StaticAnalyserException(
                    f"[ERROR] The library paths {lib_paths_copy} loaded "
                    f"with dlopen in {self.binary.path} does not lead to"
                    f" valid binaries or scripts")

    def __compute_assigned_value(self, inst):

        mnemonic = inst.mnemonic
        op_strings = inst.op_str.split(",")

        ret = -1
        if mnemonic not in ("mov", "xor", "lea"):
            return ret

        op_strings[0] = op_strings[0].strip()
        op_strings[1] = op_strings[1].strip()

        if mnemonic == "mov":
            if utils.is_number(op_strings[1]):
                ret = utils.str2int(op_strings[1])
            elif self.__is_reg(op_strings[1]):
                ret = self.__get_reg_key(op_strings[1])
            # Ça arrive parfois pour dlopen (par exemple avec make ou
            # ibus) mais ça pointe vers des fonctions donc je comprends
            # pas trop.
            # elif "rip" in inst.op_str:
            #     print(f"gougoug backtrack {op_strings}")
        elif mnemonic == "xor" and op_strings[0] == op_strings[1]:
            ret = 0
        elif mnemonic == "lea":
            mem_operand = op_strings[1].split()
            if (mem_operand[0][1:] == "rip"
                                     and utils.is_number(mem_operand[2][:-1])):
                if mem_operand[1] == "+":
                    ret = utils.compute_rip(inst) + utils.str2int(
                            mem_operand[2][:-1])
                elif mem_operand[1] == "-":
                    ret = utils.compute_rip(inst) - utils.str2int(
                            mem_operand[2][:-1])

        return ret

    def __is_reg(self, string):
        """Returns true if the given string is the name of a (x86_64 general
        purpose) register identifier.

        Parameters
        ----------
        string : str
            the string that may contain a register identifier

        Returns
        -------
        is_reg : bool
            True if the string is a register identifier
        """

        for reg_ids in self.__registers.values():
            if string in reg_ids:
                return True

        return False

    def __get_reg_key(self, reg_id):
        """Given a register identifier, returns the key to have access to this
        register in the `__registers` variable.

        Parameters
        ----------
        reg_id : str
            the string contains a register identifier

        Returns
        -------
        reg_key : str
            the key for this register

        Raises
        ------
        StaticAnalyserException
            If the given reg_id is not a register id
        """

        for reg_key, reg_ids in self.__registers.items():
            if reg_id in reg_ids:
                return reg_key

        raise StaticAnalyserException(f"{reg_id}, the given reg_id does not "
                                      f"correspond to a register id.")
