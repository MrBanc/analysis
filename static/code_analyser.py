from capstone import *

import globals

from library_analyser import LibraryAnalyser
from custom_exception import StaticAnalyserException
from elf_analyser import is_valid_binary, TEXT_SECTION
from utils import *

class CodeAnalyser:
    """
    Class use to store information about and analyse the binary code.

    This class directly analyse what is inside the `.text` sectin of the ELF
    executable but it also uses `LibraryAnalyser` to (indirectly) analyse
    syscalls used by shared library calls.
    """

    def __init__(self, binary):
        if not is_valid_binary(binary):
            raise StaticAnalyserException("The given binary is not a CLASS64 ELF file.")

        self.__text_section = binary.get_section(TEXT_SECTION)
        if self.__text_section is None:
            raise StaticAnalyserException(".text section is not found.")

        try:
            self.__lib_analyser = LibraryAnalyser(binary)
        except StaticAnalyserException as e:
            raise e

    def get_used_syscalls(self, syscalls_set, inv_syscalls_map):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        # TODO: adapt the code around the fact that md.disasm may not return the
        # entirety of the requested instructions. (or find a parameter in Cs
        # that enables continuing the analysis in case of error)
        insns = md.disasm(bytearray(self.__text_section.content), self.__text_section.virtual_address)
        list_inst = list()
        for i, ins in enumerate(insns):
            b = ins.bytes
            list_inst.append(ins)

            if b[0] == 0x0f and b[1] == 0x05:
                # Direct syscall SYSCALL
                print_verbose("DIRECT SYSCALL (x86_64): 0x{:x} {} {}".format(ins.address, ins.mnemonic, ins.op_str))
                self.wrapper_backtrack_syscalls(i, list_inst, syscalls_set, inv_syscalls_map)
            elif b[0] == 0x0f and b[1] == 0x34:
                # Direct syscall SYSENTER
                print_verbose("SYSENTER: 0x{:x} {} {}".format(ins.address, ins.mnemonic, ins.op_str))
                self.wrapper_backtrack_syscalls(i, list_inst, syscalls_set, inv_syscalls_map)
            elif b[0] == 0xcd and b[1] == 0x80:
                # Direct syscall int 0x80
                print_verbose("DIRECT SYSCALL (x86): 0x{:x} {} {}".format(ins.address, ins.mnemonic, ins.op_str))
                self.wrapper_backtrack_syscalls(i, list_inst, syscalls_set, inv_syscalls_map)
            # TODO: be sure to detect all lib calls. This may not be enough. Do some research
            # TODO: add other types of jump (create a function that takes mnemonic and return bool)
            elif ins.mnemonic == "call" or ins.mnemonic == "jmp":
                # Function call
                if self.__lib_analyser.is_lib_call(ins.op_str):
                    called_function = self.__lib_analyser.get_function_called(ins.op_str)
                    self.__lib_analyser.get_used_syscalls(syscalls_set, called_function)
            # TODO: verify also with REX prefixes
            elif b[0] == 0xe8 or b[0] == 0xff or b[0] == 0x9a:
                pass
                # print_verbose("[DEBUG] a function call was not detected:")
                # print_verbose(f"[DEBUG] 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")

    def backtrack_syscalls(self, index, ins):
        for i in range(index-1, 0, -1):
            b = ins[i].bytes
            print_verbose("-> 0x{:x}:{} {}".format(ins[i].address, ins[i].mnemonic, ins[i].op_str), indent=1)
            # MOV in EAX
            if b[0] == 0xb8:
                return int(b[1])

            # Another syscall is called, break
            if b[0] == 0xcd and b[1] == 0x80:
                break
        return -1

    def wrapper_backtrack_syscalls(self, i, list_inst, syscalls_set, inv_syscalls_map):
        print_debug("syscall detected at instruction: " + str(list_inst[-1]))
        nb_syscall = self.backtrack_syscalls(i, list_inst)
        if nb_syscall != -1 and nb_syscall < len(inv_syscalls_map):
            name = inv_syscalls_map[nb_syscall]
            print_verbose("Found: {}: {}\n".format(name, nb_syscall))
            syscalls_set.add(name)
        else:
            print_verbose("Ignore {}".format(nb_syscall))
