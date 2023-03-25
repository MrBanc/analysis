import sys
import subprocess
import lief

from capstone import *

import globals

from utils import *


class LibFunLocation:
    def __init__(self, library, address):
        self._library = library
        self._address = address

    @property
    def library(self):
        return self._library

    @property
    def address(self):
        return self._address


def disassemble_lib_function(f_location):
    pass

def find_used_library():
    libs = []
    ldd_output = subprocess.check_output(["ldd", globals.app])
    for line in ldd_output.splitlines():
        parts = line.decode("utf-8").split()
        if "=>" in parts:
            libs.append(parts[parts.index("=>") + 1])
    
    # return libs
    sys.stderr.write("[DEBUG] Using a stripped version of libc.so.6 without taking into account the actual library used by the binary.\n")
    return ['/home/ben/codes/misc/my_stripped_libc.so.6']

def lib_fun_location(f_name):
    locations = []
    for lib in find_used_library():
        lib_binary = lief.parse(lib)
        for item in lib_binary.dynamic_symbols:
            if item.name == f_name:
                locations.append(LibFunLocation(lib, item.value))
    
    if locations == []:
        sys.stderr.write(f"[WARNING] No library function was found for {f_name}. Continuing...\n")
    elif len(locations) > 1:
        sys.stderr.write(f"[WARNING] Multiple possible library functions were found for {f_name}: {locations}.\n All of them will be considered.\n")

    return locations

def detect_lib_syscalls(operand, plt_section, got_rel):
    if is_hex(operand):
        operand = int(operand, 16)
        plt_boundaries = [plt_section.virtual_address, plt_section.virtual_address + plt_section.size]
        if operand >= plt_boundaries[0] and operand < plt_boundaries[1]:
            # print(f"call to a lib: {operand}")
            plt_offset = operand - plt_section.virtual_address

            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True

            instr_1 = instr_2 = None
            for instr in md.disasm(bytearray(plt_section.content)[plt_offset:], operand):
                if instr_1 == None:
                    instr_1 = instr
                elif instr_2 == None:
                    instr_2 = instr
                else:
                    break

            got_rel_addr = int(instr_1.op_str.split()[-1][:-1], 16) + instr_2.address

            for rel in got_rel:
                if got_rel_addr == rel.address:
                    f_location = lib_fun_location(rel.symbol.name)
                    print(f"Function {rel.symbol.name} is present in {f_location[0].library} at address {hex(f_location[0].address)}")
                    disassemble_lib_function(f_location)
        else:
            pass
    else:
        sys.stderr.write(f"[WARNING] Instruction not implemented yet: call {operand}\n")
    # print_verbose("DIRECT SYSCALL (x86): 0x{:x} {} {}".format(ins.address, ins.mnemonic, ins.op_str))
    # wrapper_backtrack_syscalls(i, list_inst, syscalls_set, inv_syscalls_map)

