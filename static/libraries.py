import sys
import subprocess
import lief

from copy import copy
from os.path import exists
from capstone import *

import globals

from utils import *


used_libraries = None

LIB_PATHS = ['/lib64/']

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

    def __str__(self):
        return self._library + ": " + str(hex(self._address))

    # to print a table of objects
    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self._library == other.library and self._address == other.address


def disassemble_lib_function(f_location):
    pass

def find_used_libraries():
    libs = []
    try:
        ldd_output = subprocess.run(["ldd", globals.app], check=True, capture_output=True)
        for line in ldd_output.stdout.splitlines():
            parts = line.decode("utf-8").split()
            if "=>" in parts:
                libs.append(parts[parts.index("=>") + 1])
    except subprocess.CalledProcessError as e:
        print_verbose('[ERROR] ldd command returned with an error: ' + e.stderr.decode("utf-8") + 'Trying to find the libraries path manually...')
        libs = find_used_libraries_manually()
    return libs
    # sys.stderr.write("[DEBUG] Using a stripped version of libc.so.6 without taking into account the actual library used by the binary.\n")
    # return ['/home/ben/codes/misc/my_stripped_libc.so.6']
 
def find_used_libraries_manually():
    binary = lief.parse(globals.app)
    lib_names = binary.libraries
    libs = [] # full path of the lib
    
    for path in LIB_PATHS:
        lib_names_copy = copy(lib_names)
        for name in lib_names_copy:
            if exists(path + name):
                libs.append(path + name)
                lib_names.remove(name)

    # TODO: either add more paths in LIB_PATHS or use subprocess to run `locate` (and maybe let the user choose?)
    if len(lib_names) > 0:
        sys.stderr.write(f"[ERROR] The following libraries couldn't be found: {lib_names}\nDo you want to continue without analysing these linked libraries? (Y/n) ")
        ans = input()
        while ans.lower() != "y":
            if ans.lower() == "n":
                sys.exit(1)
            else:
                ans = input("Please answer with y or n\n")
    return libs

def lib_fun_location(f_name):
    global used_libraries
    if used_libraries == None:
        used_libraries = find_used_libraries()
    locations = []
    for lib in used_libraries:
        lib_binary = lief.parse(lib)
        for item in lib_binary.dynamic_symbols:
            if item.name == f_name:
                loc = LibFunLocation(lib, item.value)
                # some symbols are present multiple times with the same values
                if loc not in locations:
                    locations.append(loc)
    
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
                    if len(f_location) > 0:
                        print(f"Function {rel.symbol.name} is present in {f_location[0].library} at address {hex(f_location[0].address)}")
                    disassemble_lib_function(f_location)
        else:
            pass
    else:
        sys.stderr.write(f"[WARNING] Instruction not implemented yet: call {operand}\n")
    # print_verbose("DIRECT SYSCALL (x86): 0x{:x} {} {}".format(ins.address, ins.mnemonic, ins.op_str))
    # wrapper_backtrack_syscalls(i, list_inst, syscalls_set, inv_syscalls_map)

