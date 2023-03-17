import os
import re
import csv
import lief
import sys
import json
import argparse

from syscalls import *
from capstone import *

verbose = False

CSV          = "data.csv"
TEXT_SECTION = ".text"
PLT_SECTION  = ".plt"
APP          = "redis-server-static"


def print_verbose(msg, indent=0):
    
    if verbose:
        print(indent * "\t" + msg)

def is_hex(s):
    if not s or len(s) < 3:
        return False

    return s[:2] == "0x" and all(c.isdigit() or c.lower() in ('a', 'b', 'c', 'd', 'e', 'f') for c in s[2:])

def str2bool(v):

    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def process_alias(name):
    
    if name.startswith("__"):
        name = re.sub('^_*', '', name)
    if "libc_" in name:
        name = name.replace("libc_", "")
    return name

def detect_clib_syscalls(operand, plt_section, got_rel):
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
                    print(f"call to lib function {rel.symbol.name}")
        else:
            pass
            # print(f"call to regular function: {operand}")
    # print_verbose("DIRECT SYSCALL (x86): 0x{:x} {} {}".format(ins.address, ins.mnemonic, ins.op_str))
    # wrapper_backtrack_syscalls(i, list_inst, syscalls_set, inv_syscalls_map)

def backtrack_syscalls(index, ins):

    for i in range(index-1, 0, -1):
        
        b = ins[i].bytes
        print_verbose("-> 0x{:x}:{} {}".format(ins[i].address, ins[i].mnemonic, ins[i].op_str), indent=1)
        # MOV in EAX
        if b[0] == 0xb8:
            return int(b[1])

        # Another syscall is called, break
        if b[0] == 0xcd and b[1] == 0x80:
            return -1

def wrapper_backtrack_syscalls(i, list_inst, syscalls_set, inv_syscalls_map):
    nb_syscall = backtrack_syscalls(i, list_inst)
    if nb_syscall != -1 and nb_syscall < len(inv_syscalls_map):
        name = inv_syscalls_map[nb_syscall]
        print_verbose("Found: {}: {}\n".format(name, nb_syscall))
        syscalls_set.add(name)
    else:
        print_verbose("Ignore {}".format(nb_syscall))

def disassemble(text_section, plt_section, got_rel, syscalls_set, inv_syscalls_map):
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    insns = md.disasm(bytearray(text_section.content), text_section.virtual_address)
    list_inst = list()
    for i, ins in enumerate(insns):
        
        b = ins.bytes
        list_inst.append(ins)

        if b[0] == 0x0f and b[1] == 0x05:
            # Direct syscall SYSCALL
            print_verbose("DIRECT SYSCALL (x86_64): 0x{:x} {} {}".format(ins.address, ins.mnemonic, ins.op_str))
            wrapper_backtrack_syscalls(i, list_inst, syscalls_set, inv_syscalls_map)
        elif b[0] == 0x0f and b[1] == 0x34:
            # Direct syscall SYSENTER
            print_verbose("SYSENTER: 0x{:x} {} {}".format(ins.address, ins.mnemonic, ins.op_str))
            wrapper_backtrack_syscalls(i, list_inst, syscalls_set, inv_syscalls_map)
        elif b[0] == 0xcd and b[1] == 0x80:
            # Direct syscall int 0x80
            print_verbose("DIRECT SYSCALL (x86): 0x{:x} {} {}".format(ins.address, ins.mnemonic, ins.op_str))
            wrapper_backtrack_syscalls(i, list_inst, syscalls_set, inv_syscalls_map)
        elif ins.mnemonic == "call":
            # Function call
            # print(f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")
            detect_clib_syscalls(ins.op_str, plt_section, got_rel)
        # TODO: verify also with REX prefixes
        elif b[0] == 0xe8 or b[0] == 0xff or b[0] == 0x9a:
            print_verbose("[DEBUG] a function call was not detected:")
            print_verbose(f"[DEBUG] 0x{ins.address:x}: {ins.mnemonic} {ins.op_str}")

def detect_syscalls(sect_it, syscalls_set, syscalls_map):
    for s in sect_it:
        name = s.name
        if name in alias_syscalls_map:
            name = alias_syscalls_map[name]
        
        if name in syscalls_map:
            syscalls_set.add(name)

def main():
    global verbose

    parser = argparse.ArgumentParser()
    parser.add_argument('--app','-a', help='Path to application',required=True, default=APP)
    parser.add_argument('--verbose', '-v', type=str2bool, nargs='?', const=True, help='Verbose mode', default=True)
    parser.add_argument('--display', '-d', type=str2bool, nargs='?', const=True, help='Display syscalls', default=True)
    parser.add_argument('--csv', '-c', type=str2bool, nargs='?', const=True, help='Output csv', default=True)
    args = parser.parse_args()

    verbose = args.verbose
    binary = lief.parse(args.app)

    # TODO: verify it's an ELF64 file
    
    print_verbose("Analysing the ELF file. This may take some times...")
    syscalls_set = set()
    for sect_it in [binary.dynamic_symbols, binary.static_symbols, binary.symbols]:
        detect_syscalls(sect_it, syscalls_set, syscalls_map)

    # TODO: use entry point instead of start of text section? (not needed?)
    # entry_addr = binary.entrypoint
    text_section = binary.get_section(TEXT_SECTION)
    plt_section = binary.get_section(PLT_SECTION)
    if text_section is None or plt_section is None:
        sys.stderr.write("[ERROR] Text and/or plt section are not found.\n")
        sys.exit(1)

    got_rel = binary.pltgot_relocations

    inv_syscalls_map = {syscalls_map[k] : k for k in syscalls_map}
    disassemble(text_section, plt_section, got_rel, syscalls_set, inv_syscalls_map)

    if args.display:
        for k,v in syscalls_map.items():
            if k in syscalls_set:
                print_verbose("{} : {}".format(k,v))

    print_verbose("Total number of syscalls: " + str(len(syscalls_set)))

    if args.csv:
        print("# syscall, used")
        for k,v in syscalls_map.items():
            value = "N"
            if k in syscalls_set:
                value = "Y"
            print("{},{}".format(v,value))

if __name__== "__main__":
    main()  
