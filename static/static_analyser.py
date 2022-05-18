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
APP          = "redis-server-static"


def print_verbose(msg, indent=0):
    
    if verbose:
        print(indent * "\t" + msg)

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

def disassemble(text_section, syscalls_set, inv_syscalls_map):
    
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
    
    print_verbose("Analysing the ELF file. This may take some times...")
    syscalls_set = set()
    for sect_it in [binary.dynamic_symbols, binary.static_symbols, binary.symbols]:
        detect_syscalls(sect_it, syscalls_set, syscalls_map)

    text_section = binary.get_section(TEXT_SECTION)
    if text_section is None:
        sys.write("[ERROR] Text section is not found.")
        sys.exit(1)

    inv_syscalls_map = {syscalls_map[k] : k for k in syscalls_map}
    disassemble(text_section, syscalls_set, inv_syscalls_map)

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