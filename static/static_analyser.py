"""
Main file of the program.

Parses the input, calls the elf and code analyser and prints the results.
"""

import sys
import argparse
import lief

import utils
from syscalls import *
from code_analyser import CodeAnalyser
from elf_analyser import get_syscalls_from_symbols, is_valid_binary
from custom_exception import StaticAnalyserException


CSV = "data.csv"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--app','-a', help='Path to application',required=True,
                        default=utils.app)
    parser.add_argument('--verbose', '-v', type=utils.str2bool, nargs='?',
                        const=True, help='Verbose mode', default=True)
    parser.add_argument('--display', '-d', type=utils.str2bool, nargs='?',
                        const=True, help='Display syscalls', default=True)
    parser.add_argument('--csv', '-c', type=utils.str2bool, nargs='?',
                        const=True, help='Output csv', default=True)
    parser.add_argument('--log', '-l', type=utils.str2bool, nargs='?',
                        const=True, help='Log mode', default=False)
    parser.add_argument('--log-to-stdout', '-L', type=utils.str2bool,
                        nargs='?', const=True, help='Log to output',
                        default=False)
    args = parser.parse_args()

    utils.verbose = args.verbose
    utils.app = args.app
    utils.use_log_file = not args.log_to_stdout
    utils.logging = args.log
    if utils.logging:
        utils.clean_logs()
    # import pdb; pdb.set_trace()

    try:
        binary = lief.parse(utils.app)
        if not is_valid_binary(binary):
            raise StaticAnalyserException("The given binary is not a CLASS64 "
                                          "ELF file.")


        utils.print_verbose("Analysing the ELF file. This may take some "
                            "times...")

        syscalls_set = set()
        get_syscalls_from_symbols(binary, syscalls_set)

        # TODO: use entry point instead of start of text section? (not needed?)
        # entry_addr = binary.entrypoint

        code_analyser = CodeAnalyser(utils.app)

        inv_syscalls_map = get_inverse_syscalls_map()
        code_analyser.get_used_syscalls_text_section(syscalls_set,
                                                     inv_syscalls_map)
    except StaticAnalyserException as e:
        sys.stderr.write(f"[ERROR] {e}\n")
        sys.exit(1)


    if args.display:
        for k,v in syscalls_map.items():
            if k in syscalls_set:
                print(f"{k} : {v}")

    utils.print_verbose("Total number of syscalls: " + str(len(syscalls_set)))

    if args.csv:
        print("# syscall, used")
        for k,v in syscalls_map.items():
            value = "N"
            if k in syscalls_set:
                value = "Y"
            print(f"{v},{value}")

if __name__== "__main__":
    main()
