"""
Main file of the program.

Parses the input, calls the elf and code analyser and prints the results.
"""

import sys
import argparse
import lief

import utils
import syscalls
from code_analyser import CodeAnalyser
from elf_analyser import get_syscalls_from_symbols, is_valid_binary
from custom_exception import StaticAnalyserException


CSV = "data.csv"


def main():
    """Parse the arguments, starts the analysis and print the results"""

    parser = argparse.ArgumentParser()
    parser.add_argument('--app','-a', help='Path to application',required=True)
    parser.add_argument('--verbose', '-v', type=utils.str2bool, nargs='?',
                        const=True, help='Verbose mode', default=True)
    parser.add_argument('--show-warnings', '-w', type=utils.str2bool,
                        nargs='?', const=True, help='Show all warnings',
                        default=True)
    parser.add_argument('--display', '-d', type=utils.str2bool, nargs='?',
                        const=True, help='Display syscalls', default=True)
    parser.add_argument('--csv', '-c', type=utils.str2bool, nargs='?',
                        const=True, help='Output csv', default=True)
    parser.add_argument('--custom-syscalls-map', '-s',
                        help='Path to syscall to id map', required=False,
                        default=utils.sys_map)
    parser.add_argument('--log', '-l', type=utils.str2bool, nargs='?',
                        const=True, help='Log mode', default=False)
    parser.add_argument('--log-to-stdout', '-L', type=utils.str2bool,
                        nargs='?', const=True, help='Print logs to the '
                        'standard output', default=False)
    parser.add_argument('--max-backtrack-insns', '-B', type=int, nargs='?',
                        const=True, help='Maximum number of instructions to '
                        'check before a syscall instruction to find its id',
                        default=20)
    parser.add_argument('--skip-data', '-k', type=utils.str2bool, nargs='?',
                        const=True, help='Automatically skip data in code and '
                        'try to find the next instruction (may lead to '
                        'errors)', default=False)
    parser.add_argument('--all-imported-functions', '-i', type=utils.str2bool,
                        nargs='?', const=True, help='Analyse all the imported '
                        'functions found in the main ELF (even those not found'
                        ' in the code)', default=True)
    args = parser.parse_args()

    utils.app = args.app
    utils.verbose = args.verbose
    utils.show_warnings = args.show_warnings
    # utils.sys_map isn't used afterwards so the next instruction is useless
    # but is there to avoid future confusion.
    utils.sys_map = args.custom_syscalls_map
    try:
        syscalls.initialise_syscalls_map(args.custom_syscalls_map)
    except StaticAnalyserException as e:
        sys.stderr.write(f"{e}\nExiting...\n")
        return -1
    utils.use_log_file = not args.log_to_stdout
    utils.logging = args.log if args.log_to_stdout is False else True
    if utils.logging and utils.use_log_file:
        utils.clean_logs()
    utils.skip_data = args.skip_data
    utils.max_backtrack_insns = args.max_backtrack_insns
    utils.all_imported_functions = args.all_imported_functions

    try:
        binary = lief.parse(utils.app)
        if not is_valid_binary(binary):
            raise StaticAnalyserException("The given binary is not a CLASS64 "
                                          "ELF file.")

        utils.print_verbose("Analysing the ELF file. This may take some "
                            "times...")

        syscalls_set = set()
        get_syscalls_from_symbols(binary, syscalls_set)

        code_analyser = CodeAnalyser(utils.app)

        code_analyser.get_used_syscalls_text_section(syscalls_set)
    except StaticAnalyserException as e:
        sys.stderr.write(f"[ERROR] {e}\n")
        sys.exit(1)

    if args.display:
        for k,v in syscalls.syscalls_map.items():
            if v in syscalls_set:
                print(f"{v} : {k}")

    utils.print_verbose("Total number of syscalls: " + str(len(syscalls_set)))

    if args.csv:
        print("# syscall, used")
        for k,v in syscalls.syscalls_map.items():
            value = "N"
            if v in syscalls_set:
                value = "Y"
            print(f"{v},{value}")

    return 0

if __name__== "__main__":
    main()
