"""
Main file of the program.

Parses the input, calls the elf and code analyser and prints the results.
"""

import sys
import argparse

import utils
import syscalls
from code_analyser import CodeAnalyser
from elf_analyser import ELFAnalyser
from custom_exception import StaticAnalyserException


CSV = "data.csv"


def main():
    """Parse the arguments, starts the analysis and print the results"""

    try:
        parse_arguments()
        syscalls_set = launch_analysis()
    except StaticAnalyserException as e:
        sys.stderr.write(f"[ERROR] {e}\n")
        return 1

    display_results(syscalls_set)

    return 0

def parse_arguments():
    """Parse the arguments

    Raises
    ------
    StaticAnalyserException
        If no values could be read from the syscalls map file.
    """

    parser = argparse.ArgumentParser(
            description="The static binary analyser is a tool designed to "
            "detect system calls by analysing a binary of an application. This"
            " tool handles both statically and dynamically-linked (it handles "
            "the plt/got sections) binaries. The static analyser requires "
            "Capstone and Lief as third-parties libraries.")
    disp_log_group = parser.add_argument_group('display/logging options')
    functionalities_group = parser.add_argument_group(
            'functionalities (lead to overestimations when set to true)')
    parser.add_argument('--app', '-a', help='Path to application (required)',
                        required=True)
    parser.add_argument('--custom-syscalls-map', '-s',
                        help=f'Path to syscall to id map (default: '
                        f'{utils.sys_map})', required=False,
                        default=None) # Set later to better deal with warnings
    parser.add_argument('--max-backtrack-insns', '-B', type=int, nargs='?',
                        const=True, default=utils.max_backtrack_insns,
                        help=f'Maximum number of instructions to check before '
                        f'a syscall instruction to find its id (default: '
                        f'{utils.max_backtrack_insns})')

    disp_log_group.add_argument(
            '--verbose', '-v', type=utils.str2bool, nargs='?', const=True,
            default=utils.verbose,
            help=f'Verbose mode (default: {utils.verbose})')
    disp_log_group.add_argument(
            '--show-warnings', '-w', type=utils.str2bool, nargs='?',
            const=True, default=utils.show_warnings,
            help=f'Show all warnings (default: {utils.show_warnings})')
    disp_log_group.add_argument(
            '--display', '-d', type=utils.str2bool, nargs='?', const=True,
            default=utils.display_syscalls,
            help=f'Display syscalls (default: {utils.display_syscalls})')
    disp_log_group.add_argument(
            '--csv', '-c', type=utils.str2bool, nargs='?', const=True,
            default=utils.display_csv,
            help=f'Output csv (default: {utils.display_csv})')
    disp_log_group.add_argument(
            '--log', '-l', type=utils.str2bool, nargs='?', const=True,
            default=utils.logging, help=f'Log mode (default: {utils.logging})')
    disp_log_group.add_argument(
            '--log-to-stdout', '-L', type=utils.str2bool, nargs='?',
            const=True, default=not utils.use_log_file,
            help=f'Print logs to the standard output (default: '
            f'{not utils.use_log_file})')

    functionalities_group.add_argument(
            '--skip-data', '-k', type=utils.str2bool, nargs='?', const=True,
            default=utils.skip_data,
            help=f'Automatically skip data in code and try to find the next '
            f'instruction (may lead to errors) (default: {utils.skip_data})')
    functionalities_group.add_argument(
            '--all-imported-functions', '-i', type=utils.str2bool, nargs='?',
            const=True, default=utils.all_imported_functions,
            help=f'Analyse all the imported functions found in the main ELF '
            f'(even those not found in the code) (default: '
            f'{utils.all_imported_functions})')
    functionalities_group.add_argument(
            '--search-function-pointers', '-f', type=utils.str2bool, nargs='?',
            const=True, default=utils.search_function_pointers,
            help=f'Analyse all values put into register and consider them as '
            f'potential pointers to functions (default: '
            f'{utils.search_function_pointers})')
    functionalities_group.add_argument(
            '--search_raw_data', '-r', type=utils.str2bool, nargs='?',
            const=True, default=utils.search_raw_data,
            help=f'Consider the data inside the binary as valid values for '
            f'memory access to an address (ex: when confronted with `call '
            f'qword ptr [0x1234]`, the 64 bits value at address 0x1234 inside'
            f' the binary will be treated as a potential pointer to a '
            f'function) (default: {utils.search_raw_data})')
    args = parser.parse_args()

    utils.app = args.app
    utils.verbose = args.verbose
    utils.show_warnings = args.show_warnings
    utils.display_syscalls = args.display
    utils.display_csv = args.csv

    if args.custom_syscalls_map is None:
        utils.print_warning("[WARNING] default syscalls map used as none were "
                            "provided.")
        args.custom_syscalls_map = utils.sys_map
    else:
        # utils.sys_map isn't used afterwards so this is useless but is there
        # to avoid future confusion.
        utils.sys_map = args.custom_syscalls_map
    syscalls.initialise_syscalls_map(args.custom_syscalls_map)

    utils.use_log_file = not args.log_to_stdout
    utils.logging = args.log if args.log_to_stdout is False else True
    if utils.logging and utils.use_log_file:
        utils.clean_logs()

    utils.max_backtrack_insns = args.max_backtrack_insns
    utils.skip_data = args.skip_data
    utils.all_imported_functions = args.all_imported_functions
    utils.search_function_pointers = args.search_function_pointers
    utils.search_raw_data = args.search_raw_data

def launch_analysis():
    """Launch the analysis on the binary

    Raises
    ------
    StaticAnalyserException
        If any major errors occured during the analysis, preventing its
        continuation.
    """

    elf_analyser = ELFAnalyser(utils.app)

    utils.print_verbose("Analysing the ELF file. This may take some "
                        "times...")

    syscalls_set = set()
    elf_analyser.get_syscalls_from_symbols(syscalls_set)

    code_analyser = CodeAnalyser(elf_analyser)

    code_analyser.launch_analysis(syscalls_set)

    return syscalls_set

def display_results(syscalls_set):
    """Display the results of the analysis"""

    if utils.display_syscalls:
        for k,v in syscalls.syscalls_map.items():
            if v in syscalls_set:
                print(f"{v} : {k}")

    utils.print_verbose("Total number of syscalls: " + str(len(syscalls_set)))

    if utils.display_csv:
        print("# syscall, used")
        for k,v in syscalls.syscalls_map.items():
            value = "N"
            if v in syscalls_set:
                value = "Y"
            print(f"{v},{value}")

    return 0

if __name__== "__main__":
    main()
