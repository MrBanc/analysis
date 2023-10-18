"""Contains analysis global parameters and helper functions"""

import argparse


DEBUG = True
log_dir_path = "../logs/"

# global variables with their default values
app = "redis-server-static"
sys_map = "syscalls_map"
verbose = True
show_warnings = True
display_syscalls = True
display_csv = False
logging = False
use_log_file = True
max_backtrack_insns = 20
skip_data = False
all_imported_functions = True
search_function_pointers = True
search_raw_data = True

cur_depth = -1


def print_verbose(msg, indent=0):
    """Prints msg with the specified indentation into the standard output if
    verbose is True.

    Parameters
    ----------
    msg : str
        msg to print
    indent: int
        number of tabs to add before the msg
    """
    if verbose:
        print(indent * "\t" + msg)

def print_warning(warning, indent=0):
    """Prints the warning with the specified indentation into the standard
    output if show_warning is True.

    Parameters
    ----------
    warning : str
        warning to print
    indent: int
        number of tabs to add before the msg
    """
    if show_warnings:
        print(indent * "\t" + warning)

def print_debug(msg):
    """Used for debugging purposes only. Print debug messages"""

    if DEBUG:
        log(msg, "debug.log")

def log(msg, file_name, indent=0):
    """Logs msg with the specified indentation into the log file, or to the
    standard output if `use_log_file` is set to False.

    The msg is added at the end of the file.

    Parameters
    ----------
    msg : str
        msg to print
    file_name : str
        name of the log file to add the message to
    indent: int
        number of tabs to add before the msg
    """

    if not logging:
        return

    if use_log_file:
        with open(log_dir_path + file_name, "a", encoding="utf-8") as f:
            f.write(indent * " " + msg + "\n")
    else:
        print(indent * "\t" + msg)

def clean_logs():
    """Empties the content of the log files."""

    with open(log_dir_path + "backtrack.log", "w", encoding="utf-8") as f:
        f.truncate()
    with open(log_dir_path + "lib_functions.log", "w", encoding="utf-8") as f:
        f.truncate()
    if DEBUG:
        with open(log_dir_path + "debug.log", "w", encoding="utf-8") as f:
            f.truncate()

def is_hex(s):
    """Returns True if the given string represents an hexadecimal number.

    Parameters
    ----------
    s : str
        string to check

    Returns
    -------
    is_hex : bool
        True if `s` is an hexadecimal number
    """

    if not s or len(s) < 3:
        return False

    return s[:2] == "0x" and all(c.isdigit()
                                 or c.lower() in ('a', 'b', 'c', 'd', 'e', 'f')
                                 for c in s[2:])

def is_number(s):
    """Returns True if the given string represents an hexadecimal or decimal
    number.

    Parameters
    ----------
    s : str
        string to check

    Returns
    -------
    is_number : bool
        True if `s` is an hexadecimal or decimal number
    """

    return is_hex(s) or s.isnumeric()

def str2int(s):
    """Returns the number given in the string, supposing it is an hexadecimal
    or decimal number (the caller need to check before, for example using
    is_number(s)).

    Parameters
    ----------
    s : str
        string to convert

    Returns
    -------
    number : int
        The number in the string
    """

    if is_hex(s):
        number = int(s, 16)
    elif s.isdecimal():
        number = int(s)
    else:
        number = None

    return number

def str2bool(v):
    """Returns the boolean value represented in the parameter given.

    Parameters
    ----------
    v : bool or str
        value representing a boolean value

    Raises
    ------
    arg_error : ArgumentTypeError
        If the given value does not correspond to a boolean

    Returns
    -------
    boolean : bool
        the boolean value that `v` represents
    """

    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    if v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    raise argparse.ArgumentTypeError('Boolean value expected.')

def f_name_from_path(path):
    """Returns the file name from a full path (after the last slash)

    Parameters
    ----------
    path: str
        unix-like path of a file
    """

    return path.split("/")[-1]

def compute_rip(cur_inst):
    """Compute the value of RIP from the current instruction."""

    return cur_inst.address + cur_inst.size

def compute_operation(operation_str, operand1, operand2):
    """Returns the result of the operation inside the string, if supported.

    Currently only support addition and substractions of 2 numbers (but it
    should be enough in this context).

    Parameters
    ----------
    operation_str: str
        Operation to perform (can be "+", "-" etc)
    operandX: int
        The Xth operand of the operation
    """

    if operation_str == "+":
        return operand1 + operand2
    if operation_str == "-":
        return operand1 - operand2

    return None
