# TODO
""" """

import argparse

DEBUG = True
log_dir_path = "../logs/"

# global variables
verbose = True
app = "redis-server-static"
use_log_file = True
logging = False
skip_data = False

def print_verbose(msg, indent=0):
    """Prints msg with the specified indentation into the standard output if
    verbose is True.

    Parameters
    ----------
    msg : str
        msg to print
    file_name : str
        name of the log file to add the message to
    indent: int
        number of tabs to add before the msg
    """
    if verbose:
        print(indent * "\t" + msg)

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
    # TODO: remove for final code
    if DEBUG:
        open(log_dir_path + "debug.log", "w", encoding="utf-8").close()

def is_hex(s):
    if not s or len(s) < 3:
        return False

    return s[:2] == "0x" and all(c.isdigit()
                                 or c.lower() in ('a', 'b', 'c', 'd', 'e', 'f')
                                 for c in s[2:])

def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    if v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    raise argparse.ArgumentTypeError('Boolean value expected.')

def print_debug(msg):
    if DEBUG:
        log(msg, "debug.log")
        # print("[DEBUG] " + msg)

def f_name_from_path(path):
    """Returns the file name from a full path (after the last slash)

    Parameters
    ----------
    path: str
        unix-like path of a file
    """

    return path.split("/")[-1]
