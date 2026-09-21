"""Contains syscalls ID and their wrappers names and functions to use them."""

from custom_exception import StaticAnalyserException


def initialise_syscalls_map(sys_map_path):
    """Parses the syscalls map present in sys_map_path and initialises the
    syscalls_map with it.

    Parameter
    ---------
    sys_map_path : str
        path to the syscalls map (relative or absolute)


    Raises
    ------
    StaticAnalyserException
        If no values could be read from the given file.
    """

    parsed_map = {}
    try:
        with open(sys_map_path, "r", encoding="utf-8") as f:
            found_header = False
            for line_number, line in enumerate(f, 1):
                # Ignore comments and empty lines
                line = line.strip()
                if not line or line.startswith('#'):
                    continue  # Skip empty lines and comments

                if not found_header:
                    # Trying to find the first syscall (with ID 0)
                    columns = line.split()
                    if "0" in columns:
                        value_column = columns.index("0")
                    else:
                        continue

                    if len(columns) == 2:
                        key_column = 0 if value_column == 1 else 1
                    elif "read" in columns:
                        key_column = columns.index("read")
                    else:
                        continue

                    key = int(columns[value_column])
                    value = columns[key_column]
                    parsed_map[key] = value
                    found_header = True
                else:
                    # Process data lines
                    columns = line.split()
                    key = int(columns[value_column])
                    value = columns[key_column]
                    parsed_map[key] = value
    except FileNotFoundError as e:
        raise StaticAnalyserException("The syscalls map file couldn't be "
                                      "found.") from e
    except (OSError, UnicodeError) as e:
        raise StaticAnalyserException(
                f"The syscalls map file couldn't be read: {e}") from e
    except (ValueError, IndexError) as e:
        raise StaticAnalyserException(
                f"Provided syscalls map cannot be parsed at line "
                f"{line_number}: {e}") from e

    if not parsed_map:
        raise StaticAnalyserException("Provided syscalls map cannot be parsed."
                                      " Please provide a file with two columns"
                                      " with the syscalls and their IDs "
                                      "ordered by their IDs")

    # Replacing the content only after success avoids partial updates and keeps
    # the global table consistent.
    syscalls_map.clear()
    syscalls_map.update(parsed_map)

syscalls_map = {}

alias_syscalls_map = {
    "open64" : "open",
    "__fxstat64": "fstat",
    "fstat64" : "fstat",
    "pread64" : "pread64",
    "pwrite64" : "pwrite64",
    "stat64" : "stat",
    "mmap64" : "mmap",
    "getrlimit64" : "getrlimit",
    "openat64" : "openat",
    "fstatat64" : "newfstatat",
    "posix_fadvise64" : "fadvise64",
    "pwritev64" : "pwritev",
    "statfs64" : "statfs",
    "lstat64" : "lstat",
    "__lxstat64" : "lstat",
    "__GI___getrlimit" : "prlimit64",
    "lseek64" : "lseek",
    "truncate64" : "truncate",
    "ftruncate64" : "ftruncate",
    "setrlimit64" : "setrlimit",
    "sendfile64" : "sendfile",
}
