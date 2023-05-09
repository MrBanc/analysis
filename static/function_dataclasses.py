"""Dataclasses used to store information about functions"""

from typing import Set, List
from dataclasses import dataclass

@dataclass
class FunLibInfo:
    """Represent a library function. Store information related to the context
    of the function inside the library.

    Attributes
    ----------
    name : str
        name of the function
    library_path : str
        absolute path of the library in which the function is
    boundaries : list of two int
        the start address and the end address (start + size) of the function
        within the library binary
    """

    name: str
    library_path: str
    boundaries: List[int]

@dataclass
class FunGraphInfo:
    """Represent a library function. Store information related to the context
    of the function inside the call graph.

    Attributes
    ----------
    analyzed_to_depth : int
        the depth to which the function has been analyzed
    used_syscalls : set of str
        the registered syscalls that can be used by this function and any
        functions called by it, recursively up to a maximum depth of
        `analyzed_to_depth`
    called_functions: list of FunLibInfo
        the registered functions that are (directly) called by this function
    called_by: list of FunLibInfo
        the registered functions that call this function
    """

    analyzed_to_depth: int
    used_syscalls: Set[str]
    called_functions: List[FunLibInfo]
    called_by: List[FunLibInfo]
