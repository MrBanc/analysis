from typing import Set, List
from dataclasses import dataclass

@dataclass
class FunLibInfo:
    name: str
    library_path: str
    boundaries: int

@dataclass
class FunGraphInfo:
    analyzed_to_depth: int
    used_syscalls: Set[str]
    called_functions: List[FunLibInfo]
