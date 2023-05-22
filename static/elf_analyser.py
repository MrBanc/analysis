"""
Utilities to store information about and analyse the ELF 64-bit executable.
"""

import lief

from syscalls import *


TEXT_SECTION     = ".text"
PLT_SECTION      = ".plt"
PLT_SEC_SECTION  = ".plt.sec"


def is_valid_binary(binary):
    return (binary is not None
            and binary.format == lief.EXE_FORMATS.ELF
            and binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64
            and binary.header.machine_type == lief.ELF.ARCH.x86_64)

def get_syscalls_from_symbols(binary, syscalls_set):
    for sect_it in [binary.dynamic_symbols, binary.static_symbols,
                    binary.symbols]:
        detect_syscalls_in_sym_table(sect_it, syscalls_set)
