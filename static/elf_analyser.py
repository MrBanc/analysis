"""
Utilities to store information about and analyse the ELF 64-bit executable.
"""

import lief

from custom_exception import StaticAnalyserException
from syscalls import syscalls_map, alias_syscalls_map


TEXT_SECTION     = ".text"
PLT_SECTION      = ".plt"
PLT_SEC_SECTION  = ".plt.sec"


def is_valid_binary(binary):
    """Verifies that the given binary is an ELF binary for the `x86_64`
    architecture

    Parameters
    ----------
    binary : lief binary
        the binary to check

    Returns
    -------
    is_valid_binary : bool
        True if the tests pass
    """

    return (binary is not None
            and binary.format == lief.EXE_FORMATS.ELF
            and binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64
            and binary.header.machine_type == lief.ELF.ARCH.x86_64)

def is_valid_binary_path(binary_path):
    """Verifies that the given binary is an ELF binary for the `x86_64`
    architecture

    Parameters
    ----------
    binary_path : str
        the path of the binary to check

    Returns
    -------
    is_valid_binary : bool
        True if the tests pass
    """

    lief.logging.disable()
    binary = lief.parse(binary_path)
    lief.logging.enable()

    return is_valid_binary(binary)

def get_syscalls_from_symbols(binary, syscalls_set):
    """Try to detect syscalls used in the binary thanks to its symbolic
    information (for example checking the presence of wrappers).

    Parameters
    ----------
    binary : lief binary
        the binary to analyse
    syscalls_set : set of str
        set of syscalls used by the program analysed that will be updated
    """

    for sect_it in [binary.dynamic_symbols, binary.static_symbols,
                    binary.symbols]:
        __detect_syscalls_in_sym_table(sect_it, syscalls_set)

def get_section_boundaries(section):
    """Returns [section_start_address, section_end_address-1]

    Parameters
    ----------
    section : lief section
        the section to get boundaries from

    Returns
    -------
    boundaries : list of two int
        the section boundaries
    """

    return [section.virtual_address, section.virtual_address + section.size]

def get_text_section(binary):
    """Returns the .text section (as given by the lief library)

    Parameters
    ----------
    binary : ELFBinary
        the binary to get the .text section from

    Returns
    -------
    text_section : lief ELF section
        the text section as given by lief

    Raises
    ------
    StaticAnalyserException
        If the .text section is not found.
    """

    if binary.text_sect is None:
        binary.text_sect = (binary.lief_binary
                                   .get_section(TEXT_SECTION))
    if binary.text_sect is None:
        raise StaticAnalyserException(".text section is not found.")
    return binary.text_sect

def get_rodata_section(binary):
    """Returns the .rodata section (as given by the lief library)

    Parameters
    ----------
    binary : ELFBinary
        the binary to get the .rodata section from

    Returns
    -------
    rodata_section : lief ELF section
        the text section as given by lief

    Raises
    ------
    StaticAnalyserException
        If the .rodata section is not found.
    """

    if binary.rodata_sect is None:
        binary.rodata_sect = (binary.lief_binary
                                     .get_section(TEXT_SECTION))
    if binary.rodata_sect is None:
        raise StaticAnalyserException(".rodata section is not found.")
    return binary.rodata_sect

def get_section_from_address(binary, address):
    """Returns the section (in lief format) that contains the data or
    instruction located at the given address.

    Parameters
    ----------
    binary : ELFBinary
        the binary to get the .rodata section from
    address : int
        address inside the wanted section

    Returns
    -------
    section : lief section
        the section containing the given address

    Raises
    ------
    StaticAnalyserException
        If no section was found for the given address or if the address
        was invalid
    """

    # There is no need to be worry about a section not being found here as
    # the code is just trying to guess which section it is for optimization
    # purposes but with no guarantee the guessed section really exists.
    try:
        if address in get_section_boundaries(get_text_section(binary)):
            return binary.text_sect
    except StaticAnalyserException:
        pass
    try:
        if address in get_section_boundaries(get_rodata_section(binary)):
            return binary.rodata_sect
    except StaticAnalyserException:
        pass

    # If the code didn't guess the correct section, here is a general
    # approach (less optimal but should always work)
    try:
        section = (binary.lief_binary
                   .section_from_virtual_address(address))
    except TypeError as e:
        raise StaticAnalyserException(f"[WARNING] Invalid address for "
                                      f"section: {address}") from e

    if section is None:
        raise StaticAnalyserException(f"[WARNING] No section could be "
                                      f"found for address {address}")

    return section

def get_string_at_address(binary, address):
    """Return the string located at a particular address in a binary.

    Parameters
    ----------
    binary : ELFBinary
        the binary to look into
    address : int
        address of the searched string

    Returns
    -------
    string : str
        the string that has been found

    Raises
    ------
    StaticAnalyserException
        If no section was found for the given address or if the address
        was invalid
    """

    target_section = get_section_from_address(binary, address)

    section_start_offset = address - target_section.virtual_address
    string = bytearray(target_section.content)[section_start_offset:]
    section_end_offset = string.index(b"\x00") # string terminator
    return string[:section_end_offset].decode("utf8")

def __detect_syscalls_in_sym_table(sect_it, syscalls_set):

    for s in sect_it:
        name = s.name
        name_value = alias_syscalls_map.get(name)
        if name_value is not None:
            name = alias_syscalls_map[name]

        if name in syscalls_map:
            syscalls_set.add(name)
