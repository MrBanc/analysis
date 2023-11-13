"""
Contains the ELFBinary dataclass and the ELFAnalyser class.

Utilities to store information about and analyse the ELF 64-bit executable.
"""

from dataclasses import dataclass

import lief

from custom_exception import StaticAnalyserException
import library_analyser
import syscalls
import utils


TEXT_SECTION     = ".text"
PLT_SECTION      = ".plt"
PLT_SEC_SECTION  = ".plt.sec"


@dataclass
class ELFBinary:
    """Represents an ELF binary.

    Attributes
    ----------
    path : str
        the path of the binary in the file system
    lief_binary : lief binary
        the lief representation of the binary
    rodata_sect : lief section
        the lief representation of the .rodata section
    text_sect : lief section
        the lief representation of the .text section
    has_dyn_libraries : bool
        false if the binary uses no dynamic libraries or if the library
        analyser associated to the binary couldn't be created
    """

    path: str
    lief_binary: lief._lief.ELF.Binary
    rodata_sect: lief._lief.ELF.Section
    text_sect: lief._lief.ELF.Section
    has_dyn_libraries: bool


class ELFAnalyser:
    """ELFAnalyser(binary_path) -> ELFAnalyser

    Class used to store information about and analyse informations specific to
    the elf binary.

    Public Methods
    --------------
    // Verifications //
    is_valid_binary_path(self, binary_path)
        Verifies that the given binary is an ELF binary for the `x86_64`
        architecture.

    // Syscalls Related //
    get_syscalls_from_symbols(self, syscalls_set)
        Try to detect syscalls used in the binary thanks to its symbolic
        information (for example checking the presence of wrappers).

    // Sections Related //
    get_text_section(self)
        Returns the .text section (as given by the lief library)
    get_rodata_section(self)
        Returns the .rodata section (as given by the lief library)
    get_section_from_address(self, address)
        Returns the section (in lief format) that contains the data or
        instruction located at the given address.

    // Searching in Memory //
    get_string_at_address(self, address)
        Return the string located at a particular address in a binary.
    resolve_value_at_address(self, address, reference_byte_size)
        Tries to return the value that would be stored on the given address.

    // Functions Related //
    get_local_function_called(self, f_address, show_warnings=True)
        Returns the function that would be called by jumping to the address
        given.
    find_next_function_addr(self, from_addr)
        Returns the address of closest function found after the given address
        by looking at the symbolic information of the ELF.
    """

    def __init__(self, binary_path):

        lief_binary = lief.parse(binary_path)

        self.binary = ELFBinary(path=binary_path,
                           lief_binary=lief_binary,
                           rodata_sect=None,
                           text_sect=None,
                           has_dyn_libraries=False)

        if not self.__is_valid_binary():
            raise StaticAnalyserException("The given binary is not a CLASS64 "
                                          "ELF file.")

        # may not be used
        self.__address_to_fun_map = None
        self.__f_name_to_addr_map = None

    def is_valid_binary_path(self, binary_path):
        """Verifies that the given binary is an ELF binary for the `x86_64`
        architecture.

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
        lb = lief.parse(binary_path)
        lief.logging.enable()

        return self.__is_valid_binary(lb)

    def __is_valid_binary(self, lb=None):
        """Verifies that the given binary is an ELF binary for the `x86_64`
        architecture

        Parameters
        ----------
        lb : lief binary
            the binary to check

        Returns
        -------
        is_valid_binary : bool
            True if the tests pass
        """

        if lb is None:
            lb = self.binary.lief_binary

        return (lb is not None
                and lb.format == lief.EXE_FORMATS.ELF
                and lb.header.identity_class == lief.ELF.ELF_CLASS.CLASS64
                and lb.header.machine_type == lief.ELF.ARCH.x86_64)

    def get_syscalls_from_symbols(self, syscalls_set):
        """Try to detect syscalls used in the binary thanks to its symbolic
        information (for example checking the presence of wrappers).

        Parameters
        ----------
        syscalls_set : set of str
            set of syscalls used by the program analysed that will be updated
        """

        lb = self.binary.lief_binary

        for sect_it in [lb.dynamic_symbols, lb.static_symbols,
                        lb.symbols]:
            self.__detect_syscalls_in_sym_table(sect_it, syscalls_set)

    def __detect_syscalls_in_sym_table(self, sect_it, syscalls_set):

        for s in sect_it:
            name = s.name
            name_value = syscalls.alias_syscalls_map.get(name)
            if name_value is not None:
                name = syscalls.alias_syscalls_map[name]

            if name in syscalls.syscalls_map.values():
                syscalls_set.add(name)

    def get_text_section(self):
        """Returns the .text section (as given by the lief library)

        Returns
        -------
        text_section : lief ELF section
            the text section as given by lief

        Raises
        ------
        StaticAnalyserException
            If the .text section is not found.
        """

        if self.binary.text_sect is None:
            self.binary.text_sect = self.binary.lief_binary.get_section(
                    TEXT_SECTION)
        if self.binary.text_sect is None:
            raise StaticAnalyserException(".text section is not found.")
        return self.binary.text_sect

    def get_rodata_section(self):
        """Returns the .rodata section (as given by the lief library)

        Returns
        -------
        rodata_section : lief ELF section
            the text section as given by lief

        Raises
        ------
        StaticAnalyserException
            If the .rodata section is not found.
        """

        if self.binary.rodata_sect is None:
            self.binary.rodata_sect = (self.binary.lief_binary
                                       .get_section(TEXT_SECTION))
        if self.binary.rodata_sect is None:
            raise StaticAnalyserException(".rodata section is not found.")
        return self.binary.rodata_sect

    def get_section_from_address(self, address):
        """Returns the section (in lief format) that contains the data or
        instruction located at the given address.

        Parameters
        ----------
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
            if address in self.__get_section_boundaries(
                    self.get_text_section()):
                return self.binary.text_sect
        except StaticAnalyserException:
            pass
        try:
            if address in self.__get_section_boundaries(
                    self.get_rodata_section()):
                return self.binary.rodata_sect
        except StaticAnalyserException:
            pass

        # If the code didn't guess the correct section, here is a general
        # approach (less optimal but should always work)
        try:
            section = (self.binary.lief_binary
                       .section_from_virtual_address(address))
        except TypeError as e:
            raise StaticAnalyserException(f"[WARNING] Invalid address for "
                                          f"section: {address}") from e

        if section is None:
            raise StaticAnalyserException(f"[WARNING] No section could be "
                                          f"found for address {address}")

        return section

    def __get_section_boundaries(self, section):
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

        return [section.virtual_address,
                section.virtual_address + section.size]

    def get_string_at_address(self, address):
        """Return the string located at a particular address in a binary.

        Parameters
        ----------
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

        target_section = self.get_section_from_address(address)

        section_start_offset = address - target_section.virtual_address
        string = bytearray(target_section.content)[section_start_offset:]
        section_end_offset = string.index(b"\x00") # string terminator
        return string[:section_end_offset].decode("utf8")

    def resolve_value_at_address(self, address, reference_byte_size):
        """Tries to return the value that would be stored on the given address.

        First, as the objective is mainly to find function addresses, the
        relocation information is used. If it does not succeed, the raw value
        stored at this address in the binary may be returned, whether this
        functionality has been activated or not.

        Note that searching for the raw value is probably a bad idea in most
        cases and will probably never find function addresses in particular. It
        is therefore disabled by default.

        Parameters
        ----------
        address : int
            address to look at
        reference_byte_size : int
            size in bytes of the value that is referenced (1 for word, 2 for
            dword etc)

        Returns
        -------
        value : int
            the value found that would be stored on the given address, or None
            if no values were found

        Raises
        ------
        StaticAnalyserException
            If no section was found for the given address or if the address
            was invalid
        """

        value = None

        if address < 0:
            return value

        # try to resolve the value given the relocation information of the ELF
        rel = self.binary.lief_binary.get_relocation(address)
        if rel and rel.has_symbol and rel.symbol.name != "":
            value = self.__get_local_function_address(
                    rel.symbol.name, False)
        if rel and value is None and rel.addend != 0:
            value = rel.addend

        # If nothing could be found with the previous method, simply look at
        # the content of the binary at this address.
        # Note that most of the time the given value will not be the one
        # expected by the code (because the code modifies it while running) so
        # it may give invalid results.
        if utils.search_raw_data and value is None:
            value = self.__read_raw_value_at_address(self.binary, address,
                                         reference_byte_size)

            # If the content is 0, it will be considered that the value is not
            # initialised and None will be returned, even though it could be
            # possible in theory that 0 is the actual seeked value
            if value == 0:
                value = None

        return value

    def __read_raw_value_at_address(self, address, reference_byte_size,
                             endianness='little', signed=False):
        """Return the value located at the given address in a binary.
        reference_byte_size indicates the size of the value to look for.

        Parameters
        ----------
        address : int
            address of the searched value
        reference_byte_size : int
            size in bytes of the value that is referenced
        endianness : string
            endianness of the architecture, little by default (as in x86_64)
        signed : bool
            whether it should be interpreted as a signed value or not, False by
            default

        Returns
        -------
        value : int
            the value that has been found

        Raises
        ------
        StaticAnalyserException
            If no section was found for the given address or if the address
            was invalid
        """

        target_section = self.get_section_from_address(address)

        section_start_offset = address - target_section.virtual_address
        value = bytearray(target_section.content)[section_start_offset
                                                  :section_start_offset
                                                   +reference_byte_size * 8]
        value = int.from_bytes(value, byteorder=endianness, signed=signed)
        return value

    def get_local_function_called(self, f_address, show_warnings=True):
        """Returns the function that would be called by jumping to the address
        given.

        Parameters
        ----------
        f_address : int
            address of the called function
        show_warnings : bool
            Whether or not should a warning be thrown if no function was found

        Returns
        -------
        called_plt_f : LibFunction
            function that would be called
        """

        return self.__get_function_mapping(self.__address_to_fun_map,
                                           f_address, "address", show_warnings)

    def __get_local_function_address(self, f_name, show_warnings=True):
        """Returns the address of the local function with the given name
        Parameters
        ----------
        f_name : str
            name of the function that is to be found
        show_warnings : bool
            whether or not should a warning be thrown if no function was found

        Returns
        -------
        f_address : int
            address of the function
        """

        return self.__get_function_mapping(self.__f_name_to_addr_map, f_name,
                                           "name", show_warnings)

    def __get_function_mapping(self, map_dict, key, key_type,
                               show_warnings=True):

        if map_dict is None:
            map_dict = self.__initialize_function_map(key_type)

        if key not in map_dict:
            if show_warnings:
                utils.print_warning(f"[WARNING] A function was called but "
                                    f"couldn't be found with its {key_type}: "
                                    f"{key}")
            return None

        return map_dict[key]

    def __initialize_function_map(self, key_type):

        if key_type == "name":
            self.__f_name_to_addr_map = {}
            for item in self.binary.lief_binary.functions:
                self.__f_name_to_addr_map[item.name] = item.address
            return self.__f_name_to_addr_map
        if key_type == "address":
            self.__address_to_fun_map = {}
            for item in self.binary.lief_binary.functions:
                self.__address_to_fun_map[item.address] = (
                        library_analyser.LibFunction(
                            name=item.name,
                            library_path=self.binary.path,
                            boundaries=(item.address,
                                        item.address + item.size)
                            )
                        )
            return self.__address_to_fun_map

        return None

    def find_next_function_addr(self, from_addr):
        """Returns the address of closest function found after the given
        address by looking at the symbolic information of the ELF.

        Parameters
        ----------
        from_address : int
            address marking the start of the searching area (the given address
            will be strictly superior to from_address)

        Returns
        -------
        next_function_address : int
            address of the function following from_address
        """

        if self.__address_to_fun_map is None:
            self.__initialize_function_map("address")

        # If there is a guarantee that the dictionary keys are sorted, then a
        # dictionary sort would be quicker, but I don't know if there is such a
        # guarantee. From Python 3.7, the keys are guaranteed to maintain
        # insertion order, but I didn't find an ELF and a lief guarantee that
        # the way they are inserted in __address_to_fun_map is sorted by
        # addresses. Since this code will probably hardly ever be called
        # anyway, I did not try to make it sorted myself.
        return min(k for k in self.__address_to_fun_map if k > from_addr)
