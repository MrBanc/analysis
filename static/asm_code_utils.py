"""
Provide functions to analyse or process elements of the (assembly or binary)
code.
"""
import re

from capstone import (CS_GRP_JUMP, CS_GRP_CALL,
                      CS_OP_IMM, CS_OP_FP, CS_OP_MEM)

import utils
from custom_exception import StaticAnalyserException

# Used to detect the syscall identifier.
# The "high byte" (for example 'ah') is not considered. It could be,
# to be exhaustive, but it would be unlikely to store the syscall id using
# this identifier (and the code should be modified).
registers = {'eax':  {'rax','eax','ax','al'},
             'ebx':  {'rbx','ebx','bx','bl'},
             'ecx':  {'rcx','ecx','cx','cl'},
             'edx':  {'rdx','edx','dx','dl'},
             'esi':  {'rsi','esi','si','sil'},
             'edi':  {'rdi','edi','di','dil'},
             'ebp':  {'rbp','ebp','bp','bpl'},
             'esp':  {'rsp','esp','sp','spl'},
             'r8d':  {'r8','r8d','r8w','r8b'},
             'r9d':  {'r9','r9d','r9w','r9b'},
             'r10d': {'r10','r10d','r10w','r10b'},
             'r11d': {'r11','r11d','r11w','r11b'},
             'r12d': {'r12','r12d','r12w','r12b'},
             'r13d': {'r13','r13d','r13w','r13b'},
             'r14d': {'r14','r14d','r14w','r14b'},
             'r15d': {'r15','r15d','r15w','r15b'}}

__operand_byte_size = {"byte": 1,
                       "word": 2,
                       "dword": 4,
                       "qword": 8,
                       "tword": 10,
                       "oword": 16,
                       "yword": 32,
                       "zword": 64}


def extract_destination_address(ins, elf_analyser):
    """Try to extract a destination address with the instruction given.
    The objective is to find addresses that would lead to functions so only
    operands of calls (or jumps) are considered (but not checked).

    However, if the functionality to detect function pointers is activated, any
    number that can be extracted from an instruction (and only from the
    instruction, so without backtracking) and which could potentially lead to a
    function (so not a memory address that is being written to for example) is
    extracted as an address.

    It is considered that only one such address can be extracted from an
    instruction at most.

    Parameters
    ----------
    ins : capstone instruction
        the instruction to inspect
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary

    Returns
    -------
    dest_address : int
        potential destination address extracted from the instruction
    """

    dest_address = None
    show_warnings = True

    if ins.group(CS_GRP_JUMP):
        show_warnings = False

    if ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL):
        dest_address = __compute_operand_address_value(ins.op_str,
                                                 utils.compute_rip(ins),
                                                 elf_analyser,
                                                 ins.group(CS_GRP_CALL))
    # TODO: verify if it's a bug or if you just don't understand.
    # capstone bug (?): memory operands seem to be considered of type "FP"
    elif utils.search_function_pointers and (ins.op_count(CS_OP_IMM)
                                             or ins.op_count(CS_OP_FP)
                                             or ins.op_count(CS_OP_MEM)):
        # Every immediate or memory operand is examined as a potential
        # function pointer. This slows down the process a bit, is
        # approximative and rarely brings results therefore it can be
        # deactivated with command line args
        assigned = get_assigned_value(ins, elf_analyser)
        if isinstance(assigned, int) and assigned > 0:
            dest_address = assigned
        # If `assigned` is a register there is no need to backtrack it as
        # the operation at the end of the backtrack which sets the value
        # will already have been inspected as a potential function pointer
        # beforehand

        show_warnings = False

    return dest_address, show_warnings

def get_assigned_value(ins, elf_analyser):
    """Returns the value (or register) that is being assigned to the
    destination operand in the given instruction.

    Parameters
    ----------
    ins : capstone instruction
        the instruction to consider
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary

    Returns
    -------
    assigned_val : int or str
        the assigned value, which can either be a number or a register name (or
        None in case of error)
    """

    mnemonic = ins.mnemonic
    op_strings = ins.op_str.split(",")

    assigned_val = None
    if mnemonic not in ("mov", "xor", "lea"):
        return assigned_val

    op_strings[0] = op_strings[0].strip()
    op_strings[1] = op_strings[1].strip()

    if mnemonic == "mov":
        if is_reg(op_strings[1]):
            assigned_val = __get_reg_key(op_strings[1])
        else:
            assigned_val = __compute_operand_address_value(
                    op_strings[1], utils.compute_rip(ins), elf_analyser, False)
    elif mnemonic == "xor" and op_strings[0] == op_strings[1]:
        assigned_val = 0
    elif mnemonic == "lea" and bool(re.fullmatch(r'\[.*\]', op_strings[1])):
        assigned_val = __compute_operand_address_value(op_strings[1][1:-1],
                                                       utils.compute_rip(ins),
                                                       elf_analyser, False)

    return assigned_val

def mov_local_funs_to(f_to, f_from, elf_analyser):
    """Move the functions from .plt that lead to an IRELATIVE .got entry
    from `f_from` to `f_to`.

    These functions correspond to functions that are local to the currently
    analysed binary while other entries of the .got (with the type
    JUMP_SLOT) correspond to functions from other libraries, which should
    be treated differently. The purpose of this function is thus to
    separate them.

    If f_to is none, the IRELATIVE function are just removed from f_from.

    Parameters
    ----------
    f_to, f_from : lists of LibFunction
        the lists to move functions to and move functions from
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary
    """

    for i, f in enumerate(f_from):
        # no name indicates it wasn't an JUMP_SLOT got entry
        if not f.name:
            if f_to is not None:
                f_to.append(elf_analyser.get_local_function_called(
                    f.boundaries[0]))
            f_from.pop(i)

def detect_syscall_type(ins):
    """Return the syscall type corresponding to the instruction given: either
    DIRECT SYSCALL (x86_64), SYSENTER or DIRECT SYSCALL (x86).

    Parameters
    ----------
    ins : capstone instruction
        the syscall instruction

    Returns
    -------
    syscall_type : str
        the type of syscall

    Raises
    ------
    StaticAnalyserException
        If the instruction does not correspond to one of the three known
        syscall types
    """

    b = ins.bytes
    if b[0] == 0x0f and b[1] == 0x05:
        return "DIRECT SYSCALL (x86_64)"
    if b[0] == 0x0f and b[1] == 0x34:
        return "SYSENTER"
    if b[0] == 0xcd and b[1] == 0x80:
        return "DIRECT SYSCALL (x86)"

    utils.print_warning(f"invalid syscall type: {b}")
    return "undefined (syscall)"

def is_reg(string):
    """Returns true if the given string is the name of a (x86_64 general
    purpose) register identifier.

    Parameters
    ----------
    string : str
        the string that may contain a register identifier

    Returns
    -------
    is_reg : bool
        True if the string is a register identifier
    """

    if not isinstance(string, str):
        return False

    for reg_ids in registers.values():
        if string in reg_ids:
            return True

    return False

def __compute_operand_address_value(operand, rip_value, elf_analyser,
                                   show_warnings):
    """Returns the resulting address of the given operand.

    Parameters
    ----------
    operand : str
        operand containing an address or a reference to an address
    rip_value : int
        the value of the rip register (address of next instruction)
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary
    show_warnings : bool
        whether or not should a warning be thrown if the resulting address
        couldn't be found

    Returns
    -------
    address : int
        resulting address of the given operand
    """

    address = None

    if utils.is_number(operand):
        address = utils.str2int(operand)
    elif "[rip" in operand:
        address_location = __compute_rip_operation(operand, rip_value)
        reference_byte_size = __operand_byte_size[operand.split()[0]]
        try:
            address = elf_analyser.resolve_value_at_address(
                    address_location, reference_byte_size)
        except StaticAnalyserException:
            # A warning will anyway be throwed later if needed
            pass

    elif "rip" in operand:
        # will probably never enter here but we never know
        address = __compute_rip_operation(operand, rip_value)

    if show_warnings and address is None:
        # TODO: Other things could be done to try obtaining the address
        utils.print_warning("[WARNING] A function may have been called but"
                            " couln't be found. This is probably due "
                            "to an indirect address call.")

    return address

def __compute_rip_operation(operand, rip_value):
    """Beware that it will return the value of the operation with the rip,
    not the value of the whole operand. For example, if the operand is
    `qword ptr [rip + 0x1234]`, this function will return the result of
    `rip + 0x1234` and not the value located at the address `rip + 0x1234`.
    """

    ret = None

    pattern = r'.*rip ([+-]) ([^]]*).*'
    match = re.search(pattern, operand)
    pattern_is_matched = (bool(re.fullmatch(pattern, operand))
                          or bool(re.search(f'\\[{pattern}\\]', operand)))

    if (pattern_is_matched and utils.is_number(match.group(2))):
        ret = utils.compute_operation(match.group(1), rip_value,
                                      utils.str2int(match.group(2)))
    elif "rip" in operand:
        utils.print_debug(f"An operand with rip is unsupported: {operand}")

    return ret

def __get_reg_key(reg_id):
    """Given a register identifier, returns the key to have access to this
    register in the `registers` variable.

    Parameters
    ----------
    reg_id : str
        the string contains a register identifier

    Returns
    -------
    reg_key : str
        the key for this register

    Raises
    ------
    StaticAnalyserException
        If the given reg_id is not a register id
    """

    for reg_key, reg_ids in registers.items():
        if reg_id in reg_ids:
            return reg_key

    raise StaticAnalyserException(f"{reg_id}, the given reg_id does not "
                                  f"correspond to a register id.")
