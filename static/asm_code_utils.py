"""
Provide functions to analyse or process elements of the (assembly or binary)
code.
"""

import re
import sys

from capstone import (Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL,
                      CS_OP_IMM, CS_OP_FP, CS_OP_MEM)
from capstone.x86_const import X86_INS_INVALID, X86_INS_DATA16

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


def extract_destination_address(list_inst, elf_analyser):
    """Try to extract a destination address from the last instruction given.
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
    list_inst : list of capstone instructions
        the instructions that lead to the instruction to inspect (included)
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary

    Returns
    -------
    dest_address : int
        potential destination address extracted from the instruction
    show_warnings : bool
        whether or not a warning should be throwed if this destination address
        leads to something unexpected
    """

    dest_address = None
    show_warnings = not list_inst[-1].group(CS_GRP_JUMP)

    if list_inst[-1].group(CS_GRP_JUMP) or list_inst[-1].group(CS_GRP_CALL):
        dest_address = __compute_operand_address_value(list_inst[-1].op_str,
                                                       list_inst,
                                                       elf_analyser,
                                                       show_warnings)
    # TODO: verify if it's a bug or if you just don't understand.
    # capstone bug (?): memory operands seem to be considered of type "FP"
    elif utils.search_function_pointers and (list_inst[-1].op_count(CS_OP_IMM)
                                             or list_inst[-1].op_count(CS_OP_FP)
                                             or list_inst[-1].op_count(CS_OP_MEM)):
        # Every immediate or memory operand is examined as a potential
        # function pointer. This slows down the process a bit, is
        # approximative and rarely brings results therefore it can be
        # deactivated with command line args
        dest_address = get_assigned_value(list_inst, elf_analyser)
        # If `assigned` is a register there is no need to backtrack it as
        # the operation at the end of the backtrack which sets the value
        # will already have been inspected as a potential function pointer
        # beforehand

        show_warnings = False

    if not isinstance(dest_address, int) or dest_address <= 0:
        dest_address = None

    return dest_address, show_warnings

def get_assigned_value(list_inst, elf_analyser):
    """Returns the value (or register) that is being assigned to the
    destination operand in the given instruction.

    Important note: because the returned value could be an address, this
    function does not try to translate values represented with 2-th complement
    into negative values. If this function is used to obtain values which are
    not addresses, the calling function should be the one to deal with this.

    Parameters
    ----------
    list_inst : capstone instruction
        the instructions leading to the one to consider (included)
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary

    Returns
    -------
    assigned_val : int or None
        the assigned value (or None in case of error)
    """

    mnemonic = list_inst[-1].mnemonic
    op_strings = list_inst[-1].op_str.split(",")

    # TODO support add, movsx, movsxd, movl etc et les autres instructions
    # faciles à supporter

    assigned_val = None
    if mnemonic not in ("mov", "xor", "lea"):
        if utils.currently_backtracking:
            utils.log("[Operation not supported]", "backtrack.log", indent=2)
        return assigned_val

    op_strings[0] = op_strings[0].strip()
    op_strings[1] = op_strings[1].strip()

    if mnemonic == "mov":
        assigned_val = __compute_operand_address_value(
                    op_strings[1], list_inst, elf_analyser, False)
    elif mnemonic == "lea" and bool(re.fullmatch(r'\[.*\]', op_strings[1])):
        assigned_val = __compute_operand_address_value(op_strings[1][1:-1],
                                                       list_inst,
                                                       elf_analyser, False)
    elif mnemonic == "xor" and op_strings[0] == op_strings[1]:
        assigned_val = 0

    return assigned_val

def backtrack_register(focus_reg, list_inst, elf_analyser):
    # TODO: put these two comments into method docstring + do docstring

    # Beware that it will be considered that the value is put inside the
    # register in one operation. For example, this type of code is not
    # supported:
    # mov rdi, 0x1234
    # shl rdi, 16
    # mov di, 0x5678

    # Important note: because the returned value could be an address, this
    # function does not try to translate values represented with 2-th
    # complement into negative values. If this function is used to obtain
    # values which are not addresses, the calling function should be the one to
    # deal with this.


    md = Cs(CS_ARCH_X86, CS_MODE_64)

    was_already_backtracking = utils.currently_backtracking
    utils.currently_backtracking = True

    index = len(list_inst) - 1
    last_ins_index = max(0, index - 1 - utils.max_backtrack_insns)
    for i in range(index - 1, last_ins_index - 1, -1):
        if list_inst[i].id in (X86_INS_DATA16, X86_INS_INVALID):
            continue

        utils.log(f"-> {hex(list_inst[i].address)}:{list_inst[i].mnemonic}"
                  f" {list_inst[i].op_str}", "backtrack.log", indent=1)

        regs_write = list_inst[i].regs_access()[1]
        for r in regs_write:
            if md.reg_name(r) not in registers[focus_reg]:
                continue

            assigned_value = get_assigned_value(list_inst[last_ins_index:i+1],
                                                elf_analyser)

            ret = None
            if isinstance(assigned_value, int):
                ret = assigned_value

            utils.currently_backtracking = was_already_backtracking
            return ret

    utils.log("[cannot backtrack further]", "backtrack.log", indent=2)

    utils.currently_backtracking = was_already_backtracking
    return None

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
        the string that may represent a register identifier

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

def __contains_reg(string):
    """Returns true if the given string contains the name of a (x86_64 general
    purpose) register identifier.

    Parameters
    ----------
    string : str
        the string that may contain a register identifier

    Returns
    -------
    is_reg : bool
        True if the string contains a register identifier
    """

    if not isinstance(string, str):
        return False

    for reg_ids in registers.values():
        for identifier in reg_ids:
            if identifier in string:
                return True

    return False

def __compute_operand_address_value(operand, list_inst, elf_analyser,
                                    show_warnings):
    """Returns the resulting address of the given operand.

    This function can also be used to compute operand values that are not
    addresses (like constants) as they can be interpreted as addresses.

    If the previous instructions are not given, the function will not try to
    backtrack the value of registers.

    Important note: because the returned value is supposed to be an address,
    this function does not try to translate values represented with 2-th
    complement into negative values. If this function is used to obtain values
    which are not addresses, the calling function should be the one to deal
    with this.

    Parameters
    ----------
    operand : str
        operand containing an address or a reference to an address
    list_inst : list of capstone instructions
        the list of instructions that have been analysed in the current scope
        (generally the current function or the whole .text). Giving only the
        last instruction is valid, but then no backtracking will take place
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

    use_backtracking = len(list_inst) > 1
    address = None

    brackets_expr = re.search(r'\[(.*)\]', operand)

    if bool(re.search(r'[a-z]+:', operand)): # example: word ptr fs:[...]
        # not supported (yet?)
        pass
    elif not use_backtracking and __contains_reg(operand): # except rip
        if utils.currently_backtracking:
            utils.log("[cannot backtrack further]", "backtrack.log", indent=2)
    elif bool(brackets_expr):
        try:
            address_location = __compute_operation(brackets_expr.group(1),
                                                       list_inst, elf_analyser)
            reference_byte_size = __operand_byte_size[operand.split()[0]]
            # Manipulating negative numbers in 2th complement could lead to
            # arithmetic overflow which should be ignored
            address_location %= 2**64
            address = elf_analyser.resolve_value_at_address(
                    address_location, reference_byte_size)
        except StaticAnalyserException as e:
            if e.is_critical:
                sys.stderr.write(f"{e}\n")
            # A warning will anyway be throwed later if needed
    else: # does not contains square brackets or sections
        try:
            address = __compute_operation(operand, list_inst, elf_analyser)
            # same remark as above
            address %= 2**64
        except StaticAnalyserException as e:
            if e.is_critical:
                sys.stderr.write(f"{e}\n")
            # A warning will anyway be throwed later if needed

    if show_warnings and address is None:
        # TODO: Other things could be done to try obtaining the address
        utils.print_warning("[WARNING] A function may have been called but"
                            " couln't be found. This is probably due "
                            "to an indirect address call.")

    return address

def __compute_operation(operation, list_inst, elf_analyser):
    """There are two important notes about this function:

    1. It will only return the value of the operation, not the value of the
    whole operand. For example, if the operand is `qword ptr [rip + 0x1234]`,
    this function will return the result of `rip + 0x1234` and not the value
    located at the address `rip + 0x1234`.

    2. It will not try to understand the actual decimal value corresponding to
    this number. For example, if the computed value is 0xfffffffb, then
    4294967291 will be returned (and not -5, using 2th complement). This also
    holds for arithmetic overflow : the returned value could be greater than
    2**64.
    The reason why this function does not try to deal with it is because the
    calling function could want to read the value represented as a signed or an
    unsigned number. Also, it would need to know on how many bits the value is
    represented, which would be cumbersome.
    It should not cause any problems as adding a negative number in 2th
    complement is the same as adding its unsigned value and then taking the 2th
    complement.

    Raises
    ------
    StaticAnalyserException
        If the value couldn't be computed
    """

    # TODO Raise exception and catch it in calling functions

    # print(f"gougoug1 {operation}")

    terms_and_operands = re.findall(r'[-+*]|[^ -+*]+', operation)
    terms_and_operands = [token.strip() for token in terms_and_operands]

    for i, token in enumerate(terms_and_operands):
        if utils.is_number(token):
            continue
        if is_reg(token):
            if utils.currently_backtracking:
                utils.log(f"[Shifting focus to {token}]",
                          "backtrack.log", indent=2)
            else:
                utils.log(f"Value of interest, start backtracking: "
                          f"{hex(list_inst[-1].address)} {list_inst[-1].mnemonic} "
                          f"{list_inst[-1].op_str} from "
                          f"{elf_analyser.binary.path}",
                          "backtrack.log", indent=0)
            # TODO logging pour le backtrack. peut-être dans un wrapper ?
            reg_value = backtrack_register(__get_reg_key(token), list_inst,
                                           elf_analyser)
            if utils.currently_backtracking:
                utils.log(f"[{token} value found: {reg_value}]",
                          "backtrack.log", indent=2)
            else:
                utils.log(f"Value found: {reg_value}\n", "backtrack.log",
                          indent=0)
            if not isinstance(reg_value, int):
                raise StaticAnalyserException("[WARNING] Register backtracing "
                                              "did not return an int",
                                              is_critical=False)
            if reg_value >= 0:
                terms_and_operands[i] = str(reg_value)
            else:
                terms_and_operands[i] = "(" + str(reg_value) + ")"
        elif "rip" == token:
            rip_value = utils.compute_rip(list_inst[-1])
            terms_and_operands[i] = str(rip_value)
        elif token in ("+", "-", "*"):
            pass
        else:
            raise StaticAnalyserException(f"[WARNING] Unsupported token in an "
                                          f"operation: {token}",
                                          is_critical=True)

    if len(terms_and_operands) < 1:
        raise StaticAnalyserException("[WARNING] Empty operation",
                                      is_critical=False)

    # print(f"gougoug2 {terms_and_operands}")

    # The content of terms_and_operands is checked beforehand so using `eval`
    # in this case should not be dangerous.
    # pylint: disable=eval-used
    result = eval("".join(terms_and_operands))

    # print(f"gougoug3 {result}")

    return result

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

    # TODO: les fonctions appelantes ne prennent pas en compte cette exception
    # donc ça fait crash le programme si elle arrive...
    raise StaticAnalyserException(f"[WARNING] {reg_id}, the given reg_id does "
                                  f"not correspond to a register id.")
