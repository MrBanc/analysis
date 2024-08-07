"""
Provide functions to analyse or process elements of the (assembly or binary)
code.
"""

from dataclasses import dataclass

import re

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

# Only used for error message management
__high_byte_regs = ['ah', 'bh', 'ch', 'dh']

__operand_byte_size = {"byte": 1,
                       "word": 2,
                       "dword": 4,
                       "qword": 8,
                       "tword": 10,
                       "oword": 16,
                       "yword": 32,
                       "zword": 64}


@dataclass
class Address:
    """Represents an address in a binary.

    Attributes
    ----------
    value : int
        the address value
    is_local : bool
        whether or not the address is local to the binary
    f_name : str, optional
        if the address correspond to the start of a function, this is the name
        of the function
    """

    value: int
    is_local: bool
    f_name: str = None


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
    dest_address : Address or None
        potential destination address extracted from the instruction
    show_warnings : bool
        whether or not a warning should be throwed if this destination address
        leads to something unexpected
    """

    dest_address = None
    show_warnings = not list_inst[-1].group(CS_GRP_JUMP)

    if list_inst[-1].group(CS_GRP_JUMP) or list_inst[-1].group(CS_GRP_CALL):
        dest_address = __compute_address_operand(list_inst[-1].op_str,
                                                 list_inst,
                                                 elf_analyser,
                                                 show_warnings)
    # TODO: verify if it's a bug or if you just don't understand.
    # capstone bug (?): memory operands seem to be considered of type "FP"
    elif (utils.search_function_pointers
          and __may_discover_f_pointer(list_inst[-1])):
        # Every immediate or memory operand is examined as a potential
        # function pointer. This slows down the process a bit, is
        # approximative and rarely brings results therefore it can be
        # deactivated with command line args
        dest_address = __get_assigned_address(list_inst, elf_analyser)
        # If `assigned` is a register (or another value that can be
        # backtracked) there is no need to backtrack it as the operation at the
        # end of the backtrack which sets the value will already have been
        # inspected as a potential function pointer beforehand

        show_warnings = False

    if (dest_address is not None and dest_address.value <= 0
                                 and dest_address.f_name is None):
        dest_address = None

    return dest_address, show_warnings

def value_backtracker(focus_val, list_inst, elf_analyser):
    """Try to find the content/value of a given "variable" at the instruction
    to consider by using backtracking. The "variable" can be a register, a
    stack value or a memory location for example.

    Two important notes about this function:

    1. When backtracking registers, it will be considered that the value is put
    inside the register in one operation. For example, this type of code is not
    supported:
      mov rdi, 0x1234
      shl rdi, 16
      mov di, 0x5678

    2. Because the returned value could be an address, this function does not
    try to translate values represented with 2-th complement into negative
    values. If this function is used to obtain values which are not addresses,
    the calling function should be the one to deal with this.

    Parameters
    ----------
    focus_val : str
        the value to backtrack (register or stack value or ...)
    list_inst : list of capstone instructions
        the instructions leading to the one to consider (included)
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary

    Returns
    -------
    resolved_value : int or None
        the content (or value) of the tracked "variable" (or None in case it
        couldn't be found)
    """

    was_already_backtracking = utils.currently_backtracking
    utils.currently_backtracking = True

    index = len(list_inst) - 1
    # TODO try to find the beginning of the function if we are in the main
    # binary so that we cannot backtrack beyond
    last_ins_index = max(0, index - 1 - utils.max_backtrack_insns)
    for i in range(index - 1, last_ins_index - 1, -1):
        if list_inst[i].id in (X86_INS_DATA16, X86_INS_INVALID):
            continue

        utils.log(f"-> {hex(list_inst[i].address)}:{list_inst[i].mnemonic}"
                  f" {list_inst[i].op_str}", "backtrack.log", indent=1)

        if not __is_writing_to_focus(focus_val,
                                 list_inst[last_ins_index:i+1],
                                 elf_analyser):
            continue

        assigned_value = __get_assigned_value(list_inst[last_ins_index:i+1],
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
                local_fun = elf_analyser.get_local_function_called(
                        f.boundaries[0])
                if local_fun is None:
                    utils.print_error(
                            f"A function from .plt was previously detected but"
                            f" cannot be found in the symbolic information: "
                            f"{hex(f.boundaries[0])}. This should be "
                            f"impossible.")
                    continue
                f_to.append(local_fun)
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

def __get_assigned_value(list_inst, elf_analyser):
    """Returns the value that is being assigned to the destination operand in
    the given instruction.

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

    assigned_val = __get_assigned_object(list_inst, elf_analyser)

    # Convert the Address object into an int
    if isinstance(assigned_val, Address):
        if assigned_val.is_local:
            assigned_val = assigned_val.value
        else:
            assigned_val = None
    elif isinstance(assigned_val, int) or assigned_val is None:
        pass
    else:
        utils.print_error(f"[ERROR] Assigned value isn't of an expected type: "
                          f"{assigned_val}: {type(assigned_val)}")
        assigned_val = None

    return assigned_val

def __get_assigned_address(list_inst, elf_analyser):
    """Returns the address that is being assigned to the destination operand in
    the given instruction.

    Parameters
    ----------
    list_inst : capstone instruction
        the instructions leading to the one to consider (included)
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary

    Returns
    -------
    assigned_addr : Address or None
        the assigned address (or None in case of error)
    """

    assigned_val = __get_assigned_object(list_inst, elf_analyser)

    if isinstance(assigned_val, Address):
        return assigned_val
    if isinstance(assigned_val, int):
        return Address(assigned_val, True)

    return None

def __is_writing_to_focus(focus_val, list_inst, elf_analyser):
    """Returns true if the given instruction (the last one of list_inst) writes
    to the focus value.
    
    Note that a list of instructions is given to allow for backtracking the
    value written to, if necessary. (e.g. if the focus is at the address
    0x1234, maybe that writing to [eax] will write to 0x1234. To know that, it
    is necessary to backtrack eax). This is also why the elf_analyser is given
    as it is needed for the backtracking.

    Parameters
    ----------
    focus_val : str
        the value to focus on
    list_inst : list of capstone instructions
        the instructions leading to the one to consider (included)
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary

    Returns
    -------
    is_writing : bool
        True if the instruction writes to the focus value
    """

    md = Cs(CS_ARCH_X86, CS_MODE_64)

    if is_reg(focus_val):
        regs_writen = list_inst[-1].regs_access()[1]
        for r in regs_writen:
            if md.reg_name(r) in registers[focus_val]:
                return True
        return False

    # The focus could be something else than a register
    first_operand = list_inst[-1].op_str.split(",")[0].strip()
    if first_operand and (not is_reg(first_operand)):
        if utils.backtrack_potential_values:
            first_op_key = __get_backtrack_val_key(first_operand,
                                                   list_inst,
                                                   elf_analyser)
        else:
            first_op_key = __get_backtrack_val_key(first_operand,
                                                   [list_inst[-1]],
                                                   elf_analyser)
        if focus_val == first_op_key:
            return True

    # There are cases where the second operand is the one written to (e.g. with
    # xchg). This case is not taken care of (yet?).

    return False

def __contains_value_to_backtrack(string):
    """Returns true if, in order to compute the value of the given string, it
    would be necessary to backtrack a value (e.g. a register value).

    Parameters
    ----------
    string : str
        the string that may contain a value to backtrack
    
    Returns
    -------
    contains_val : bool
        True if the string contains a value to backtrack
    """

    terms_and_operands = __separate_terms_and_operands(string)

    for token in terms_and_operands:
        if is_reg(token):
            return True
        if token == "[":
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

def __get_assigned_object(list_inst, elf_analyser):
    """Helper function to obtain the object that is being assigned to the
    destination operand in the given instruction.

    Beware that the type of the returned object is not determined and should be
    checked by the calling function (see `__get_assigned_value`,
    `__get_assigned_address`...).

    ! If you add a new possible type of assigned object, you should modify the
    already existing calling functions to handle this new type.

    Parameters
    ----------
    list_inst : capstone instruction
        the instructions leading to the one to consider (included)
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary

    Returns
    -------
    assigned_val : undefined
        the assigned object (or None in case of error)
    """

    mnemonic = list_inst[-1].mnemonic
    op_strings = list_inst[-1].op_str.split(",")

    # TODO support add, xchg, movsx, movsxd, movl etc et les autres
    # instructions faciles à supporter

    assigned_val = None
    if mnemonic not in ("mov", "xor", "lea"):
        if utils.currently_backtracking:
            utils.log("[Operation not supported]", "backtrack.log", indent=2)
        return assigned_val

    op_strings[0] = op_strings[0].strip()
    op_strings[1] = op_strings[1].strip()

    if mnemonic == "mov":
        assigned_val = __compute_address_operand(
                    op_strings[1], list_inst, elf_analyser, False)
    elif mnemonic == "lea" and bool(re.fullmatch(r'\[.*\]', op_strings[1])):
        assigned_val = __compute_address_operand(op_strings[1][1:-1],
                                                 list_inst,
                                                 elf_analyser, False)
    elif mnemonic == "xor" and op_strings[0] == op_strings[1]:
        assigned_val = 0

    return assigned_val

def __compute_address_operand(operand, list_inst, elf_analyser,
                                    show_warnings):
    """Returns the resulting address of the given operand.

    This function can also be used to compute operand values that are not
    addresses (like constants) as they can be interpreted as addresses.

    If the previous instructions are not given, the function will not try to
    backtrack the value of registers, stack values, memory addresses etc.

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
    address : Address or None
        resulting address of the given operand
    """

    use_backtracking = len(list_inst) > 1
    address = None

    brackets_expr = re.search(r'\[(.*)\]', operand)

    try:
        if bool(re.search(r'[a-z]+:', operand)): # example: word ptr fs:[...]
            # not supported (yet?)
            pass
        elif bool(brackets_expr):
            address = __compute_address_bracket_operand(operand, list_inst,
                                                        elf_analyser)
        elif not use_backtracking and __contains_value_to_backtrack(operand):
            if utils.currently_backtracking:
                utils.log("[cannot backtrack further]",
                          "backtrack.log", indent=2)
        else: # does not contains square brackets or register prefixing them
            address_val = __compute_operation(operand, list_inst, elf_analyser)
            # same remark as above
            address_val %= 2**64
            address = Address(address_val, True)
    except StaticAnalyserException as e:
        if e.is_critical:
            utils.print_error(f"{e}")
        # A warning will anyway be thrown later if needed

    if show_warnings and address is None:
        # TODO: Other things could be done to try obtaining the address
        utils.print_warning("[WARNING] A function may have been called but"
                            " couln't be found. This is probably due "
                            "to an indirect address call.")

    return address

def __compute_address_bracket_operand(operand, list_inst, elf_analyser):
    """

    Raises
    ------
    StaticAnalyserException
        If the value couldn't be computed
    """

    use_backtracking = len(list_inst) > 1
    brackets_expr = re.search(r'\[(.*)\]', operand)

    address = None

    # First, try to obtain the address directly (looking at the symbols and the
    # content of the binary)
    # The address found is returned if a function name could be found.
    # Otherwise, we try the second method to see if a good result can be
    # obtained by backtracking. (if not, the value found by the first method is
    # returned)

    try:
        address_location = __compute_operation(brackets_expr.group(1),
                                                   list_inst, elf_analyser)
        reference_byte_size = __operand_byte_size[operand.split()[0]]
        # Manipulating negative numbers in 2th complement could lead to
        # arithmetic overflow which should be ignored
        address_location %= 2**64
        address = elf_analyser.resolve_address_stored_at(
                address_location, reference_byte_size)
        if address is not None and address.f_name is not None:
            return address
    except StaticAnalyserException as e:
        if e.is_critical:
            utils.print_error(f"{e}")

    # Second method: backtracking

    key = None
    if use_backtracking and any(reg in brackets_expr.group(1)
           for reg in (registers["eax"] | {"rip"} | registers["ebp"])):
        key = __get_backtrack_val_key(operand, list_inst, elf_analyser)
    if key is not None:
        if utils.currently_backtracking:
            utils.log(f"[Shifting focus to [{brackets_expr.group(1)}]"
                      f"(key: {key})]", "backtrack.log", indent=2)
        else:
            utils.log(f"Value of interest, start backtracking: "
                      f"{hex(list_inst[-1].address)} "
                      f"{list_inst[-1].mnemonic} "
                      f"{list_inst[-1].op_str} from "
                      f"{elf_analyser.binary.path}",
                      "backtrack.log", indent=0)
        address_b_val = value_backtracker(key, list_inst, elf_analyser)
        if utils.currently_backtracking:
            utils.log(f"[{key} value found: {address_b_val}]",
                      "backtrack.log", indent=2)
        else:
            utils.log(f"Value found: {address_b_val}\n", "backtrack.log",
                      indent=0)

        if isinstance(address_b_val, int) and address_b_val >= 0:
            address = Address(address_b_val, True)

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

    terms_and_operands = __separate_terms_and_operands(operation)

    for i, token in enumerate(terms_and_operands):
        if utils.is_number(token):
            continue
        if is_reg(token):
            try:
                reg_key = __get_reg_key(token)
            except StaticAnalyserException as e:
                raise e
            if reg_key in ("ebp", "esp"):
                if utils.currently_backtracking:
                    utils.log("[Cancel backtracking (stack-related register)]",
                              "backtrack.log", indent=2)
                raise StaticAnalyserException(
                        "[WARNING] Computing the operation requires knowing "
                        "the value of a stack related register",
                        is_critical=False)

            if utils.currently_backtracking:
                utils.log(f"[Shifting focus to {token}]",
                          "backtrack.log", indent=2)
            else:
                utils.log(f"Value of interest, start backtracking: "
                          f"{hex(list_inst[-1].address)} "
                          f"{list_inst[-1].mnemonic} {list_inst[-1].op_str} "
                          f"from {elf_analyser.binary.path}",
                          "backtrack.log", indent=0)
            reg_value = value_backtracker(reg_key, list_inst, elf_analyser)
            if utils.currently_backtracking:
                utils.log(f"[{token} value found: {reg_value}]",
                          "backtrack.log", indent=2)
            else:
                utils.log(f"Value found: {reg_value}\n", "backtrack.log",
                          indent=0)
            if not isinstance(reg_value, int):
                raise StaticAnalyserException("[WARNING] Register backtracking"
                                              " did not return an int",
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
            msg = f"[WARNING] Unsupported token in an operation: {token}"
            is_critical = token not in __high_byte_regs
            raise StaticAnalyserException(msg, is_critical=is_critical)

    if len(terms_and_operands) < 1:
        raise StaticAnalyserException("[WARNING] Empty operation",
                                      is_critical=False)

    # The content of terms_and_operands is checked beforehand so using `eval`
    # in this case should not be dangerous.
    # pylint: disable=eval-used
    result = eval("".join(terms_and_operands))

    return result

def __separate_terms_and_operands(string):

    terms_and_operands = re.findall(r'[+\-*\[\]]|[^ +\-*\[\]]+', string)
    return [token.strip() for token in terms_and_operands]

def __get_backtrack_val_key(string, list_inst, elf_analyser):
    """Returns the key to identify the value to backtrack. If the value is a
    register, the key allows to access the register in the `registers`
    variable.

    Note that a list of instructions is given to allow backtracking the value
    of the string, if necessary. (e.g. if the string is `qword ptr [eax]`, the
    key should correspond to the value of eax. To know that, it is necessary to
    backtrack eax).
    This is also why the elf_analyser is given as it is needed for the
    backtracking.

    Parameters
    ----------
    string : str
        the string that contains the value to backtrack
    list_inst : list of capstone instructions
        the instructions leading to the one to consider (included)
    elf_analyser : ELFAnalyser
        instance of ELFAnalyser corresponding to the analysed binary

    Returns
    -------
    val_key : str
        the key for this value
    """

    brackets_expr = re.search(r'(\[.*\])', string).group(1) if (
            bool(re.search(r'\[.*\]', string))) else ""

    if is_reg(string):
        return __get_reg_key(string)

    if not (utils.backtrack_memory or utils.backtrack_stack):
        return None

    if ("rip" in brackets_expr) and (list_inst is None):
        utils.print_error("[ERROR] Computing the value of rip requires knowing"
                          " the current instruction")
        return None

    stack_reg_used, brackets_expr = __extract_stack_reg(brackets_expr)

    if ((stack_reg_used and not utils.backtrack_stack)
        or (not stack_reg_used and not utils.backtrack_memory)):

        return None

    try:
        address_or_offset = __compute_operation(brackets_expr[1:-1],
                                                list_inst, elf_analyser)
    except StaticAnalyserException as e:
        utils.print_error(f"[ERROR] Could not compute the value of the "
                          f"brackets expression ({brackets_expr}): {e}")
        return None

    return "mem " + stack_reg_used + " " + str(address_or_offset)

def __extract_stack_reg(brackets_expr):

    stack_reg_used = ""

    terms_and_operands = __separate_terms_and_operands(brackets_expr)

    for i, token in enumerate(terms_and_operands):
        if is_reg(token):
            try:
                reg_key = __get_reg_key(token)
            except StaticAnalyserException as e:
                raise e
            if reg_key in ("ebp", "esp"):
                stack_reg_used += reg_key
                if "*" in (terms_and_operands[i-1], terms_and_operands[i+1]):
                    terms_and_operands[i] = "1"
                else:
                    terms_and_operands[i] = "0"

    new_brackets_expr = "".join(terms_and_operands)

    return stack_reg_used, new_brackets_expr

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

    # It is critical because it should never happen as `is_reg` should have
    # verified that it was indeed a register
    raise StaticAnalyserException(f"[WARNING] {reg_id}, the given reg_id does "
                                  f"not correspond to a register id.",
                                  is_critical=True)

def __may_discover_f_pointer(ins):

    op_strings = ins.op_str.split(",")

    # If the second operand is a register, it could contain a function pointer.
    # However, false is returned to avoid doing twice the same thing because if
    # it is possible to find a function pointer by backtracking this register,
    # it will already have been found when analysing the previous instructions.
    return ( (ins.op_count(CS_OP_IMM)
              or ins.op_count(CS_OP_FP)
              or ins.op_count(CS_OP_MEM))
            and len(op_strings) == 2 and not is_reg(op_strings[1].strip()))
