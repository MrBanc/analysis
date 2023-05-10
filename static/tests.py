import lief
from capstone import *
from capstone.x86_const import X86_INS_INVALID, X86_INS_DATA16

binary = lief.parse("/lib64/libc.so.6")
text_section = binary.get_section(".text")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True

insns = md.disasm(bytearray(text_section.content),
                  text_section.virtual_address)

ins_jmp_list = []
ins_other_list = []
list_ins = []
for i, ins in enumerate(insns):
    list_ins.append(ins)
    if ins.id == 0:
        continue
    if CS_GRP_JUMP in ins.groups:
        ins_jmp_list.append(ins)
    else:
        ins_other_list.append(ins)

