	.file	"test14.c"
	.intel_syntax noprefix
	.text
	.section	.rodata
.LC0:
	.string	"/tmp/testdir"
	.text
	.globl	f1
	.type	f1, @function
f1:
.LFB0:
	.cfi_startproc
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	mov	DWORD PTR [rbp-4], 83
	mov	eax, DWORD PTR [rbp-4]
	mov	edi, 1
	mov	edx, OFFSET FLAT:.LC0
	mov	esi, 511
#APP
# 7 "test14.c" 1
	syscall
# 0 "" 2
#NO_APP
	nop
	pop	rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	f1, .-f1
	.globl	main
	.type	main, @function
main:
.LFB1:
	.cfi_startproc
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	mov	rbp, rsp
	.cfi_def_cfa_register 6
	mov	edi, 1
	call	f1
	mov	eax, 0
	pop	rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
	.ident	"GCC: (GNU) 14.1.1 20240701 (Red Hat 14.1.1-7)"
	.section	.note.GNU-stack,"",@progbits
