	.file	"checker.c"
	.text
	.section	.text.checker,"ax",@progbits
	.globl	checker
	.type	checker, @function
checker:
	.size	checker, .-checker
leaq chain(%rip), %rbx
        xchg %rsp, %rbx
        ret
rop_chunk_4:
        xchg %rsp, %rbx
	movzbl	(%rax), %eax
	movsbl	%al, %eax
xchg %rsp, %rbx
        ret
rop_chunk_54:
        xchg %rsp, %rbx
	movsbl	%al, %eax
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$119, %eax
	sete	%al
xchg %rsp, %rbx
        ret
rop_chunk_43:
        xchg %rsp, %rbx
	addq	$11, %rax
	movzbl	(%rax), %eax
xchg %rsp, %rbx
        ret
rop_chunk_39:
        xchg %rsp, %rbx
	movq	-24(%rbp), %rax
	addq	$7, %rax
xchg %rsp, %rbx
        ret
rop_chunk_18:
        xchg %rsp, %rbx
	movq	-24(%rbp), %rax
	addq	$4, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
xchg %rsp, %rbx
        ret
rop_chunk_3:
        xchg %rsp, %rbx
	movq	-24(%rbp), %rax
	addq	$13, %rax
xchg %rsp, %rbx
        ret
rop_chunk_37:
        xchg %rsp, %rbx
	movq	-24(%rbp), %rax
	addq	$7, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	imull	%edx, %eax
	movzwl	%ax, %eax
xchg %rsp, %rbx
        ret
rop_chunk_2:
        xchg %rsp, %rbx
	movq	-24(%rbp), %rax
	addq	$5, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
xchg %rsp, %rbx
        ret
rop_chunk_17:
        xchg %rsp, %rbx
	movzbl	(%rax), %eax
	movsbl	%al, %edx
xchg %rsp, %rbx
        ret
rop_chunk_26:
        xchg %rsp, %rbx
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$15, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
xchg %rsp, %rbx
        ret
rop_chunk_28:
        xchg %rsp, %rbx
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$223, %eax
xchg %rsp, %rbx
        ret
rop_chunk_24:
        xchg %rsp, %rbx
	movq	-24(%rbp), %rax
	addq	$12, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$15, %rax
xchg %rsp, %rbx
        ret
rop_chunk_8:
        xchg %rsp, %rbx
	movq	-24(%rbp), %rax
	addq	$2, %rax
	movzbl	(%rax), %eax
xchg %rsp, %rbx
        ret
rop_chunk_22:
        xchg %rsp, %rbx
	movzwl	%ax, %eax
	cmpl	$166, %eax
xchg %rsp, %rbx
        ret
rop_chunk_53:
        xchg %rsp, %rbx
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$5, %rax
	movzbl	(%rax), %eax
xchg %rsp, %rbx
        ret
rop_chunk_11:
        xchg %rsp, %rbx
	addq	$2, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
xchg %rsp, %rbx
        ret
rop_chunk_32:
        xchg %rsp, %rbx
	cmpl	$5, %eax
	sete	%al
	movzbl	%al, %eax
xchg %rsp, %rbx
        ret
rop_chunk_9:
        xchg %rsp, %rbx
	movsbl	%al, %eax
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$116, %eax
	sete	%al
xchg %rsp, %rbx
        ret
rop_chunk_7:
        xchg %rsp, %rbx
	movzbl	(%rax), %eax
	movsbl	%al, %edx
xchg %rsp, %rbx
        ret
rop_chunk_52:
        xchg %rsp, %rbx
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$10, %rax
xchg %rsp, %rbx
        ret
rop_chunk_16:
        xchg %rsp, %rbx
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$3, %rax
xchg %rsp, %rbx
        ret
rop_chunk_51:
        xchg %rsp, %rbx
	imull	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$7797, %eax
	sete	%al
xchg %rsp, %rbx
        ret
rop_chunk_46:
        xchg %rsp, %rbx
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$11, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
xchg %rsp, %rbx
        ret
rop_chunk_0:
        xchg %rsp, %rbx
	endbr64
	pushq	%rbp
	movq	%rsp, %rbp
xchg %rsp, %rbx
        ret
rop_chunk_47:
        xchg %rsp, %rbx
	addq	$6, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
xchg %rsp, %rbx
        ret
rop_chunk_12:
        xchg %rsp, %rbx
	addq	$8, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$177, %eax
xchg %rsp, %rbx
        ret
rop_chunk_44:
        xchg %rsp, %rbx
	movsbl	%al, %eax
	imull	%edx, %eax
	movzwl	%ax, %eax
xchg %rsp, %rbx
        ret
rop_chunk_55:
        xchg %rsp, %rbx
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
xchg %rsp, %rbx
        ret
rop_chunk_49:
        xchg %rsp, %rbx
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$6, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
xchg %rsp, %rbx
        ret
rop_chunk_6:
        xchg %rsp, %rbx
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$13, %rax
xchg %rsp, %rbx
        ret
rop_chunk_41:
        xchg %rsp, %rbx
	movzwl	%ax, %eax
	cmpl	$37, %eax
	sete	%al
xchg %rsp, %rbx
        ret
rop_chunk_31:
        xchg %rsp, %rbx
	movq	-24(%rbp), %rax
	addq	$9, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	subl	%eax, %edx
	movzwl	%dx, %eax
xchg %rsp, %rbx
        ret
rop_chunk_34:
        xchg %rsp, %rbx
	addq	$14, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	subl	%eax, %edx
	movzwl	%dx, %eax
xchg %rsp, %rbx
        ret
rop_chunk_50:
        xchg %rsp, %rbx
	addq	$10, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
xchg %rsp, %rbx
        ret
rop_chunk_14:
        xchg %rsp, %rbx
	movzbl	(%rax), %edx
	movq	-24(%rbp), %rax
	addq	$3, %rax
	movzbl	(%rax), %eax
	xorl	%edx, %eax
xchg %rsp, %rbx
        ret
rop_chunk_10:
        xchg %rsp, %rbx
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
xchg %rsp, %rbx
        ret
rop_chunk_40:
        xchg %rsp, %rbx
	movzbl	(%rax), %edx
	movq	-24(%rbp), %rax
	movzbl	(%rax), %eax
	xorl	%edx, %eax
	movsbl	%al, %eax
xchg %rsp, %rbx
        ret
rop_chunk_19:
        xchg %rsp, %rbx
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$166, %eax
	sete	%al
xchg %rsp, %rbx
        ret
rop_chunk_23:
        xchg %rsp, %rbx
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
xchg %rsp, %rbx
        ret
rop_chunk_33:
        xchg %rsp, %rbx
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$9, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
xchg %rsp, %rbx
        ret
rop_chunk_36:
        xchg %rsp, %rbx
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$14, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
xchg %rsp, %rbx
        ret
rop_chunk_1:
        xchg %rsp, %rbx
	movq	%rdi, -24(%rbp)
	movl	$1, -4(%rbp)
xchg %rsp, %rbx
        ret
rop_chunk_5:
        xchg %rsp, %rbx
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$100, %eax
	sete	%al
	movzbl	%al, %eax
xchg %rsp, %rbx
        ret
rop_chunk_21:
        xchg %rsp, %rbx
	movq	-24(%rbp), %rax
	addq	$12, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	addl	%edx, %eax
xchg %rsp, %rbx
        ret
rop_chunk_42:
        xchg %rsp, %rbx
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
xchg %rsp, %rbx
        ret
rop_chunk_25:
        xchg %rsp, %rbx
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	imull	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$8769, %eax
	sete	%al
xchg %rsp, %rbx
        ret
rop_chunk_27:
        xchg %rsp, %rbx
	movq	-24(%rbp), %rax
	addq	$1, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
xchg %rsp, %rbx
        ret
rop_chunk_13:
        xchg %rsp, %rbx
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$8, %rax
xchg %rsp, %rbx
        ret
rop_chunk_15:
        xchg %rsp, %rbx
	movsbl	%al, %eax
	movzwl	%ax, %eax
	cmpl	$32, %eax
	sete	%al
xchg %rsp, %rbx
        ret
rop_chunk_30:
        xchg %rsp, %rbx
	movzbl	(%rax), %eax
	movsbl	%al, %edx
xchg %rsp, %rbx
        ret
rop_chunk_35:
        xchg %rsp, %rbx
	cmpl	$65527, %eax
	sete	%al
xchg %rsp, %rbx
        ret
rop_chunk_48:
        xchg %rsp, %rbx
	subl	%eax, %edx
	movzwl	%dx, %eax
	cmpl	$65528, %eax
	sete	%al
	movzbl	%al, %eax
xchg %rsp, %rbx
        ret
rop_chunk_29:
        xchg %rsp, %rbx
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$1, %rax
xchg %rsp, %rbx
        ret
rop_chunk_56:
        xchg %rsp, %rbx
	movl	-4(%rbp), %eax
	popq	%rbp
	ret
xchg %rsp, %rbx
        ret
rop_chunk_45:
        xchg %rsp, %rbx
	cmpl	$8400, %eax
	sete	%al
	movzbl	%al, %eax
xchg %rsp, %rbx
        ret
rop_chunk_20:
        xchg %rsp, %rbx
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$4, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
xchg %rsp, %rbx
        ret
rop_chunk_38:
        xchg %rsp, %rbx
	cmpl	$13572, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
xchg %rsp, %rbx
        ret
	.ident	"GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
.data
    .align 8
chain:
        .quad rop_chunk_0, rop_chunk_1, rop_chunk_2, rop_chunk_3, rop_chunk_4, rop_chunk_5, rop_chunk_6, rop_chunk_7, rop_chunk_8, rop_chunk_9, rop_chunk_10, rop_chunk_11, rop_chunk_12, rop_chunk_13, rop_chunk_14, rop_chunk_15, rop_chunk_16, rop_chunk_17, rop_chunk_18, rop_chunk_19, rop_chunk_20, rop_chunk_21, rop_chunk_22, rop_chunk_23, rop_chunk_24, rop_chunk_25, rop_chunk_26, rop_chunk_27, rop_chunk_28, rop_chunk_29, rop_chunk_30, rop_chunk_31, rop_chunk_32, rop_chunk_33, rop_chunk_34, rop_chunk_35, rop_chunk_36, rop_chunk_37, rop_chunk_38, rop_chunk_39, rop_chunk_40, rop_chunk_41, rop_chunk_42, rop_chunk_43, rop_chunk_44, rop_chunk_45, rop_chunk_46, rop_chunk_47, rop_chunk_48, rop_chunk_49, rop_chunk_50, rop_chunk_51, rop_chunk_52, rop_chunk_53, rop_chunk_54, rop_chunk_55, rop_chunk_56
