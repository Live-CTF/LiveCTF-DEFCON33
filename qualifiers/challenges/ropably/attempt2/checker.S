	.file	"checker.c"
	.text
	.section	.text.checker,"ax",@progbits
	.globl	checker
	.type	checker, @function
checker:
	endbr64
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rdi, -24(%rbp)
	movl	$1, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$5, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$13, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$100, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$13, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$2, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$116, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$2, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$8, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$177, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$8, %rax
	movzbl	(%rax), %edx
	movq	-24(%rbp), %rax
	addq	$3, %rax
	movzbl	(%rax), %eax
	xorl	%edx, %eax
	movsbl	%al, %eax
	movzwl	%ax, %eax
	cmpl	$32, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$3, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$4, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$166, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$4, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$12, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$166, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$12, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$15, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	imull	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$8769, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$15, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$1, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$223, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$1, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$9, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	subl	%eax, %edx
	movzwl	%dx, %eax
	cmpl	$5, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$9, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$14, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	subl	%eax, %edx
	movzwl	%dx, %eax
	cmpl	$65527, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$14, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$7, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	imull	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$13572, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$7, %rax
	movzbl	(%rax), %edx
	movq	-24(%rbp), %rax
	movzbl	(%rax), %eax
	xorl	%edx, %eax
	movsbl	%al, %eax
	movzwl	%ax, %eax
	cmpl	$37, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$11, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	imull	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$8400, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$11, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$6, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	subl	%eax, %edx
	movzwl	%dx, %eax
	cmpl	$65528, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$6, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$10, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	imull	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$7797, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movq	-24(%rbp), %rax
	addq	$10, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %edx
	movq	-24(%rbp), %rax
	addq	$5, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	addl	%edx, %eax
	movzwl	%ax, %eax
	cmpl	$119, %eax
	sete	%al
	movzbl	%al, %eax
	andl	%eax, -4(%rbp)
	movl	-4(%rbp), %eax
	popq	%rbp
	ret
	.size	checker, .-checker
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
