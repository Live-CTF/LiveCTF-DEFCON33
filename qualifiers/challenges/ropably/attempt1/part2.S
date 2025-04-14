	.section	.text.checker,"ax",@progbits
	.globl	checker
	.type	checker, @function
checker:
    leaq chain(%rip), %rbx
    xchg %rsp, %rbx
    ret

rop_chunk0:
    xchg %rsp, %rbx
	endbr64
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$32, %rsp
	movq	%fs:40, %rax
    xchg %rsp, %rbx
    ret

rop_chunk1:
    xchg %rsp, %rbx
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	leaq	-20(%rbp), %rax
	movq	%rax, %rsi
	leaq	.LC0(%rip), %rax
	movq	%rax, %rdi
    xchg %rsp, %rbx
    ret

rop_chunk2:
    xchg %rsp, %rbx
	movl	$0, %eax
	call	__isoc99_scanf@PLT
	leaq	-16(%rbp), %rax
	movq	%rax, %rsi
	leaq	.LC0(%rip), %rax
    xchg %rsp, %rbx
    ret

rop_chunk3:
    xchg %rsp, %rbx
	movq	%rax, %rdi
	movl	$0, %eax
	call	__isoc99_scanf@PLT
	movl	-20(%rbp), %edx
	movl	-16(%rbp), %eax
    xchg %rsp, %rbx
    ret

rop_chunk4:
    xchg %rsp, %rbx
	addl	%edx, %eax
	movl	%eax, -12(%rbp)
	movl	-12(%rbp), %eax
	movl	%eax, %esi
    xchg %rsp, %rbx
    ret

rop_chunk5:
    xchg %rsp, %rbx
	leaq	.LC1(%rip), %rax
	movq	%rax, %rdi
	movl	$0, %eax
	call	printf@PLT
    xchg %rsp, %rbx
    ret

rop_chunk6:
    xchg %rsp, %rbx
	nop
	movq	-8(%rbp), %rax
	subq	%fs:40, %rax
	je	.L2
	call	__stack_chk_fail@PLT
.L2:
	leave
	ret
	.size	checker, .-checker
	.ident	"GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0"
