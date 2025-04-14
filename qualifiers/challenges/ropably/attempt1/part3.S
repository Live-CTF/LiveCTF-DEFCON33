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
    .quad rop_chunk0, rop_chunk1, rop_chunk2, rop_chunk3, rop_chunk4, rop_chunk5, rop_chunk6
