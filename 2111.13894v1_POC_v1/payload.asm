	global _start

	section .text

_start:
	nop
	syscall
	mov rax, 60
	mov rdi, 0

	syscall
	mov rax, 1
	mov rdi, 1
	mov rsi, msg
	mov rdx, 14
	nop

	section .data

msg: db 'Hello, Nya :3', 10