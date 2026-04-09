; direct_syscall.asm - MASM syntax for ml64.exe
; Direct syscall stubs for NtAllocateVirtualMemory, NtWriteVirtualMemory,
; NtCreateThreadEx, NtWaitForSingleObject

.CODE

_NtAllocateVirtualMemory_stub PROC
    mov r10, rcx
    mov eax, 018h
    syscall
    ret
_NtAllocateVirtualMemory_stub ENDP

_NtWriteVirtualMemory_stub PROC
    mov r10, rcx
    mov eax, 03Ah
    syscall
    ret
_NtWriteVirtualMemory_stub ENDP

_NtCreateThreadEx_stub PROC
    mov r10, rcx
    mov eax, 0C7h
    syscall
    ret
_NtCreateThreadEx_stub ENDP

_NtWaitForSingleObject_stub PROC
    mov r10, rcx
    mov eax, 04h
    syscall
    ret
_NtWaitForSingleObject_stub ENDP

END
