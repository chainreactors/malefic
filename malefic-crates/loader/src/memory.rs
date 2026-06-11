use malefic_common::errors::CommonError;
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct MaleficMemManager {
    mems: BTreeMap<usize, MaleficChunk>,
    next_id: usize,
}

impl MaleficMemManager {
    pub fn default() -> Self {
        Self {
            mems: BTreeMap::new(),
            next_id: 0,
        }
    }

    pub unsafe fn alloc(&mut self, size: usize) -> Result<usize, ()> {
        let mem = MaleficChunk::new(size).map_err(|_| ())?;
        let id = self.next_id;
        self.next_id += 1;
        self.mems.insert(id, mem);
        Ok(id)
    }

    pub unsafe fn remove(&mut self, id: usize) -> Result<(), ()> {
        if let Some(mut mem) = self.mems.remove(&id) {
            let _ = mem.delete();
            Ok(())
        } else {
            Err(())
        }
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
    handle: *const core::ffi::c_void,
}

pub fn malloc_and_set_memory(shellcode: Vec<u8>) -> Result<MaleficChunk, CommonError> {
    let size = shellcode.len();
    let memory = MaleficChunk::new(size)?;
    memory.set_mem(shellcode.as_ptr() as *const core::ffi::c_void);
    let _ = memory.set_protect_exec()?;
    Ok(memory)
}

impl MaleficChunk {
    pub fn get_ptr(&self) -> *mut core::ffi::c_void {
        self.ptr
    }

    pub fn get_size(&self) -> usize {
        self.size
    }

    pub fn new_fd(size: usize, fd: i64) -> Result<Self, CommonError> {
        if fd.is_negative() || size.eq(&0) {
            return Err(CommonError::AllocationFailed);
        }
        #[cfg(target_os = "linux")]
        {
            let ptr = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE,
                    fd as i32,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(CommonError::AllocationFailed);
            }
            return Ok(Self {
                ptr,
                size,
                handle: core::ptr::null(),
            });
        }
        #[cfg(target_os = "macos")]
        {
            todo!()
        }
        #[allow(unreachable_code)]
        Ok(Self {
            ptr: core::ptr::null_mut(),
            size: 0,
            handle: core::ptr::null(),
        })
    }

    #[allow(unused_variables)]
    pub fn new(size: usize) -> Result<Self, CommonError> {
        #[cfg(target_os = "linux")]
        {
            let ptr = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(CommonError::AllocationFailed);
            }
            return Ok(Self {
                ptr,
                size,
                handle: core::ptr::null(),
            });
        }
        #[cfg(target_os = "macos")]
        {
            todo!()
        }
        #[allow(unreachable_code)]
        Ok(Self {
            ptr: core::ptr::null_mut(),
            size: 0,
            handle: core::ptr::null(),
        })
    }

    #[allow(unused_variables)]
    pub fn set_protect(&self, prot: u32) -> Result<(), CommonError> {
        #[cfg(target_os = "linux")]
        unsafe {
            if libc::mprotect(self.ptr, self.size, prot as libc::c_int) != 0 {
                return Err(CommonError::AllocationFailed);
            }
        }
        Ok(())
    }

    pub fn set_protect_exec(&self) -> Result<(), CommonError> {
        #[cfg(target_os = "linux")]
        unsafe {
            if libc::mprotect(self.ptr, self.size, libc::PROT_EXEC) != 0 {
                return Err(CommonError::AllocationFailed);
            }
        }
        Ok(())
    }

    #[allow(unused_variables)]
    pub fn delete(&mut self) -> Result<(), CommonError> {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                let ret = libc::munmap(self.ptr, self.size);
                if ret < 0 {
                    return Err(CommonError::FreeFailed);
                }
                return Ok(());
            }
        }
        #[allow(unreachable_code)]
        Ok(())
    }

    pub fn set_mem(&self, ptr: *const core::ffi::c_void) {
        unsafe {
            std::ptr::copy(ptr, self.ptr, self.size);
        }
    }
}
