use crate::{Error, Protection, Region, Result};
use std::cmp::{max, min};
use std::ffi::c_void;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::sync::Once;
use windows_sys::Win32::System::Memory::{
  VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualQuery, VirtualUnlock,
  MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE,
  PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
  PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOMBINE, PAGE_WRITECOPY,
};
use windows_sys::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};

pub struct QueryIter {
  region_address: usize,
  upper_bound: usize,
}

impl QueryIter {
  pub fn new(origin: *const (), size: usize) -> Result<QueryIter> {
    let system = system_info();

    Ok(QueryIter {
      region_address: max(origin as usize, system.lpMinimumApplicationAddress as usize),
      upper_bound: min(
        (origin as usize).saturating_add(size),
        system.lpMaximumApplicationAddress as usize,
      ),
    })
  }

  pub fn upper_bound(&self) -> usize {
    self.upper_bound
  }
}

impl Iterator for QueryIter {
  type Item = Result<Region>;

  fn next(&mut self) -> Option<Self::Item> {
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    while self.region_address < self.upper_bound {
      let bytes = unsafe {
        VirtualQuery(
          self.region_address as *mut c_void,
          &mut info,
          size_of::<MEMORY_BASIC_INFORMATION>(),
        )
      };

      if bytes == 0 {
        return Some(Err(Error::SystemCall(io::Error::last_os_error())));
      }

      self.region_address = (info.BaseAddress as usize).saturating_add(info.RegionSize);

      // Only mapped memory regions are of interest
      if info.State == MEM_RESERVE || info.State == MEM_COMMIT {
        let mut region = Region {
          base: info.BaseAddress as *const _,
          reserved: info.State != MEM_COMMIT,
          guarded: (info.Protect & PAGE_GUARD) != 0,
          shared: (info.Type & MEM_PRIVATE) == 0,
          size: info.RegionSize as usize,
          ..Default::default()
        };

        if region.is_committed() {
          region.protection = Protection::from_native(info.Protect);
        }

        return Some(Ok(region));
      }
    }

    None
  }
}

pub fn page_size() -> usize {
  system_info().dwPageSize as usize
}

pub unsafe fn alloc(base: *const (), size: usize, protection: Protection) -> Result<*const ()> {
  let allocation = VirtualAlloc(
    base as *mut c_void,
    size,
    MEM_COMMIT | MEM_RESERVE,
    protection.to_native(),
  );

  if allocation.is_null() {
    return Err(Error::SystemCall(io::Error::last_os_error()));
  }

  Ok(allocation as *const ())
}

pub unsafe fn free(base: *const (), _size: usize) -> Result<()> {
  match VirtualFree(base as *mut c_void, 0, MEM_RELEASE) {
    0 => Err(Error::SystemCall(io::Error::last_os_error())),
    _ => Ok(()),
  }
}

pub unsafe fn protect(base: *const (), size: usize, protection: Protection) -> Result<()> {
  let result = VirtualProtect(base as *mut c_void, size, protection.to_native(), &mut 0);

  if result == 0 {
    Err(Error::SystemCall(io::Error::last_os_error()))
  } else {
    Ok(())
  }
}

pub fn lock(base: *const (), size: usize) -> Result<()> {
  let result = unsafe { VirtualLock(base as *mut c_void, size) };

  if result == 0 {
    Err(Error::SystemCall(io::Error::last_os_error()))
  } else {
    Ok(())
  }
}

pub fn unlock(base: *const (), size: usize) -> Result<()> {
  let result = unsafe { VirtualUnlock(base as *mut c_void, size) };

  if result == 0 {
    Err(Error::SystemCall(io::Error::last_os_error()))
  } else {
    Ok(())
  }
}

fn system_info() -> &'static SYSTEM_INFO {
  static INIT: Once = Once::new();
  static mut INFO: MaybeUninit<SYSTEM_INFO> = MaybeUninit::uninit();

  unsafe {
    INIT.call_once(|| GetNativeSystemInfo(INFO.as_mut_ptr()));
    &*INFO.as_ptr()
  }
}

impl Protection {
  fn from_native(protection: u32) -> Self {
    // Ignore unsupported flags (TODO: Preserve this information?)
    let ignored = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;

    match protection & !ignored {
      PAGE_EXECUTE => Protection::EXECUTE,
      PAGE_EXECUTE_READ => Protection::READ_EXECUTE,
      PAGE_EXECUTE_READWRITE => Protection::READ_WRITE_EXECUTE,
      PAGE_EXECUTE_WRITECOPY => Protection::READ_WRITE_EXECUTE,
      PAGE_NOACCESS => Protection::NONE,
      PAGE_READONLY => Protection::READ,
      PAGE_READWRITE => Protection::READ_WRITE,
      PAGE_WRITECOPY => Protection::READ_WRITE,
      _ => unreachable!("Protection: 0x{:X}", protection),
    }
  }

  pub(crate) fn to_native(self) -> u32 {
    match self {
      Protection::NONE => PAGE_NOACCESS,
      Protection::READ => PAGE_READONLY,
      Protection::EXECUTE => PAGE_EXECUTE,
      Protection::READ_EXECUTE => PAGE_EXECUTE_READ,
      Protection::READ_WRITE => PAGE_READWRITE,
      Protection::READ_WRITE_EXECUTE => PAGE_EXECUTE_READWRITE,
      Protection::WRITE_EXECUTE => PAGE_EXECUTE_READWRITE,
      _ => unreachable!("Protection: {:?}", self),
    }
  }
}
