use crate::{Error, Protection, Result};
use libc::{MAP_ANON, MAP_FAILED, MAP_FIXED, MAP_PRIVATE};
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};
use std::io;

pub fn page_size() -> usize {
  unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

pub unsafe fn alloc(base: *const (), size: usize, protection: Protection) -> Result<*const ()> {
  let mut native_prot = protection.to_native();

  // This adjustment ensures that the behavior of memory allocation is
  // orthogonal across all platforms by aligning NetBSD's protection flags and
  // PaX behavior with those of other operating systems.
  if cfg!(target_os = "netbsd") {
    let max_protection = (PROT_READ | PROT_WRITE | PROT_EXEC) << 3;
    native_prot |= max_protection;
  }

  let mut flags = MAP_PRIVATE | MAP_ANON;

  if !base.is_null() {
    flags |= MAP_FIXED;
  }

  #[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
  if matches!(
    protection,
    Protection::WRITE_EXECUTE | Protection::READ_WRITE_EXECUTE
  ) {
    // On hardened context, MAP_JIT is necessary (on arm64) to allow W/X'ed regions.
    flags |= libc::MAP_JIT;
  }

  match libc::mmap(base as *mut _, size, native_prot, flags, -1, 0) {
    MAP_FAILED => Err(Error::SystemCall(io::Error::last_os_error())),
    address => Ok(address as *const ()),
  }
}

pub unsafe fn free(base: *const (), size: usize) -> Result<()> {
  match libc::munmap(base as *mut _, size) {
    0 => Ok(()),
    _ => Err(Error::SystemCall(io::Error::last_os_error())),
  }
}

pub unsafe fn protect(base: *const (), size: usize, protection: Protection) -> Result<()> {
  match libc::mprotect(base as *mut _, size, protection.to_native()) {
    0 => Ok(()),
    _ => Err(Error::SystemCall(io::Error::last_os_error())),
  }
}

pub fn lock(base: *const (), size: usize) -> Result<()> {
  match unsafe { libc::mlock(base.cast(), size) } {
    0 => Ok(()),
    _ => Err(Error::SystemCall(io::Error::last_os_error())),
  }
}

pub fn unlock(base: *const (), size: usize) -> Result<()> {
  match unsafe { libc::munlock(base.cast(), size) } {
    0 => Ok(()),
    _ => Err(Error::SystemCall(io::Error::last_os_error())),
  }
}

impl Protection {
  fn to_native(self) -> libc::c_int {
    // This is directly mapped to its native counterpart to allow users to
    // include non-standard flags with `Protection::from_bits_unchecked`.
    self.bits as libc::c_int
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use libc::PROT_NONE;

  #[test]
  fn protection_flags_match_unix_constants() {
    assert_eq!(Protection::NONE.bits, PROT_NONE as usize);
    assert_eq!(Protection::READ.bits, PROT_READ as usize);
    assert_eq!(Protection::WRITE.bits, PROT_WRITE as usize);
    assert_eq!(
      Protection::READ_WRITE_EXECUTE,
      Protection::from_bits_truncate((PROT_READ | PROT_WRITE | PROT_EXEC) as usize)
    );
  }

  #[test]
  fn protection_flags_are_mapped_to_native() {
    let rwx = PROT_READ | PROT_WRITE | PROT_EXEC;

    assert_eq!(Protection::NONE.to_native(), 0);
    assert_eq!(Protection::READ.to_native(), PROT_READ);
    assert_eq!(Protection::READ_WRITE.to_native(), PROT_READ | PROT_WRITE);
    assert_eq!(Protection::READ_WRITE_EXECUTE.to_native(), rwx);
  }
}
