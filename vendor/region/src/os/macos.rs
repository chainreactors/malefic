use crate::{Error, Protection, Region, Result};
use mach2::vm_prot::*;

pub struct QueryIter {
  region_address: mach2::vm_types::mach_vm_address_t,
  upper_bound: usize,
}

impl QueryIter {
  pub fn new(origin: *const (), size: usize) -> Result<QueryIter> {
    Ok(QueryIter {
      region_address: origin as _,
      upper_bound: (origin as usize).saturating_add(size),
    })
  }

  pub fn upper_bound(&self) -> usize {
    self.upper_bound
  }
}

impl Iterator for QueryIter {
  type Item = Result<Region>;

  fn next(&mut self) -> Option<Self::Item> {
    // The possible memory share modes
    const SHARE_MODES: [u8; 3] = [
      mach2::vm_region::SM_SHARED,
      mach2::vm_region::SM_TRUESHARED,
      mach2::vm_region::SM_SHARED_ALIASED,
    ];

    // Check if the search area has been passed
    if self.region_address as usize >= self.upper_bound {
      return None;
    }

    let mut region_size: mach2::vm_types::mach_vm_size_t = 0;

    let mut info: mach2::vm_region::vm_region_submap_info_64 =
      mach2::vm_region::vm_region_submap_info_64::default();

    let mut depth = u32::MAX;
    let result = unsafe {
      mach2::vm::mach_vm_region_recurse(
        mach2::traps::mach_task_self(),
        &mut self.region_address,
        &mut region_size,
        &mut depth,
        (&mut info as *mut _) as mach2::vm_region::vm_region_recurse_info_t,
        &mut mach2::vm_region::vm_region_submap_info_64::count(),
      )
    };

    match result {
      // The end of the process' address space has been reached
      mach2::kern_return::KERN_INVALID_ADDRESS => None,
      mach2::kern_return::KERN_SUCCESS => {
        // The returned region may have a different address than the request
        if self.region_address as usize >= self.upper_bound {
          return None;
        }

        let region = Region {
          base: self.region_address as *const _,
          guarded: (info.user_tag == mach2::vm_statistics::VM_MEMORY_GUARD),
          protection: Protection::from_native(info.protection),
          max_protection: Protection::from_native(info.max_protection),
          shared: SHARE_MODES.contains(&info.share_mode),
          size: region_size as usize,
          ..Default::default()
        };

        self.region_address = self.region_address.saturating_add(region_size);
        Some(Ok(region))
      }
      _ => Some(Err(Error::MachCall(result))),
    }
  }
}

impl Protection {
  fn from_native(protection: vm_prot_t) -> Self {
    const MAPPINGS: &[(vm_prot_t, Protection)] = &[
      (VM_PROT_READ, Protection::READ),
      (VM_PROT_WRITE, Protection::WRITE),
      (VM_PROT_EXECUTE, Protection::EXECUTE),
    ];

    MAPPINGS
      .iter()
      .filter(|(flag, _)| protection & *flag == *flag)
      .fold(Protection::NONE, |acc, (_, prot)| acc | *prot)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn protection_flags_are_mapped_from_native() {
    let rw = VM_PROT_READ | VM_PROT_WRITE;
    let rwx = rw | VM_PROT_EXECUTE;

    assert_eq!(Protection::from_native(0), Protection::NONE);
    assert_eq!(Protection::from_native(VM_PROT_READ), Protection::READ);
    assert_eq!(Protection::from_native(rw), Protection::READ_WRITE);
    assert_eq!(Protection::from_native(rwx), Protection::READ_WRITE_EXECUTE);
  }
}
