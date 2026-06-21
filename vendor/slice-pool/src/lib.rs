//! This crate provides functionality for using a sliceable type as the
//! underlying memory for a pool.
//!
//! The allocated memory can be a mutable slice of any type.
//!
//! ```
//! use slice_pool::sync::SlicePool;
//!
//! let values = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
//! let mut memory = SlicePool::new(values);
//! assert_eq!(memory.len(), 10);
//!
//! // Not enough memory available (only 10 elements)
//! assert!(memory.alloc(11).is_none());
//!
//! let mut first = memory.alloc(2).unwrap();
//! assert_eq!(*first, [10, 20]);
//! first[1] = 15;
//! assert_eq!(*first, [10, 15]);
//!
//! let mem2 = memory.alloc(5).unwrap();
//! assert_eq!(*mem2, [30, 40, 50, 60, 70]);
//! ```

pub mod sync;
pub mod unsync;

/// A chunk of memory inside a slice.
#[derive(Debug, Copy, Clone)]
struct Chunk {
  offset: usize,
  size: usize,
  free: bool,
}

impl Chunk {
  pub fn new(size: usize) -> Self {
    Self::with_offset(size, 0)
  }

  pub fn with_offset(size: usize, offset: usize) -> Self {
    Chunk {
      size,
      offset,
      free: true,
    }
  }
}
