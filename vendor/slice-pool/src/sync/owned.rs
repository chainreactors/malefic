use super::ChunkChain;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::{fmt, mem, slice};

/// Interface for any slice compatible with a thread-safe `SlicePool`.
pub trait Sliceable<T>: Send + Sync + AsMut<[T]> + AsRef<[T]> {}

/// Implements the trait for vectors and similar types.
impl<T, V> Sliceable<T> for V
where
  T: Send,
  V: Send + Sync + AsRef<[T]> + AsMut<[T]>,
{
}

/// A thread-safe interface for allocating chunks in an owned slice.
pub struct SlicePool<T: Send> {
  chain: Arc<ChunkChain>,
  slice: Arc<Sliceable<T>>,
}

impl<T: Send + 'static> SlicePool<T> {
  /// Constructs a new owned slice pool from a sliceable object.
  pub fn new<S: Sliceable<T> + 'static>(slice: S) -> Self {
    let size = slice.as_ref().len();

    SlicePool {
      chain: Arc::new(ChunkChain::new(size)),
      slice: Arc::new(slice),
    }
  }

  /// Allocates a new slice from the pool.
  pub fn alloc(&self, size: usize) -> Option<SliceBox<T>> {
    let chunk = self.chain.allocate(size)?;

    // The following code uses unsafe, and is the only occurring instance of it.
    // Since the 'SliceBox' is a self-referential type, Rust does not allow us
    // to express this with its current lifetime semantics. To avoid this
    // restriction, the slice is transmuted to a static and mutable slice. It
    // can be treated as static, since it's next to the 'Arc', which is keeping
    // the data alive. It can also be treated as mutable since the 'SliceBox'
    // becomes the only way to access the slice.
    let data: &'static mut [T] = unsafe {
      let offset = chunk.offset as isize;
      let base = (*self.slice).as_ref().as_ptr().offset(offset);
      slice::from_raw_parts_mut(base as *mut _, size)
    };

    Some(SliceBox {
      chain: self.chain.clone(),
      slice: self.slice.clone(),
      data,
    })
  }

  /// Returns the address of the underlying slice.
  pub fn as_ptr(&self) -> *const T {
    (*self.slice).as_ref().as_ptr()
  }

  /// Returns the size of the underlying slice.
  pub fn len(&self) -> usize {
    (*self.slice).as_ref().len()
  }
}

/// An allocation in an owned `SlicePool`.
pub struct SliceBox<T: Send + 'static> {
  #[allow(unused)]
  slice: Arc<Sliceable<T>>,
  chain: Arc<ChunkChain>,
  data: &'static mut [T],
}

impl<T: Send> Deref for SliceBox<T> {
  type Target = [T];

  fn deref(&self) -> &Self::Target {
    &self.data
  }
}

impl<T: Send> DerefMut for SliceBox<T> {
  fn deref_mut<'b>(&'b mut self) -> &'b mut [T] {
    self.data
  }
}

impl<T: Send> Drop for SliceBox<T> {
  /// Returns the ownership of the slice to the pool.
  fn drop(&mut self) {
    let base = (*self.slice).as_ref().as_ptr();
    let diff = (self.data.as_ptr() as isize).wrapping_sub(base as isize);
    self.chain.release(diff as usize / mem::size_of::<T>())
  }
}

impl<T: Send + fmt::Debug> fmt::Debug for SliceBox<T> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{:?}", self.deref())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Arc;
  use std::thread;

  #[test]
  fn pool_owned_lifetime() {
    let alloc = {
      let values = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
      let memory = SlicePool::new(values);

      let alloc = {
        let alloc = memory.alloc(2).unwrap();
        assert_eq!(*alloc, [10, 20]);
        {
          let alloc = memory.alloc(5).unwrap();
          assert_eq!(*alloc, [30, 40, 50, 60, 70]);
        }

        let alloc = memory.alloc(1).unwrap();
        assert_eq!(*alloc, [30]);
        alloc
      };
      assert_eq!(*alloc, [30]);
      alloc
    };
    assert_eq!(*alloc, [30]);
  }

  #[test]
  fn pool_owned_thread() {
    let storage = SlicePool::new(vec![10, 20, 30, 40]);
    let pool = Arc::new(storage);

    let val = pool.alloc(2).unwrap();
    assert_eq!(*val, [10, 20]);

    let pool2 = pool.clone();
    thread::spawn(move || {
      let val = pool2.alloc(2).unwrap();
      assert_eq!(*val, [30, 40]);
    }).join()
    .unwrap();

    assert_eq!(pool.len(), 4);
  }

  #[test]
  fn pool_fragmentation() {
    let pool = SlicePool::new(vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);

    let val1 = pool.alloc(2).unwrap();
    assert_eq!(*val1, [10, 20]);

    let val2 = pool.alloc(4).unwrap();
    assert_eq!(*val2, [30, 40, 50, 60]);

    let val3 = pool.alloc(2).unwrap();
    assert_eq!(*val3, [70, 80]);

    // By dropping this allocation, a fragmentation occurs.
    mem::drop(val2);

    let val4 = pool.alloc(2).unwrap();
    assert_eq!(*val4, [90, 100]);

    let val5 = pool.alloc(4).unwrap();
    assert_eq!(*val5, [30, 40, 50, 60]);
  }
}
