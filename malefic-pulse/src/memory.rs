pub unsafe fn zero(memory: *mut u8, length: u32) {
    for i in 0..length {
        *memory.offset(i as isize) = 0;
    }
}

pub unsafe fn copy(destination: *mut u8, source: *const u8, length: u32) -> *mut u8 {
    for i in 0..length {
        *destination.offset(i as isize) = *source.offset(i as isize);
    }
    destination
}

pub unsafe fn compare(memory1: *const u8, memory2: *const u8, length: usize) -> u32 {
    let mut a = memory1;
    let mut b = memory2;
    let mut len = length;

    while len > 0 {
        let val1 = *a;
        let val2 = *b;

        if val1 != val2 {
            return (val1 as i32 - val2 as i32) as u32;
        }

        a = a.offset(1);
        b = b.offset(1);
        len -= 1;
    }

    0
}

pub unsafe fn symbol<T>(s: *const u8) -> T {
    let rip_data = external_rip_data();
    let offset = (s as usize).wrapping_sub(rip_data_fn_addr() as usize);
    let absolute_addr = rip_data.wrapping_sub(offset);

    core::mem::transmute_copy(&absolute_addr)
}

fn rip_data_fn_addr() -> usize {
    crate::RipData as usize
}

fn external_rip_data() -> usize {
    unsafe { crate::RipData() }
}

// Compiler intrinsics required by no_std builds (-nostdlib)
#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, val: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = val as u8;
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let diff = *s1.add(i) as i32 - *s2.add(i) as i32;
        if diff != 0 {
            return diff;
        }
        i += 1;
    }
    0
}

#[macro_export]
macro_rules! range_head_list {
    ($head_list:expr, $type:ty, |$current:ident| $body:block) => {{
        let head_ptr = $head_list as *const LIST_ENTRY;
        let mut $current = (*head_ptr).Flink as $type;

        while $current as *const _ != head_ptr as *const _ {
            $body
            $current = (*$current).InLoadOrderLinks.Flink as $type;
        }
    }};
}
