use crate::kit::binding::DeleteSelf;

pub unsafe fn self_delete(stream: &str) {
    DeleteSelf(stream.as_ptr(), stream.len() as u32)
}
