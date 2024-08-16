mod spite;
mod beacon;

pub use spite::Spite as Spite;
// pub use spite::TRANSPORT_TYPE_SPITE as TRANSPORT_TYPE_SPITE;

cfg_if::cfg_if!{
    if #[cfg(feature = "beacon")] {
        pub use beacon::BeaconBase as Meta;
    }
}