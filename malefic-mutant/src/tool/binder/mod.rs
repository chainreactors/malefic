pub mod embed;
pub mod metadata;

pub use embed::{bind, check, extract};

#[allow(unused_imports)]
pub use embed::extract_primary;
#[allow(unused_imports)]
pub use metadata::BinderMetadata;
