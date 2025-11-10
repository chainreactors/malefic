pub mod extract;
pub mod inject;
pub mod remove;

pub use extract::SignatureExtractor;
pub use inject::SignatureInjector;
pub use remove::SignatureRemover;

pub mod error;
