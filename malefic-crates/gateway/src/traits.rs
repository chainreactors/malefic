/// Trait for types that can be obfuscated at the field level.
/// Implemented automatically by `#[derive(ObfuscateBox)]`.
pub trait ObfuscatedField<T> {
    /// Encrypt a value into its obfuscated representation.
    fn obfuscate(value: T) -> Self;
    /// Decrypt the obfuscated representation back to the original value.
    fn deobfuscate(&self) -> T;
}

/// Trait for structs whose fields can be XOR-toggled in-place for memory obfuscation.
///
/// # Safety
/// After toggle, struct fields contain invalid data (String is not valid UTF-8, etc.).
/// Must use `Encrusted<T>` wrapper to ensure fields are not accessed while toggled.
pub unsafe trait Obfuscatable {
    /// XOR-toggle all fields in-place using the provided PRNG for key stream.
    /// Calling twice with the same seed restores original values.
    unsafe fn toggle_obfuscate(&mut self, rng: &mut nanorand::WyRand);
}
