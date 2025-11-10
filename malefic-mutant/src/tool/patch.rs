use anyhow::{anyhow, bail, Context, Result};
use clap::ValueEnum;
use std::fs;
use std::path::{Path, PathBuf};

const BLOCK_LEN: usize = 64;

#[derive(Clone, Debug, ValueEnum)]
pub enum PatchField {
    #[value(alias = "name")]
    Name,
    #[value(alias = "key")]
    Key,
    #[value(alias = "server_address", alias = "server")]
    ServerAddress,
}

impl PatchField {
    pub fn label(&self) -> &'static str {
        match self {
            PatchField::Name => "NAME",
            PatchField::Key => "KEY",
            PatchField::ServerAddress => "SERVER_ADDRESS",
        }
    }

    fn default_current(&self) -> Option<&'static str> {
        match self {
            PatchField::Name => Some("malefic"),
            PatchField::Key => Some("maliceofinternal"),
            PatchField::ServerAddress => Some("127.0.0.1:5001"),
        }
    }

    fn block_len(&self) -> usize {
        BLOCK_LEN
    }
}

pub struct PatchOptions<'a> {
    pub file: &'a str,
    pub field: PatchField,
    pub value: &'a str,
    pub value_is_hex: bool,
    pub current: Option<&'a str>,
    pub current_hex: Option<&'a str>,
    pub offset: Option<&'a str>,
    pub index: usize,
    pub output: Option<&'a str>,
    pub xor_key: &'a [u8],
}

pub struct PatchOutcome {
    pub offset: usize,
    pub output_path: PathBuf,
}

pub fn patch_binary(opts: &PatchOptions) -> Result<PatchOutcome> {
    let file_path = PathBuf::from(opts.file);
    let mut data = fs::read(&file_path)
        .with_context(|| format!("failed to read binary '{}'", file_path.display()))?;

    let new_plain = parse_value(opts.value, opts.value_is_hex)?;
    let block_len = opts.field.block_len();
    if new_plain.len() > block_len {
        bail!(
            "value for {} exceeds {} bytes (got {})",
            opts.field.label(),
            block_len,
            new_plain.len()
        );
    }
    let new_block = encode_block(&new_plain, block_len, opts.xor_key);

    let offset = if let Some(off) = opts.offset.as_ref() {
        parse_offset(off)?
    } else {
        let (current_bytes, source_desc) = determine_current_bytes(opts)?;
        let needle = encode_block(&current_bytes, block_len, opts.xor_key);
        let offsets = find_occurrences(&data, &needle);
        if offsets.is_empty() {
            bail!(
                "could not locate {} block for value '{}' in file of {} bytes",
                opts.field.label(),
                source_desc,
                data.len()
            );
        }
        let idx = opts.index;
        if idx >= offsets.len() {
            bail!(
                "requested index {} but only {} matches were found",
                idx,
                offsets.len()
            );
        }
        offsets[idx]
    };

    let end = offset
        .checked_add(block_len)
        .ok_or_else(|| anyhow!("offset overflow"))?;
    if end > data.len() {
        bail!(
            "offset 0x{:X} ({} decimal) + length {} exceeds file size {} bytes",
            offset,
            offset,
            block_len,
            data.len()
        );
    }

    data[offset..end].copy_from_slice(&new_block);

    let output_path = if let Some(out) = opts.output {
        PathBuf::from(out)
    } else {
        default_output_path(&file_path)
    };

    fs::write(&output_path, data)
        .with_context(|| format!("failed to write patched binary '{}'", output_path.display()))?;

    Ok(PatchOutcome {
        offset,
        output_path,
    })
}

fn determine_current_bytes(opts: &PatchOptions) -> Result<(Vec<u8>, String)> {
    if let Some(hex) = opts.current_hex.as_ref() {
        let bytes = parse_hex_like(hex)?;
        return Ok((bytes, hex.to_string()));
    }

    if let Some(current) = opts.current.as_ref() {
        let bytes = current.as_bytes().to_vec();
        return Ok((bytes, current.to_string()));
    }

    if let Some(default) = opts.field.default_current() {
        return Ok((default.as_bytes().to_vec(), default.to_string()));
    }

    bail!(
        "please provide --current or --current-hex or an explicit --offset when patching {}",
        opts.field.label()
    );
}

fn parse_value(input: &str, is_hex: bool) -> Result<Vec<u8>> {
    if is_hex {
        parse_hex_like(input)
    } else {
        Ok(input.as_bytes().to_vec())
    }
}

fn parse_hex_like(text: &str) -> Result<Vec<u8>> {
    let mut cleaned = String::new();
    for chunk in text.split(|c: char| c.is_whitespace() || c == ',') {
        if chunk.is_empty() {
            continue;
        }
        let chunk = chunk.strip_prefix("0x").unwrap_or(chunk);
        cleaned.push_str(chunk);
    }

    if cleaned.len() % 2 != 0 {
        bail!("hex input must have an even number of digits");
    }
    let bytes = hex::decode(cleaned).with_context(|| "failed to decode hex input")?;
    Ok(bytes)
}

fn encode_block(raw: &[u8], length: usize, xor_key: &[u8]) -> Vec<u8> {
    assert!(
        !xor_key.is_empty(),
        "xor_key must not be empty when encoding blocks"
    );
    let mut block = vec![0u8; length];
    for idx in 0..length {
        let key = xor_key[idx % xor_key.len()];
        block[idx] = if idx < raw.len() { raw[idx] ^ key } else { key };
    }
    block
}

fn find_occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }

    let mut positions = Vec::new();
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            positions.push(i);
        }
    }
    positions
}

fn parse_offset(text: &str) -> Result<usize> {
    let trimmed = text.trim();
    let value = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        usize::from_str_radix(hex, 16)?
    } else {
        trimmed.parse::<usize>()?
    };
    Ok(value)
}

fn default_output_path(original: &Path) -> PathBuf {
    let file_name = original
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "patched.bin".to_string());
    let patched_name = format!("{}.patched", file_name);
    let default_path = PathBuf::from(patched_name.clone());
    original
        .parent()
        .map(|p| p.join(patched_name))
        .unwrap_or(default_path)
}

/// Represents a single field patch operation
pub struct FieldPatch {
    pub field: PatchField,
    pub value: String,
    pub is_hex: bool,
    pub default_value: Option<String>,
}

/// Options for batch patching multiple fields
pub struct BatchPatchOptions {
    pub file: String,
    pub patches: Vec<FieldPatch>,
    pub output: Option<String>,
    pub xor_key: Vec<u8>,
}

pub struct BatchPatchOutcome {
    pub patched_fields: Vec<(PatchField, usize)>, // (field, offset)
    pub output_path: PathBuf,
}

/// Patch multiple fields in a single pass
pub fn batch_patch_binary(opts: &BatchPatchOptions) -> Result<BatchPatchOutcome> {
    if opts.patches.is_empty() {
        bail!("no fields specified for patching");
    }

    let file_path = PathBuf::from(&opts.file);
    let mut data = fs::read(&file_path)
        .with_context(|| format!("failed to read binary '{}'", file_path.display()))?;

    let mut patched_fields = Vec::new();
    let xor_key = &opts.xor_key;

    // Process each field patch
    for patch in &opts.patches {
        let new_plain = parse_value(&patch.value, patch.is_hex)?;
        let block_len = patch.field.block_len();

        if new_plain.len() > block_len {
            bail!(
                "value for {} exceeds {} bytes (got {})",
                patch.field.label(),
                block_len,
                new_plain.len()
            );
        }

        let new_block = encode_block(&new_plain, block_len, xor_key);

        // Use default current value to locate the block
        let default_current = patch
            .default_value
            .as_deref()
            .or_else(|| patch.field.default_current())
            .ok_or_else(|| anyhow!("no default value for {}", patch.field.label()))?;

        let current_bytes = default_current.as_bytes();
        let needle = encode_block(current_bytes, block_len, xor_key);
        let offsets = find_occurrences(&data, &needle);

        if offsets.is_empty() {
            bail!(
                "could not locate {} block for default value '{}' in file of {} bytes",
                patch.field.label(),
                default_current,
                data.len()
            );
        }

        // Use the first match
        let offset = offsets[0];
        let end = offset
            .checked_add(block_len)
            .ok_or_else(|| anyhow!("offset overflow"))?;

        if end > data.len() {
            bail!(
                "offset 0x{:X} ({} decimal) + length {} exceeds file size {} bytes",
                offset,
                offset,
                block_len,
                data.len()
            );
        }

        // Apply the patch
        data[offset..end].copy_from_slice(&new_block);
        patched_fields.push((patch.field.clone(), offset));
    }

    // Write the patched data
    let output_path = if let Some(out) = &opts.output {
        PathBuf::from(out)
    } else {
        default_output_path(&file_path)
    };

    fs::write(&output_path, data)
        .with_context(|| format!("failed to write patched binary '{}'", output_path.display()))?;

    Ok(BatchPatchOutcome {
        patched_fields,
        output_path,
    })
}
