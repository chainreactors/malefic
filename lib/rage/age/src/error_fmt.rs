//! Error formatting macros for age crate - simplified i18n-compatible implementation

/// Loads a localized age string (simplified version without i18n).
#[doc(hidden)]
#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        $crate::error_fmt::get_message($message_id)
    }};

    ($message_id:literal, $($name:ident = $value:expr),* $(,)?) => {{
        $crate::error_fmt::get_message_with_named_args($message_id, &[$((stringify!($name), &$value.to_string())),*])
    }};
}

/// age-localized version of the write! macro.
#[doc(hidden)]
#[macro_export]
macro_rules! wfl {
    ($f:ident, $message_id:literal) => {
        write!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($name:ident = $value:expr),* $(,)?) => {
        write!($f, "{}", $crate::fl!($message_id, $($name = $value),*))
    };
}

/// age-localized version of the writeln! macro.
#[doc(hidden)]
#[macro_export]
macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($name:ident = $value:expr),* $(,)?) => {
        writeln!($f, "{}", $crate::fl!($message_id, $($name = $value),*))
    };
}

/// Get a localized message by ID (simplified version without i18n).
#[doc(hidden)]
pub fn get_message(message_id: &str) -> String {
    match message_id {
        "err-failed-to-write-output" => format!("Failed to write output: {}", "{err}"),
        "err-no-identities-in-stdin" => "No identities found in standard input".to_string(),
        "err-no-identities-in-file" => format!("No identities found in file: {}", "{filename}"),
        "err-plugin-multiple" => "Multiple plugin errors occurred:".to_string(),
        "err-decryption-failed" => "Failed to decrypt file".to_string(),
        "err-header-invalid" => "Invalid header".to_string(),
        "err-header-mac-invalid" => "Invalid header MAC".to_string(),
        "err-key-decryption" => "Failed to decrypt key".to_string(),
        "err-no-matching-keys" => "No matching keys found".to_string(),
        "err-unknown-format" => "Unknown age format".to_string(),
        "err-missing-recipients" => "Missing recipients".to_string(),
        "err-mixed-recipient-passphrase" => {
            "Cannot combine passphrase encryption with other recipients".to_string()
        }
        "err-incompatible-recipients-oneway" => format!(
            "Recipients with labels {} are incompatible with other recipients",
            "{labels}"
        ),
        "err-incompatible-recipients-twoway" => format!(
            "Recipients with labels {} are incompatible with recipients with labels {}",
            "{left}", "{right}"
        ),
        "err-invalid-recipient-labels" => format!("Invalid recipient labels: {}", "{labels}"),
        "err-missing-plugin" => format!("Plugin {} not found", "{plugin_name}"),
        "rec-unknown-format" => {
            "This file was created by a newer version of age that we do not support.".to_string()
        }
        "rec-excessive-work" => format!(
            "This file would take {} seconds to decrypt on this device.",
            "{duration}"
        ),
        "rec-missing-plugin" => {
            "You may need to install additional software to decrypt this file.".to_string()
        }
        "err-identity-file-contains-plugin" => format!(
            "Identity file {} contains a plugin identity ({})",
            "{filename}", "{plugin_name}"
        ),
        "rec-identity-file-contains-plugin" => format!(
            "The {} plugin does not support converting identities to recipients.",
            "{plugin_name}"
        ),
        "encrypted-passphrase-prompt" => format!("Enter passphrase for {}", "{filename}"),
        "err-plugin-identity" => format!("Plugin {} error: {}", "{plugin_name}", "{message}"),
        "err-plugin-recipient" => format!(
            "Plugin {} recipient {} error: {}",
            "{plugin_name}", "{recipient}", "{message}"
        ),
        "err-excessive-work" => "This passphrase is very expensive to decrypt.".to_string(),
        "encrypted-warn-no-match" => {
            format!("Warning: could not decrypt identity in {}", "{filename}")
        }
        _ => message_id.to_string(),
    }
}

/// Get a localized message with named arguments (simplified version without i18n).
#[doc(hidden)]
pub fn get_message_with_named_args(message_id: &str, args: &[(&str, &str)]) -> String {
    let mut msg = get_message(message_id);
    for (name, value) in args {
        msg = msg.replace(&format!("{{{}}}", name), value);
    }
    msg
}

/// Get a localized message with arguments (simplified version without i18n).
#[doc(hidden)]
pub fn get_message_with_args<T: std::fmt::Display>(message_id: &str, args: &[T]) -> String {
    // This is a simplified implementation that doesn't handle complex argument replacement
    // For now, we'll just return the base message and append the args if needed
    let mut msg = get_message(message_id);
    if !args.is_empty() {
        let arg_strings: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        // Simple replacement for common patterns
        for (i, arg) in arg_strings.iter().enumerate() {
            match i {
                0 => {
                    msg = msg
                        .replace("{err}", arg)
                        .replace("{filename}", arg)
                        .replace("{plugin_name}", arg)
                        .replace("{labels}", arg)
                        .replace("{left}", arg)
                        .replace("{duration}", arg)
                }
                1 => msg = msg.replace("{plugin_name}", arg).replace("{right}", arg),
                _ => {}
            }
        }
    }
    msg
}

/// Helper function for backward compatibility
#[doc(hidden)]
pub(crate) fn error_string(message_id: &str) -> String {
    get_message(message_id)
}

/// Helper function for backward compatibility
#[doc(hidden)]
pub(crate) fn error_string_with_args<T: std::fmt::Display>(
    message_id: &str,
    args: &[(&str, T)],
) -> String {
    let mut msg = get_message(message_id);
    for (name, value) in args {
        msg = msg.replace(&format!("{{{}}}", name), &value.to_string());
    }
    msg
}

/// Formats an error message.
#[doc(hidden)]
#[macro_export]
macro_rules! fmt_err {
    ($message:literal) => {{
        $message
    }};

    ($message:literal, $($args:expr),* $(,)?) => {{
        format!($message, $($args),*)
    }};
}
