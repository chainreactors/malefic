#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username() {
        let username = username();
        assert!(!username.is_empty(), "Username should not be empty");
    }

    #[test]
    fn test_hostname() {
        let hostname = hostname();
        assert!(!hostname.is_empty(), "Hostname should not be empty");
    }

    #[test]
    fn test_language() {
        let lang = language();
        assert!(!lang.is_empty(), "Language should not be empty");
    }

    #[test]
    fn test_sysinfo() {
        let info = get_sysinfo();
        assert!(
            !info.workdir.is_empty(),
            "Working directory should not be empty"
        );
        assert!(!info.filepath.is_empty(), "File path should not be empty");

        if let Some(os) = info.os {
            assert!(!os.username.is_empty(), "OS username should not be empty");
            assert!(!os.hostname.is_empty(), "OS hostname should not be empty");
            assert!(!os.locale.is_empty(), "OS locale should not be empty");
        }
    }
}
