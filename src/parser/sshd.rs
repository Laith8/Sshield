use std::{net::IpAddr, path::Path, sync::{LazyLock, OnceLock}};
use crate::parser::entry::LoginEvent;
use std::fs;
use regex::{Regex, RegexSet, RegexSetBuilder};
use crate::source::event::RawLoginEntry;
use std::str::FromStr;
use crate::parser::regex::;

static REGEX_ACCEPTED: OnceLock<RegexSet> = OnceLock::new();
static REGEX_IGNORED: OnceLock<RegexSet> = OnceLock::new();
static REGEX_FAILED: OnceLock<RegexSet> = OnceLock::new();

static REGEX_IP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)[0-9a-f:.]+").unwrap());
static REGEX_PORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bport\s+([0-9]{1,5})\b").unwrap());
static USER_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // Failed password, publickey, keyboard-interactive, etc.
        r"Failed \S+ for (?:invalid user )?(\S+?) from\b",
        // Authentication failures.
        r"[aA]uthentication (?:failure|error|failed) for (.+?) (?:from\b|$)",
        // Unknown user.
        r"User not known to the underlying authentication module for (.+?) (?:from\b|$)",
        // Invalid / illegal user.
        r"[iI](?:llegal|nvalid) user (\S+)",
        // User not allowed.
        r"User (\S+).*? not allowed because ",
        // PAM authentication failure.
        r"\buser=(\S+)",
        // Maximum authentication attempts exceeded.
        r"maximum authentication attempts exceeded for (?:invalid user )?(.+?) (?:from\b|$)",
        // Disconnecting / disconnected users.
        r"(?:Disconnecting|Disconnected)(?: from)? (?:invalid|authenticating) user (\S+)",
        // Too many authentication failures.
        r"Too many authentication failures for (\S+)",
        // Successful login.
        r"Accepted \S+ for (\S+) from\b",
        // Root login refused. please leave this at the end.
        r"ROOT LOGIN REFUSED FROM\b",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

#[derive(serde::Deserialize)]
struct RegexConfig {
    regex: RegexCategory
}

#[derive(serde::Deserialize)]
struct RegexCategory {
    ban: Vec<String>,
    ignore: Vec<String>,
    accept: Vec<String>
}

pub struct SshdParser;

impl SshdParser {
    pub fn new() -> Self { Self }
    pub fn parse(message) -> 
}

//struct SshdParser {
//    login_accepted: &'static RegexSet,
//    login_ignored: &'static RegexSet,
//    login_failed: &'static RegexSet
//}
//
//impl SshdParser {
//    pub fn from<T: AsRef<Path>>(config_path: T) -> Result<Self, &'static str> {
//        let file = fs::read_to_string(config_path).map_err(|_| "Error opening config file")?;
//        let regex_config: RegexConfig = toml::from_str(&file).map_err(|_| "Error reading config")?;
//
//        let login_accepted_set = RegexSetBuilder::new(regex_config.regex.accept)
//            .build()
//            .map_err(|_| "Error parsing regexes")?;
//        let login_accepted = REGEX_ACCEPTED.get_or_init(|| {
//            login_accepted_set
//        });
//        let login_ignored_set = RegexSetBuilder::new(regex_config.regex.ignore)
//            .build()
//            .map_err(|_| "Error parsing regexes")?;
//        let login_ignored = REGEX_IGNORED.get_or_init(|| {
//            login_ignored_set
//        });
//        let login_failed_set = RegexSetBuilder::new(regex_config.regex.ban)
//            .build()
//            .map_err(|_| "Error parsing regexes")?;
//        let login_failed = REGEX_FAILED.get_or_init(|| {
//            login_failed_set
//        });
//        Ok(
//            Self { login_accepted, login_ignored, login_failed }
//        )
//    }
//
//    pub fn parse(&self, entry: RawLoginEntry) -> LoginEvent {
//        let message = &entry.message;
//        if self.login_accepted.is_match(message) {
//            todo!()
//        } else if self.login_failed.is_match(message) {
//            todo!()
//        } else if self.login_failed.is_match(message) {
//            todo!()
//        } else {
//            LoginEvent::Unparseable(entry)
//        }
//    }
//
//    
//
//
//pub fn get_ip(input: &str) -> Option<IpAddr> {
//    let re = Regex::new(r"(?i)[0-9a-f:.]+").unwrap();
//
//    re.find_iter(input).find_map(|m| {
//        let before = input[..m.start()].chars().next_back();
//        let after = input[m.end()..].chars().next();
//
//        if before.is_some_and(|c| c.is_ascii_alphanumeric())
//            || after.is_some_and(|c| c.is_ascii_alphanumeric())
//        {
//            return None;
//        }
//
//        IpAddr::from_str(m.as_str().trim_end_matches('.')).ok()
//    })
//}
//
//    pub fn get_user(input: &str) -> Option<String> {
//        let patterns = [
//            r"Failed \S+ for (?:invalid user )?([^\s,;]+)",
//            r"[aA]uthentication (?:failure|error|failed) for ([^\s,;]+)",
//            r"User not known to the underlying authentication module for ([^\s,;]+)",
//            r"[iI](?:llegal|nvalid) user ([^\s,;]+)",
//            r"User ([^\s,;]+).*? not allowed because ",
//            r"\buser=([^\s,;]+)",
//            r"maximum authentication attempts exceeded for (?:invalid user )?([^\s,;]+)",
//            r"(?:Disconnecting|Disconnected)(?: from)? (?:invalid|authenticating) user ([^\s,;]+)",
//            r"Too many authentication failures for ([^\s,;]+)",
//            r"Accepted \S+ for ([^\s,;]+)",
//        ];
//
//        for pattern in patterns {
//            let re = Regex::new(pattern).unwrap();
//
//            if let Some(captures) = re.captures(input) {
//                if let Some(username) = captures.get(1) {
//                    return Some(username.as_str().to_string());
//                }
//            }
//        }
//
//        if input.contains("ROOT LOGIN REFUSED FROM") {
//            return Some("root".to_string());
//        }
//
//        None
//    }
//
//
//    pub fn get_ip(input: &str) -> Option<IpAddr> {
//        let re = Regex::new(r"(?i)[0-9a-f:.]+").unwrap();
//
//        re.find_iter(input).find_map(|m| {
//            let before = input[..m.start()].chars().next_back();
//            let after = input[m.end()..].chars().next();
//
//            if before.is_some_and(|c| c.is_ascii_alphanumeric())
//                || after.is_some_and(|c| c.is_ascii_alphanumeric())
//            {
//                return None;
//            }
//
//            IpAddr::from_str(m.as_str().trim_end_matches('.')).ok()
//        })
//    }
//
//}