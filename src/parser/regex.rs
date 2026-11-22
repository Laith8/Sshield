use std::sync::LazyLock;
use regex::{Regex,RegexSet};

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

fn read_config() -> RegexConfig {
    let file = std::fs::read_to_string("config.toml")
        .expect("Error opening config file");

    toml::from_str(&file)
        .expect("Error reading config")
}

pub static REGEX_ACCEPTED: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(read_config().regex.accept.clone())
        .expect("Error parsing accepted regexes")
});

pub static REGEX_IGNORED: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(read_config().regex.ignore.clone())
        .expect("Error parsing ignored regexes")
});

pub static REGEX_FAILED: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(read_config().regex.ban.clone())
        .expect("Error parsing failed regexes")
});

pub static REGEX_IP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)[0-9a-f:.]+").unwrap());
pub static REGEX_PORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bport\s+([0-9]{1,5})\b").unwrap());
pub static REGEX_USER: LazyLock<[Regex; 11]> = LazyLock::new(|| {
    [
        // Failed password, publickey, keyboard-interactive, etc.
        Regex::new(r"(?i)Failed \S+ for (?:invalid user )?([^\s,;]+) from\b").unwrap(),
        // Authentication failures.
        Regex::new(r"(?i)authentication (?:failure|error|failed) for ([^\s,;]+)(?:\s+from\b|$)").unwrap(),
        // Unknown user.
        Regex::new(r"(?i)User not known to the underlying authentication module for ([^\s,;]+)(?:\s+from\b|$)").unwrap(),
        // Invalid / illegal user.
        Regex::new(r"(?i)(?:illegal|invalid) user ([^\s,;]+)").unwrap(),
        // User not allowed.
        Regex::new(r"(?i)User ([^\s,;]+).*? not allowed because ").unwrap(),
        // PAM authentication failure.
        Regex::new(r"(?i)\buser=([^\s,;]+)").unwrap(),
        // Maximum authentication attempts exceeded.
        Regex::new(r"(?i)maximum authentication attempts exceeded for (?:invalid user )?([^\s,;]+)(?:\s+from\b|$)").unwrap(),
        // Disconnecting / disconnected users.
        Regex::new(r"(?i)(?:Disconnecting|Disconnected)(?: from)? (?:invalid|authenticating) user ([^\s,;]+)").unwrap(),
        // Too many authentication failures.
        Regex::new(r"(?i)Too many authentication failures for ([^\s,;]+)").unwrap(),
        // Successful login.
        Regex::new(r"(?i)Accepted \S+ for ([^\s,;]+) from\b").unwrap(),
        // Root login refused. pleaxse leave this last.
        Regex::new(r"(?i)ROOT LOGIN REFUSED FROM\b").unwrap(),
    ]
});