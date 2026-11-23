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