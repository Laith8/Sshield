use std::{path::Path, sync::OnceLock};
use crate::parser::entry::LoginEvent;
use std::fs;
use regex::{RegexSet, RegexSetBuilder};

static REGEX_ACCEPTED: OnceLock<RegexSet> = OnceLock::new();
static REGEX_IGNORED: OnceLock<RegexSet> = OnceLock::new();
static REGEX_FAILED: OnceLock<RegexSet> = OnceLock::new();

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

struct SshdParser {
    login_accepted: &'static RegexSet,
    login_ignored: &'static RegexSet,
    login_failed: &'static RegexSet
}

impl SshdParser {
    fn from<T: AsRef<Path>>(config_path: T) -> Result<Self, &'static str> {
        let file = fs::read_to_string(config_path).map_err(|_| "Error opening config file")?;
        let regex_config: RegexConfig = toml::from_str(&file).map_err(|_| "Error reading config")?;

        let login_accepted_set = RegexSetBuilder::new(regex_config.regex.accept)
            .build()
            .map_err(|_| "Error parsing regexes")?;
        let login_accepted = REGEX_ACCEPTED.get_or_init(|| {
            login_accepted_set
        });
        let login_ignored_set = RegexSetBuilder::new(regex_config.regex.ignore)
            .build()
            .map_err(|_| "Error parsing regexes")?;
        let login_ignored = REGEX_IGNORED.get_or_init(|| {
            login_ignored_set
        });
        let login_failed_set = RegexSetBuilder::new(regex_config.regex.ban)
            .build()
            .map_err(|_| "Error parsing regexes")?;
        let login_failed = REGEX_FAILED.get_or_init(|| {
            login_failed_set
        });
        Ok(
            Self { login_accepted, login_ignored, login_failed }
        )
    }

    fn parse(&self) -> LoginEvent {
        todo!()
    }
}

// multiple regexes - make a test impl for each group