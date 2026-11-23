use std::net::IpAddr;
use crate::source::event::RawLoginEntry;
use crate::parser::regex::{REGEX_ACCEPTED, REGEX_FAILED, REGEX_IGNORED, REGEX_IP};
use std::str::FromStr;

#[derive(Debug)]
#[allow(dead_code)]
pub enum LoginEvent {
    AcceptedLogin(LoginEntry),
    FailedLogin(LoginEntry),
    IgnoredLogin,
    Unparseable
}

#[derive(Debug)]
#[allow(dead_code)]
/// timestamp in microseconds
pub struct LoginEntry {
    ip: Option<IpAddr>,
    timestamp: i64,
}

impl LoginEvent {
    pub fn from_raw_login_entry(entry: RawLoginEntry) -> LoginEvent {
        let message = &entry.message;

        let login_entry = LoginEntry::from_raw_login_entry(&entry);

        if REGEX_ACCEPTED.is_match(message) {
            LoginEvent::AcceptedLogin(login_entry)
        } else if REGEX_FAILED.is_match(message) {
             LoginEvent::FailedLogin(login_entry)
        } else if REGEX_IGNORED.is_match(message) {
             LoginEvent::IgnoredLogin
        } else {
            LoginEvent::Unparseable
        }
    }

    
}

impl LoginEntry {
    fn from_raw_login_entry(entry: &RawLoginEntry) -> Self {
        LoginEntry {
            ip: Self::get_ip(&entry.message),
            timestamp: entry.timestamp
        }
    }

    fn get_ip(input: &str) -> Option<IpAddr> {
        REGEX_IP.find_iter(input).find_map(|m| {
            let before = input[..m.start()].chars().next_back();
            let after = input[m.end()..].chars().next();

            if before.is_some_and(|c| c.is_ascii_alphanumeric())
                || after.is_some_and(|c| c.is_ascii_alphanumeric())
            {
                return None;
            }

            let candidate = m.as_str().trim_end_matches('.');

            let candidate = candidate
                .split_once(':')
                .filter(|(ip, port)| {
                    ip.contains('.')
                        && port.chars().all(|c| c.is_ascii_digit())
                })
                .map_or(candidate, |(ip, _)| ip);

            IpAddr::from_str(candidate).ok()
        })
    }
}