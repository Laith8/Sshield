use std::net::IpAddr;
use crate::source::event::RawLoginEntry;
use crate::parser::regex::{REGEX_ACCEPTED, REGEX_FAILED, REGEX_IGNORED, REGEX_IP, REGEX_PORT, REGEX_USER};
use std::str::FromStr;

#[derive(Debug)]
pub enum LoginEvent {
    AcceptedLogin(LoginEntry),
    FailedLogin (LoginEntry),
    IgnoredLogin(LoginEntry),
    Unparseable(RawLoginEntry)
}

#[derive(Debug)]
/// timestamp in microseconds
pub struct LoginEntry {
    message: String,
    user: Option<String>,
    ip: Option<IpAddr>,
    port: Option<u16>,
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
             LoginEvent::IgnoredLogin(login_entry)
        } else {
            LoginEvent::Unparseable(entry)
        }
    }

    
}

impl LoginEntry {
    fn from_raw_login_entry(entry: &RawLoginEntry) -> Self {
        LoginEntry {
            message: entry.message.clone(),
            user: Self::get_user(&entry.message),
            ip: Self::get_ip(&entry.message),
            port: Self::get_port(&entry.message),
            timestamp: entry.timestamp
        }
    }

    fn get_port(message: &str) -> Option<u16> {
        let captures = REGEX_PORT.captures(message)?;
        let port = captures.get(1)?.as_str().parse::<u16>().ok()?;
        (port > 0).then_some(port)
    }

    fn get_user(message: &str) -> Option<String> {
        for (i, re) in REGEX_USER.iter().enumerate() {
            if let Some(captures) = re.captures(message) {
                // Root login refused.
                if i == 10 {
                    return Some("root".to_string());
                }

                if let Some(username) = captures.get(1) {
                    return Some(username.as_str().to_string());
                }
            }
        }

        None
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