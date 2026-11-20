use std::net::IpAddr;
use regex::{Regex, RegexSet, RegexSetBuilder};
use std::str::FromStr;
use std::sync::OnceLock;
use systemd::{JournalRecord, journal::OpenOptions};
use chrono::Local;

const TWO_HOURS_IN_MICROSEC: u64 = 2 * 60 * 60 * 1_000_000;

#[derive(Debug)]
/// timestamp in microseconds
struct SSHLoginEntry {
    message: String,
    user: Option<String>,
    ip: IpAddr,
    port: Option<u16>,
    timestamp: i64,
}

type SSHLoginMessage = String;

#[derive(Debug)]
enum SSHLogin {
    Success(SSHLoginEntry),
    Failure {
        entry: SSHLoginEntry,
        failure: SSHLoginFail
    },
    Unknown(SSHLoginMessage)
}

#[derive(Debug)]
enum SSHLoginFail {
    Password,
    PublicKey,
    KeyboardInteractive,
    Pam,
    InvalidUser,
    AccountRestricted,
    TooManyAttempts,
    Authentication,
    Protocol,
}

static SSH_PATTERNS: OnceLock<RegexSet> = OnceLock::new();

fn patterns() -> &'static RegexSet {
    SSH_PATTERNS.get_or_init(|| {
        RegexSetBuilder::new([
            // 0: Successful authentication
            r"(?i)\bAccepted\s+\w+\s+for\s+\S+\s+from\s+\S+",

            // 1: Failed authentication methods
            r"(?i)\bFailed\s+(?:password|publickey|keyboard-interactive|hostbased|gssapi-with-mic)\s+for\b",

            // 2: Generic authentication failures
            r"(?i)\bauthentication\s+(?:failure|error|failed)\s+for\b",

            // 3: Unknown user
            r"(?i)\bUser not known to the underlying authentication module for\b",

            // 4: Invalid / illegal user
            r"(?i)\b(?:illegal|invalid) user\b",

            // 5: Root login refused
            r"(?i)\bROOT LOGIN REFUSED FROM\b",

            // 6: User restrictions
            r"(?i)\bnot allowed because (?:not listed in AllowUsers|listed in DenyUsers|not in any group|a group is listed in DenyGroups|none of user's groups are listed in AllowGroups)\b",

            // 7: PAM authentication failure
            r"(?i)\bpam_[a-z]+\s*\(sshd:auth\):\s+authentication failure;",

            // 8: Maximum authentication attempts
            r"(?i)\bmaximum authentication attempts exceeded for\b",

            // 9: Locked account
            r"(?i)\bnot allowed because account is locked\b",

            // 10: Username/service change rejected
            r"(?i)\bChange of username or service not allowed\b",

            // 11: Too many authentication failures
            r"(?i)\bToo many authentication failures\b",

            // 12: Explicit authentication failure disconnect
            r"(?i)\b3:\s+.*:\s*Auth fail\b",

            // 13: Refused connection
            r"(?i)\brefused connect from\b",

            // 14: No authentication methods available
            r"(?i)\bNo(?: supported)? authentication methods available\b",

            // 15: Algorithm negotiation failure
            r"(?i)\bUnable to negotiate\b",

            // 16: No matching algorithm
            r"(?i)\bno matching .+ found\b",

            // 17: Invalid protocol version
            r"(?i)\bBad protocol version identification\b",

            // 18: Invalid SSH protocol identifier
            r"(?i)\bkex_exchange_identification: (?:read: )?Client sent invalid protocol identifier\b",

            // 19: SSH server protocol/authentication errors
            r"(?i)\bSSH: Server;Ltype: (?:Authname|Version|Kex);Remote:\s*\S+",

            // 20: Malformed SSH handshake / MAC errors
            r"(?i)\b(?:banner exchange|ssh_dispatch_run_fatal): Connection from .+: (?:invalid format|message authentication code incorrect|connection corrupted)\b",

            // 21: Authentication disconnect due to unsupported methods
            r"(?i)\bReceived disconnect from .+:\s*14:",
        ])
        .case_insensitive(false)
        .build()
        .expect("Invalid SSH regex patterns")
    })
}

impl SSHLoginEntry {
    fn from_entry(mut entry: JournalRecord) -> Result<Self, &'static str> {
        let message = entry.remove("MESSAGE").ok_or("No message field found")?;
        Ok(
            Self {
                ip: Self::get_ip(&message).ok_or("No ip found")?,
                user: Self::get_user(&message),
                port: Self::get_port(&message),
                timestamp: entry.remove("_SOURCE_REALTIME_TIMESTAMP").ok_or("No \"_SOURCE_REALTIME_TIMESTAMP\" field found")?.parse().map_err(|_| "Error parsing \"_SOURCE_REALTIME_TIMESTAMP\"")?,
                message: message,
            }
        )
    }

    fn get_ip(input: &str) -> Option<IpAddr> {
        let re = Regex::new(r"(?i)[0-9a-f:.]+").unwrap();

        re.find_iter(input).find_map(|m| {
            let candidate = m.as_str();

            let before = input[..m.start()].chars().next_back();
            let after = input[m.end()..].chars().next();

            if before.is_some_and(|c| c.is_ascii_alphabetic()) {
                return None;
            }

            if after.is_some_and(|c| c.is_ascii_alphabetic()) {
                return None;
            }

            let candidate = candidate
                .trim_end_matches('.')
                .split_once(':')
                .filter(|(ip, port)| {
                    ip.contains('.') && !ip.contains(':') && port.chars().all(|c| c.is_ascii_digit())
                })
                .map_or(candidate.trim_end_matches('.'), |(ip, _)| ip);

            IpAddr::from_str(candidate).ok()
        })
    }

    fn get_port(message: &str) -> Option<u16> {
        let re = Regex::new(r"\bport ([0-9]{1,5})\b").unwrap();
        let port = re.captures(message)?;
        let port = port.get(1)?.as_str().parse().ok()?;
        (port > 0).then_some(port)
    }

    fn get_user(message: &str) -> Option<String> {
        let patterns = [
            // Failed password, publickey, keyboard-interactive, etc.
            r"Failed \S+ for (?:invalid user )?(\S+?) from ",
            // Authentication failures
            r"[aA]uthentication (?:failure|error|failed) for (.+?) (?:from )?",
            // Unknown user
            r"User not known to the underlying authentication module for (.+?) (?:from )?",
            // Invalid or illegal user
            r"[iI](?:llegal|nvalid) user (.+?) from ",
            // User not allowed
            r"User (\S+).*? not allowed because ",
            // PAM authentication failure
            r"user=(\S+)",
            // Maximum authentication attempts exceeded
            r"maximum authentication attempts exceeded for (?:invalid user )?(.+?) (?:from )?",
            // Disconnecting / disconnected users
            r"(?:Disconnecting|Disconnected)(?: from)? (?:invalid|authenticating) user (\S+)",
            // Too many authentication failures
            r"Too many authentication failures for (\S+)",
            // Successful login
            r"Accepted \S+ for (\S+) from ",
        ];
        for pattern in patterns {
            let re = Regex::new(pattern).unwrap();

            if let Some(captures) = re.captures(message) {
                if let Some(username) = captures.get(1) {
                    return Some(username.as_str().to_string());
                }
            }
        }
        None
    }
}

impl SSHLogin {
    fn new(entry: JournalRecord) -> Result<Self, &'static str> {
        let entry = SSHLoginEntry::from_entry(entry)?;
        Self::from_login_entry(entry)
    }

    fn from_login_entry(entry: SSHLoginEntry) -> Result<Self, &'static str> {
        let message = &entry.message;
        let lower = message.to_ascii_lowercase();

        // Ignore timeouts and connection resets.
        // These are not authentication failures.
        if lower.contains("timeout")
            || lower.contains("timed out")
            || lower.contains("connection reset")
            || lower.contains("reset by peer")
            || lower.contains("connection closed")
            || lower.contains("read from socket failed")
        {
            return Ok(SSHLogin::Unknown(message.clone()));
        }

        let matches = patterns().matches(message);

        // Successful authentication.
        if matches.matched(0) {
            return Ok(SSHLogin::Success(entry));
        }

        // No matching rule.
        if !matches.iter().any(|i| i >= 1) {
            return Ok(SSHLogin::Unknown(message.clone()));
        }

        // Determine the failure category.
        let failure = if lower.contains("publickey") {
            SSHLoginFail::PublicKey
        } else if lower.contains("password") {
            SSHLoginFail::Password
        } else if lower.contains("keyboard-interactive") {
            SSHLoginFail::KeyboardInteractive
        } else if lower.contains("pam_")
            || lower.contains("pam:auth")
            || lower.contains("underlying authentication module")
        {
            SSHLoginFail::Pam
        } else if matches.matched(4) {
            SSHLoginFail::InvalidUser
        } else if matches.matched(5)
            || matches.matched(6)
            || matches.matched(9)
            || matches.matched(10)
        {
            SSHLoginFail::AccountRestricted
        } else if matches.matched(8) || matches.matched(11) {
            SSHLoginFail::TooManyAttempts
        } else if matches.matched(15)
            || matches.matched(16)
            || matches.matched(17)
            || matches.matched(18)
            || matches.matched(19)
            || matches.matched(20)
        {
            SSHLoginFail::Protocol
        } else {
            SSHLoginFail::Authentication
        };

        Ok(SSHLogin::Failure {
            entry,
            failure,
        })
    }
}

fn main() {
    println!("Hello, world!");
    watch_journald_root_ssh();
}

fn watch_journald_root_ssh(){
    let mut opts = OpenOptions::default();
    opts.system(true); opts.local_only(true);

    let mut journal = opts.open().unwrap();
    journal.match_add("_SYSTEMD_UNIT", "ssh.service").unwrap();
    
    let time = Local::now().timestamp_micros() as u64 - TWO_HOURS_IN_MICROSEC;
    journal.seek_realtime_usec(time).unwrap();

    loop {
        let entry = journal.await_next_entry(None).unwrap().unwrap();
        let entrybackup = entry.clone();
        match SSHLogin::new(entry) {
            Ok(x) => println!("{:#?}", x),
            Err(_e) => println!("{entrybackup:#?}")
        }
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn check(input: &str, expected: Option<&str>) {
        let expected = expected.map(|ip| IpAddr::from_str(ip).unwrap());

        assert_eq!(
            SSHLoginEntry::get_ip(&input.to_string()),
            expected,
            "Unexpected result for input: {input:?}"
        );
    }

    #[test]
    fn ipv4_basic() {
        check("127.0.0.1", Some("127.0.0.1"));
        check("192.168.1.1", Some("192.168.1.1"));
        check("10.0.0.1", Some("10.0.0.1"));
        check("255.255.255.255", Some("255.255.255.255"));
        check("0.0.0.0", Some("0.0.0.0"));
    }

    #[test]
    fn ipv4_embedded() {
        check("IP=192.168.1.1", Some("192.168.1.1"));
        check("Connected to (10.0.0.1)!", Some("10.0.0.1"));
        check("Host: [172.16.0.1]", Some("172.16.0.1"));
        check("address=8.8.8.8.", Some("8.8.8.8"));
        check("IP: 192.168.1.1, port: 22", Some("192.168.1.1"));
    }

    #[test]
    fn ipv4_ports() {
        check("192.168.1.1:22", Some("192.168.1.1"));
        check("192.168.1.1:2222", Some("192.168.1.1"));
        check("10.0.0.1:65535", Some("10.0.0.1"));
        check("ssh://192.168.1.1:22", Some("192.168.1.1"));
    }

    #[test]
    fn ipv4_invalid_boundaries() {
        check("x192.168.1.1", None);
        check("192.168.1.1x", None);
        check("a192.168.1.1b", None);
        check("192.168.1.1a", None);
        check("192.168.1.10.5", None);
        check("192.168.1.1.2", None);
        check("192.168.1.1:22:33", None);
    }

    #[test]
    fn ipv4_invalid_addresses() {
        check("192.168.1", None);
        check("999.999.999.999", None);
        check("256.1.1.1", None);
        check("192.168.1.999", None);
        check("1.2.3.999", None);
        check("1.2.3.4.5", None);
        check("1.2.3.4.5.6", None);
    }

    #[test]
    fn ipv6_basic() {
        check("::1", Some("::1"));
        check("::", Some("::"));
        check("2001:db8::1", Some("2001:db8::1"));
        check("fe80::1", Some("fe80::1"));
        check(
            "2001:4860:4860::8888",
            Some("2001:4860:4860::8888"),
        );
        check(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        );
    }

    #[test]
    fn ipv6_embedded() {
        check("IP=2001:db8::1", Some("2001:db8::1"));
        check("Connected from (fe80::1)!", Some("fe80::1"));
        check("[2001:db8::1]", Some("2001:db8::1"));
        check("address=2001:4860:4860::8888", Some("2001:4860:4860::8888"));
    }

    #[test]
    fn ipv6_boundaries() {
        check("x::1", None);
        check("::1x", None);
        check("a2001:db8::1", None);
        check("2001:db8::1g", None);
    }

    #[test]
    fn ipv6_ports() {
        check("[::1]:22", Some("::1"));
        check("[2001:db8::1]:2222", Some("2001:db8::1"));
        check("user@[2001:db8::1]:22", Some("2001:db8::1"));
        check("[fe80::1]:2200", Some("fe80::1"));
        check("::1:22", Some("::1:22")); // Valid IPv6, not distinguishable from a port.
    }

    #[test]
    fn ipv4_mapped_ipv6() {
        check(
            "::ffff:192.168.1.1",
            Some("::ffff:192.168.1.1"),
        );
        check(
            "[::ffff:10.0.0.1]:22",
            Some("::ffff:10.0.0.1"),
        );
    }

    #[test]
    fn malformed_ipv6() {
        check("::::", None);
        check("1:2:3:4:5:6:7:8:9", None);
        check("2001:db8::gggg", None);
        check("2001:db8::1::2", None);
    }

    #[test]
    fn whitespace_and_formatting() {
        check("  192.168.1.1  ", Some("192.168.1.1"));
        check("\t127.0.0.1\n", Some("127.0.0.1"));
        check("IP:\n10.0.0.1\n", Some("10.0.0.1"));
        check("Host:\t[::1]\n", Some("::1"));
    }

    #[test]
    fn multiple_ips() {
        check(
            "192.168.1.1 and 10.0.0.1",
            Some("192.168.1.1"),
        );
        check(
            "10.0.0.1 then 2001:db8::1",
            Some("10.0.0.1"),
        );
    }

    #[test]
    fn no_ip() {
        check("", None);
        check("localhost", None);
        check("example.com", None);
        check("google.com", None);
        check("hello world", None);
        check("not-an-ip", None);
    }
}
