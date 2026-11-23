use systemd::Journal;
use systemd::journal::OpenOptions;
use crate::source::reader::LogReader;
use crate::source::event::RawLoginEntry;
use std::time::{Duration,SystemTime,UNIX_EPOCH};

pub struct JournalSource {
    journal: Journal
}

impl JournalSource {
    pub fn new() -> Result<JournalSource, &'static str> {
        let mut opts = OpenOptions::default();
        opts.system(true);
        opts.local_only(true);
        
        let mut journal = opts.open().map_err(|_| "Error opening systemd journal")?;
        journal.match_add("_SYSTEMD_UNIT", "ssh.service")
            .map_err(|_| "Error adding journal filter")?;

        let ssh = journal.match_add("_SYSTEMD_UNIT", "ssh.service").is_err();
        let sshd = journal.match_add("_SYSTEMD_UNIT", "sshd.service").is_err();

        if ssh && sshd {
            return Err("sshd service name not found");
        }
        
        journal.seek_realtime_usec(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "Failed to get system time")?
                .as_micros() as u64)
                .map_err(|_| "Failed to seek in journal")?;

        Ok(Self { journal })
    }
}

impl LogReader for JournalSource {
    fn blocking_next_entry(&mut self, timeout: Option<Duration>) -> Result<Option<RawLoginEntry>, &'static str> {
        let entry = self.journal
            .await_next_entry(timeout)
            .map_err(|_| "Failed to read journal")?;
        match entry {
            None => Ok(None),
            Some(mut e) => {
                Ok(
                    Some(
                        RawLoginEntry {
                            timestamp:e
                                .remove("_SOURCE_REALTIME_TIMESTAMP")
                                .ok_or("_SOURCE_REALTIME_TIMESTAMP not found in journal")?
                                .parse()
                                .map_err(|_| "Could not parse journal value of _SOURCE_REALTIME_TIMESTAMP")?,
                            message: e.remove("MESSAGE").ok_or("MESSAGE not found in journal")? 
                        }
                    )
                )
            }
        }
    }
}