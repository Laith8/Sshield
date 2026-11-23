use systemd::Journal;
use systemd::journal::OpenOptions;
use crate::source::reader::LogReader;
use crate::source::event::RawLoginEntry;
use crate::source::error::LogReaderError;
use std::time::Duration;

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
        journal.seek_tail()
            .map_err(|_| "Error seeking journal")?;

        Ok(Self { journal })
    }
}

impl LogReader for JournalSource {
    fn await_next_entry(&mut self, timeout: Option<Duration>) -> Result<Option<RawLoginEntry>, LogReaderError> {
        let entry = self.journal
            .await_next_entry(timeout)
            .map_err(|_| LogReaderError::LogOpenError)?;
        match entry {
            None => Ok(None),
            Some(mut entry) => {
                Ok(Some(
                    RawLoginEntry {
                    timestamp: entry
                        .remove("_SOURCE_REALTIME_TIMESTAMP")
                        .ok_or(LogReaderError::InvalidLogData)?
                        .parse()
                        .map_err(|_| LogReaderError::InvalidLogData)?,
                    message: entry.remove("MESSAGE").ok_or(LogReaderError::InvalidLogData)?
                }
                ))
            }
        }
    }
}