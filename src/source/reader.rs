use std::time::Duration;

use crate::source::event::RawLoginEntry;
use crate::source::error::LogReaderError;

pub trait LogReader {
    fn await_next_entry(&mut self, timeout: Option<Duration>) -> Result<Option<RawLoginEntry>, LogReaderError>;
}