use std::time::Duration;

use crate::source::event::RawLoginEntry;

pub trait LogReader {
    fn blocking_next_entry(&mut self, timeout: Option<Duration>) -> Result<Option<RawLoginEntry>, &'static str>;
}