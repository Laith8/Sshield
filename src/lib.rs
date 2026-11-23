mod parser;
mod source;

use crate::source::journald::JournalSource;
use crate::source::reader::LogReader;
use crate::parser::entry::LoginEvent;

pub fn run() -> Result<(), &'static str> {
    let mut reader = get_log_reader()?;

    loop {
        match reader.blocking_next_entry(None) {
            Err(_) => reader = get_log_reader()?,
            Ok(entry) => {
                // delegate logic to later built jail from here
                match entry {
                    None => return Err("CRITICAL: impossible path reached"), // shouldn't happen as long as timeout is None
                    Some(entry) => {
                        println!("Login event: \n{:#?}", LoginEvent::from_raw_login_entry(entry));
                    }
                }
            }
        }
    }
}

pub fn get_log_reader() -> Result<impl LogReader, &'static str>{
    // currently only journald supported
    JournalSource::new()
}