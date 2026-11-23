mod parser;
mod source;

use crate::source::journald::JournalSource;
use crate::parser::entry::LoginEvent;
use crate::source::reader::LogReader;

pub fn run() -> Result<(), &'static str> {
    let mut reader = get_log_reader()?;

    loop {
        let entry = reader.blocking_next_entry(None)?;
        match entry {
            None => break,
            Some(e) => {
                println!("Login event: \n{:#?}", LoginEvent::from_raw_login_entry(e))
            }
        }
    }

    Ok(())
}

pub fn get_log_reader() -> Result<impl LogReader, &'static str>{
    JournalSource::new()
}