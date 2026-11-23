mod parser;
mod source;

use crate::source::journald::JournalSource;
use crate::parser::entry::LoginEvent;
use crate::source::reader::LogReader;

pub fn process(){
    let mut journal = JournalSource::new().unwrap();
    loop {
        let entry = journal.await_next_entry(None).unwrap().unwrap();
        println!("Login event: \n{:?}", LoginEvent::from_raw_login_entry(entry))
    }
}