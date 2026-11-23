#[derive(Debug)]
pub enum LogReaderError {
    LogOpenError,
    InvalidLogData,
}