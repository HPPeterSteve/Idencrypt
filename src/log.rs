use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;

#[allow(dead_code)]
pub enum LogLevel {
    INFO,
    WARN,
    ERROR,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LogLevel::INFO => write!(f, "INFO"),
            LogLevel::WARN => write!(f, "WARN"),
            LogLevel::ERROR => write!(f, "ERROR"),
        }
    }
}

pub fn log(level: LogLevel, message: &str) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_entry = format!("[{}] [{}] {}\n", timestamp, level, message);

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("idenvault.log")
    {
        let _ = file.write_all(log_entry.as_bytes());
    }
}

pub fn info(message: &str) {
    log(LogLevel::INFO, message);
}

#[allow(dead_code)]
pub fn warn(message: &str) {
    log(LogLevel::WARN, message);
}

#[allow(dead_code)]
pub fn error(message: &str) {
    log(LogLevel::ERROR, message);
}
