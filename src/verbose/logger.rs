use chrono::{Local};

pub struct Logger{

}

impl Logger {
    pub fn log_message(message: &str, m_type: &str, source: &str){
        let date = Local::now();
        let message = format!("{} {} [{}] {}", date, source, m_type, message);
        println!("{}", message);
    }

    pub fn log_error(message: &str, source: &str){
        let date = Local::now();
        let message = format!("{} {} [ERROR] {}", date, source, message);
        eprintln!("{}", message);
    }
}