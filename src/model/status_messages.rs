use crate::model::error::Error;

const STATUS_MAX_LINES: usize = 10;

pub(crate) struct StatusMessages {
    status_lines: Vec<String>,
}

impl StatusMessages {
    pub fn new() -> Self {
        Self {
            status_lines: Vec::new(),
        }
    }

    pub fn set(&mut self, s: &str) {
        if self.status_lines.len() > STATUS_MAX_LINES {
            self.status_lines.remove(0);
        }
        self.status_lines.push(s.to_string());
        // also print on stdout
        println!("| {}", s);
    }

    pub fn set_error(&mut self, es: &str) {
        self.set(&format!("Error: {}!", es.to_string()));
    }

    pub fn set_error_err(&mut self, e: &Error) {
        self.set_error(&e.to_string());
    }

    pub fn get_last(&self) -> String {
        self.get_last_n(1)
    }

    pub fn get_last_n(&self, n: usize) -> String {
        if self.status_lines.len() < n {
            String::new()
        } else {
            self.status_lines[self.status_lines.len() - n].clone()
        }
    }
}
