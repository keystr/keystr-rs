use crate::base::error::Error;
use crate::model::keystr_model::{Event, EVENT_QUEUE};

use std::sync::{Arc, RwLock};

const STATUS_MAX_LINES: usize = 10;

#[derive(Clone)]
pub(crate) struct StatusMessages {
    status_lines: Arc<RwLock<Vec<String>>>,
}

impl StatusMessages {
    pub fn new() -> Self {
        Self {
            status_lines: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn set(&self, s: &str) {
        let mut lines = self.status_lines.write().unwrap();
        if lines.len() > STATUS_MAX_LINES {
            lines.remove(0);
        }
        lines.push(s.to_string());
        // also print on stdout
        println!("| {}", s);
        // also send UI notification
        let _ = EVENT_QUEUE.push(Event::StatusUpdate);
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
        let lines = self.status_lines.read().unwrap();
        if lines.len() < n {
            String::new()
        } else {
            lines[lines.len() - n].clone()
        }
    }
}
