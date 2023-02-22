use crate::{delegator::Delegator, keystore::Keystore};

pub(crate) struct KeystrModel {
    pub own_keys: Keystore,
    pub delegator: Delegator,
    pub status: StatusMessages,
}

impl KeystrModel {
    pub fn new() -> Self {
        KeystrModel {
            own_keys: Keystore::new(),
            delegator: Delegator::new(),
            status: StatusMessages::new(),
        }
    }
}

const STATUS_MAX_LINES: usize = 10;

pub(crate) struct StatusMessages {
    status_lines: Vec<String>,
}

impl StatusMessages {
    fn new() -> Self {
        Self {
            status_lines: Vec::new(),
        }
    }

    pub fn set(&mut self, s: &str) {
        if self.status_lines.len() > STATUS_MAX_LINES {
            self.status_lines.remove(0);
        }
        self.status_lines.push(s.to_string());
    }

    pub fn set_error(&mut self, s: &str) {
        self.set(&format!("Error: {}!", s.to_string()));
    }

    pub fn get_last(&self) -> String { self.get_last_n(1) }

    pub fn get_butlast(&self) -> String { self.get_last_n(2) }

    fn get_last_n(&self, n: usize) -> String {
        if self.status_lines.len() < n {
            String::new()
        } else {
            self.status_lines[self.status_lines.len() - n].clone()
        }
    }
}
