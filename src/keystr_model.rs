use crate::{delegator::Delegator, keystore::Keystore};

pub(crate) struct KeystrModel {
    pub own_keys: Keystore,
    pub delegator: Delegator,
    pub status_line: String,
}

impl KeystrModel {
    pub fn new() -> Self {
        KeystrModel {
            own_keys: Keystore::new(),
            delegator: Delegator::new(),
            status_line: String::new(),
        }
    }

    pub fn set_status(&mut self, s: &str) {
        self.status_line = s.to_string();
    }

    pub fn set_error_status(&mut self, s: &str) {
        self.status_line = format!("Error: {}!", s.to_string());
    }
}
