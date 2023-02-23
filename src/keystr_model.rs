use crate::{
    delegator::Delegator, error::Error, keystore::Keystore, security_settings::SecuritySettings,
};

pub(crate) struct KeystrModel {
    pub own_keys: Keystore,
    pub delegator: Delegator,
    pub status: StatusMessages,
    pub security_settings: SecuritySettings,
}

impl KeystrModel {
    pub fn new() -> Self {
        let mut model = Self {
            own_keys: Keystore::new(),
            delegator: Delegator::new(),
            status: StatusMessages::new(),
            security_settings: SecuritySettings::new(),
        };
        model.status.set("Keystr started");
        //. Try load
        if model.security_settings.allows_persist() {
            let _res = model
                .own_keys
                .load_action(&model.security_settings, &mut model.status);
        }
        model
    }
}

const STATUS_MAX_LINES: usize = 10;

pub struct StatusMessages {
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
