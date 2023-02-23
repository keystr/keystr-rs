use crate::{delegator::Delegator, keystore::Keystore};

use std::fmt;

pub(crate) struct KeystrModel {
    pub own_keys: Keystore,
    pub delegator: Delegator,
    pub status: StatusMessages,
    pub security_level: SecurityLevel,
}

/// Security level regarding secret key handling/persistence; chosen by the user
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityLevel {
    /// Never persist secret key
    Never,
    /// Persist but only encrypted
    PersistEncryptedOnly,
    /// Persist security key
    Persist,
}

impl fmt::Display for SecurityLevel {
    /// Return tag in JSON string format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", KeystrModel::get_security_level_desc(*self))
    }
}

pub(crate) static SECURITY_LEVELS: &[SecurityLevel] = &[
    SecurityLevel::Never,
    SecurityLevel::PersistEncryptedOnly,
    SecurityLevel::Persist,
];

impl KeystrModel {
    pub fn new() -> Self {
        KeystrModel {
            own_keys: Keystore::new(),
            delegator: Delegator::new(),
            status: StatusMessages::new(),
            security_level: SecurityLevel::PersistEncryptedOnly,
        }
    }

    pub fn get_security_warning_secret(&self) -> String {
        "I understand that if the secret key leaks to the wrong hands, the entire identity is COMPROMISED irreversibly.\n\
        I must make backups of security keys, because if they are lost, the identity is LOST forever.".to_string()
    }

    pub fn get_security_level_desc(level: SecurityLevel) -> String {
        match level {
            SecurityLevel::Never => "! Never persist secret keys. If I decide to import a secret key, it should only live in the memory of the app in the current session.".to_string(),
            SecurityLevel::PersistEncryptedOnly => "!! Secret key may be persisted, but only encrypted using a passphrase I provide.".to_string(),
            SecurityLevel::Persist => "!!! Secret key may be persisted in local storage, for safekeeping and convenience (encrypted or not)".to_string(),
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

    pub fn get_last(&self) -> String {
        self.get_last_n(1)
    }

    pub fn get_butlast(&self) -> String {
        self.get_last_n(2)
    }

    fn get_last_n(&self, n: usize) -> String {
        if self.status_lines.len() < n {
            String::new()
        } else {
            self.status_lines[self.status_lines.len() - n].clone()
        }
    }
}
