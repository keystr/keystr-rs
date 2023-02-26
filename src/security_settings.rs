use std::fmt;

pub struct SecuritySettings {
    pub security_level: SecurityLevel,
}

/// Security level regarding secret key handling/persistence; chosen by the user
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityLevel {
    /// Never persist secret key
    Never,
    /// Persist but only encrypted
    // PersistEncryptedOnly,
    /// Persist security key
    Persist,
}

impl fmt::Display for SecurityLevel {
    /// Return tag in JSON string format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", SecuritySettings::get_security_level_desc(*self))
    }
}

pub(crate) static SECURITY_LEVELS: &[SecurityLevel] = &[
    SecurityLevel::Never,
    // SecurityLevel::PersistEncryptedOnly,
    SecurityLevel::Persist,
];

impl SecuritySettings {
    pub fn new() -> Self {
        Self {
            security_level: SecurityLevel::Never, // TODO PersistEncryptedOnly,
        }
    }

    pub fn get_security_warning_secret(&self) -> String {
        "I understand that if the secret key leaks to the wrong hands, the entire identity is COMPROMISED irreversibly.\n\
        I must make backups of security keys, because if they are lost, the identity is LOST forever.".to_string()
    }

    pub fn get_security_level_desc(level: SecurityLevel) -> String {
        match level {
            SecurityLevel::Never => "! Never persist secret keys. If I decide to import a secret key, it should only live in the memory of the app in the current session.".to_string(),
            // SecurityLevel::PersistEncryptedOnly => "!! Secret key may be persisted, but only encrypted using a passphrase I provide.".to_string(),
            SecurityLevel::Persist => "!! Secret key may be persisted in local storage, for safekeeping and convenience (encrypted or not)".to_string(),
        }
    }

    pub fn allows_persist(&self) -> bool {
        self.security_level == SecurityLevel::Persist
        // TODO || self.security_level == SecurityLevel::PersistEncryptedOnly
    }
}
