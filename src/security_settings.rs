use serde::{Deserialize, Serialize};

use std::fmt;

/// Security-related settings
#[derive(Default, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub security_level: SecurityLevel,
}

/// Security level regarding secret key handling/persistence; chosen by the user
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Never persist secret key
    Never,
    /// Persist security key, encrypted with mandatory password
    #[default]
    PersistMandatoryPassword,
    /// Persist security key, encrypted, with optional password
    PersistOptionalPassword,
}

impl fmt::Display for SecurityLevel {
    /// Return tag in JSON string format
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", SecuritySettings::get_security_level_desc(*self))
    }
}

pub(crate) static SECURITY_LEVELS: &[SecurityLevel] = &[
    SecurityLevel::Never,
    SecurityLevel::PersistMandatoryPassword,
    SecurityLevel::PersistOptionalPassword,
];

impl SecuritySettings {
    pub fn get_security_warning_secret(&self) -> String {
        "I understand that if the secret key leaks to the wrong hands, the entire identity is COMPROMISED irreversibly.\n\
        I must make backups of security keys, because if they are lost, the identity is LOST forever.".to_string()
    }

    pub fn get_security_level_desc(level: SecurityLevel) -> String {
        match level {
            SecurityLevel::Never => "! Never persist secret keys. If I decide to import a secret key, it should only live in the memory of the app in the current session.".to_string(),
            SecurityLevel::PersistMandatoryPassword => "!! Secret key may be persisted, but always encrypted using a password I provide.".to_string(),
            SecurityLevel::PersistOptionalPassword => "!!! Secret key may be persisted, encrypted without or with a password".to_string(),
        }
    }

    pub fn allows_persist(&self) -> bool {
        self.security_level == SecurityLevel::PersistMandatoryPassword
            || self.security_level == SecurityLevel::PersistOptionalPassword
    }
}
