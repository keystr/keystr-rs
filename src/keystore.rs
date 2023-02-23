use crate::{error::Error, keystr_model::StatusMessages, security_settings::SecuritySettings};
use nostr::prelude::{FromPkStr, FromSkStr, Keys, ToBech32};

use std::fs;

#[derive(PartialEq)]
pub enum KeysSetState {
    NotSet,
    PublicOnly,
    SecretAndPublic,
}

// Model for KeyStore part
#[readonly::make]
pub struct Keystore {
    pub set_level: KeysSetState,
    #[readonly]
    has_unsaved_change: bool,
    keys: Keys,
    // Input for public key import
    pub public_key_input: String,
    // Input for secret key import
    pub secret_key_input: String,
}

const SECRET_FILENAME: &str = ".keystr_sec";

impl Keystore {
    pub fn new() -> Self {
        Keystore {
            set_level: KeysSetState::NotSet,
            has_unsaved_change: false,
            keys: Keys::generate(), // placeholder value initially
            public_key_input: String::new(),
            secret_key_input: String::new(),
        }
    }

    /// Action to clear existing keys
    pub fn clear(&mut self) {
        self.keys = Keys::generate();
        self.set_level = KeysSetState::NotSet;
    }

    /// Generate new random keys
    pub fn generate(&mut self) {
        self.keys = Keys::generate();
        self.set_level = KeysSetState::SecretAndPublic;
        self.has_unsaved_change = true;
    }

    /// Import public key only, in 'npub' bech32 or hex format. Signing will not be possible.
    pub fn import_public_key(&mut self, public_key_str: &str) -> Result<(), Error> {
        self.clear();
        self.keys = Keys::from_pk_str(public_key_str)?;
        self.set_level = KeysSetState::PublicOnly;
        self.has_unsaved_change = true;
        Ok(())
    }

    /// Warning: Security-sensitive method!
    /// Import secret key, in 'nsec' bech32 or hex format (pubkey is derived from it)
    pub fn import_secret_key(&mut self, secret_key_str: &str) -> Result<(), Error> {
        self.clear();
        self.keys = Keys::from_sk_str(secret_key_str)?;
        self.set_level = KeysSetState::SecretAndPublic;
        self.has_unsaved_change = true;
        Ok(())
    }

    /// Warning: Security-sensitive method!
    /// Save secret key to file.
    pub fn save(&mut self) -> Result<(), Error> {
        if !self.is_secret_key_set() {
            return Err(Error::KeyNotSet);
        }
        if !self.has_unsaved_change {
            return Err(Error::KeyNoChangeToSave);
        }
        let hex_string = hex::encode(self.keys.secret_key()?.secret_bytes());
        fs::write(SECRET_FILENAME, hex_string.to_string())?;
        Ok(())
    }

    /// Load secret key from file
    pub fn load(&mut self) -> Result<(), Error> {
        let sk_hex = fs::read_to_string(SECRET_FILENAME)?;
        self.import_secret_key(&sk_hex)?;
        Ok(())
    }

    /// Warning: Security-sensitive method!
    ///.Action to save secret key from file
    pub fn save_action(
        &mut self,
        security_settings: &SecuritySettings,
        status: &mut StatusMessages,
    ) {
        let res = if !security_settings.allows_persist() {
            Err(Error::KeySaveNotAllowed)
        } else {
            self.save()
        };
        if let Err(e) = res {
            status.set_error_err(&e);
        } else {
            status.set("Secret key persisted to storage");
        }
    }

    ///.Action to load secret key from file
    pub fn load_action(
        &mut self,
        security_settings: &SecuritySettings,
        status: &mut StatusMessages,
    ) {
        // TODO confirmation
        let res = if !security_settings.allows_persist() {
            Err(Error::KeyLoadNotAllowed)
        } else {
            self.load()
        };
        if let Err(e) = res {
            status.set_error_err(&e);
        } else {
            status.set("Keys loaded from storage");
        }
    }

    pub fn is_public_key_set(&self) -> bool {
        self.set_level != KeysSetState::NotSet
    }

    pub fn is_secret_key_set(&self) -> bool {
        self.set_level == KeysSetState::SecretAndPublic
    }

    pub fn get_keys(&self) -> Result<Keys, Error> {
        if !self.is_secret_key_set() {
            return Err(Error::KeyNotSet);
        }
        Ok(self.keys.clone())
    }

    pub fn get_npub(&self) -> String {
        if !self.is_public_key_set() {
            "(not set)".to_string()
        } else {
            match self.keys.public_key().to_bech32() {
                Err(_) => "(conversion error)".to_string(),
                Ok(s) => s,
            }
        }
    }

    /// Warning: Security-sensitive method!
    pub fn get_nsec(&self) -> String {
        if !self.is_secret_key_set() {
            "(not set)".to_string()
        } else {
            match self.keys.secret_key() {
                Err(_) => "(no secret key)".to_string(),
                Ok(key) => match key.to_bech32() {
                    Err(_) => "(conversion error)".to_string(),
                    Ok(s) => s,
                },
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new() {
        let k = Keystore::new();
        assert_eq!(k.is_public_key_set(), false);
        assert_eq!(k.is_secret_key_set(), false);
        assert_eq!(k.get_npub(), "(not set)");
        assert_eq!(k.get_nsec(), "(not set)");
        assert!(k.get_keys().is_err());
    }

    #[test]
    fn test_generate() {
        let mut k = Keystore::new();
        k.generate();
        assert!(k.is_public_key_set());
        assert!(k.is_secret_key_set());
        assert!(k.get_npub().len() > 60);
        assert!(k.get_nsec().len() > 60);
        assert!(k.get_keys().is_ok());
        assert_eq!(
            k.get_keys().unwrap().public_key().to_bech32().unwrap(),
            k.get_npub()
        );
        assert_eq!(
            k.get_keys()
                .unwrap()
                .secret_key()
                .unwrap()
                .to_bech32()
                .unwrap(),
            k.get_nsec()
        );
    }

    #[test]
    fn test_import_secret_key() {
        let mut k = Keystore::new();
        let _res = k
            .import_secret_key("nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae")
            .unwrap();
        assert!(k.is_public_key_set());
        assert!(k.is_secret_key_set());
        assert_eq!(
            k.get_nsec(),
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae"
        );
        assert_eq!(
            k.get_npub(),
            "npub1rfze4zn25ezp6jqt5ejlhrajrfx0az72ed7cwvq0spr22k9rlnjq93lmd4"
        );
    }

    #[test]
    fn test_import_secret_key_hex() {
        let mut k = Keystore::new();
        let _res = k
            .import_secret_key("b2f3673ee3a659283e6599080e0ab0e669a3c2640914375a9b0b357faae08b17")
            .unwrap();
        assert_eq!(
            k.get_nsec(),
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae"
        );
    }

    #[test]
    fn test_import_secret_key_hex_invalid() {
        let mut k = Keystore::new();
        let res = k.import_secret_key("__NOT_A_VALID_KEY__");
        assert!(res.is_err());
        assert_eq!(k.is_public_key_set(), false);
        assert_eq!(k.is_secret_key_set(), false);
    }

    #[test]
    fn test_import_public_key() {
        let mut k = Keystore::new();
        let _res = k
            .import_public_key("npub1rfze4zn25ezp6jqt5ejlhrajrfx0az72ed7cwvq0spr22k9rlnjq93lmd4")
            .unwrap();
        assert!(k.is_public_key_set());
        assert_eq!(k.is_secret_key_set(), false);
        assert_eq!(
            k.get_npub(),
            "npub1rfze4zn25ezp6jqt5ejlhrajrfx0az72ed7cwvq0spr22k9rlnjq93lmd4"
        );
    }

    #[test]
    fn test_import_public_key_hex() {
        let mut k = Keystore::new();
        let _res = k
            .import_public_key("1a459a8a6aa6441d480ba665fb8fb21a4cfe8bcacb7d87300f8046a558a3fce4")
            .unwrap();
        assert_eq!(
            k.get_npub(),
            "npub1rfze4zn25ezp6jqt5ejlhrajrfx0az72ed7cwvq0spr22k9rlnjq93lmd4"
        );
    }

    #[test]
    fn test_import_public_key_invalid() {
        let mut k = Keystore::new();
        let res = k.import_public_key("__NOT_A_VALID_KEY__");
        assert!(res.is_err());
        assert_eq!(k.is_public_key_set(), false);
        assert_eq!(k.is_secret_key_set(), false);
    }
}
