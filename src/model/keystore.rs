use crate::model::encrypt::Encrypt;
use crate::model::error::Error;
use crate::model::security_settings::{SecurityLevel, SecuritySettings};
use crate::model::status_messages::StatusMessages;
use crate::model::storage::Storage;
use nostr::prelude::{FromPkStr, FromSkStr, Keys, SecretKey, ToBech32, XOnlyPublicKey};

use std::fs;

// Model for KeyStore part
#[readonly::make]
pub(crate) struct Keystore {
    #[readonly]
    has_unsaved_change: bool,
    keys: Option<Keys>,
    encrypted_secret_key: Option<Vec<u8>>,
    pub hide_secret_key: bool,
    // Input for public key import
    pub public_key_input: String,
    // Input for secret key import
    pub secret_key_input: String,
    // Input for encryption password, for decrypt
    pub decrypt_password_input: String,
    // Input for encryption password, for save
    pub save_password_input: String,
    // Input for repeat encryption password, for save
    pub save_repeat_password_input: String,
}

impl Keystore {
    pub fn new() -> Self {
        Keystore {
            has_unsaved_change: false,
            keys: None,
            encrypted_secret_key: None,
            hide_secret_key: true,
            public_key_input: String::new(),
            secret_key_input: String::new(),
            decrypt_password_input: String::new(),
            save_password_input: String::new(),
            save_repeat_password_input: String::new(),
        }
    }

    /// Action to clear existing keys
    pub fn clear(&mut self) {
        self.keys = None;
        self.encrypted_secret_key = None;
        self.has_unsaved_change = false;
    }

    /// Generate new random keys
    pub fn generate(&mut self) {
        self.keys = Some(Keys::generate());
        self.encrypted_secret_key = None;
        self.has_unsaved_change = true;
    }

    /// Import public key only, in 'npub' bech32 or hex format. Signing will not be possible.
    pub fn import_public_key(&mut self, public_key_str: &str) -> Result<(), Error> {
        self.clear();
        self.keys = Some(Keys::from_pk_str(public_key_str)?);
        self.has_unsaved_change = true;
        Ok(())
    }

    /// Warning: Security-sensitive method!
    /// Import secret key, in 'nsec' bech32 or hex format (pubkey is derived from it)
    pub fn import_secret_key(
        &mut self,
        secret_key_str: &str,
        is_changed: bool,
    ) -> Result<(), Error> {
        self.clear();
        self.keys = Some(Keys::from_sk_str(secret_key_str)?);
        self.has_unsaved_change = is_changed;
        Ok(())
    }

    /// Warning: Security-sensitive method!
    pub fn import_encrypted_secret_key(
        &mut self,
        encrypted_key_str: &str,
        is_changed: bool,
    ) -> Result<(), Error> {
        self.clear();
        self.encrypted_secret_key =
            Some(hex::decode(encrypted_key_str).map_err(|_e| Error::KeyInvalidEncrypted)?);
        self.has_unsaved_change = is_changed;
        Ok(())
    }

    /// Try to decrypt the already loaded encrypted key using the decryption password
    /// It is recommend to zeroize() the password after use.
    pub fn decrypt_secret_key(&mut self, password: &str) -> Result<(), Error> {
        let sk_bytes = match &self.encrypted_secret_key {
            None => return Err(Error::KeyNotSet),
            Some(d) => d,
        };
        let sk = Encrypt::decrypt_key(&sk_bytes, &password)?;
        self.import_secret_key(&sk.to_bech32()?, false)
    }

    /// Warning: Security-sensitive method!
    /// Save secret key to file.
    pub fn save_encrypted_secret_key(&self) -> Result<(), Error> {
        let sk = self.get_secret_key()?;

        if self.save_password_input != self.save_repeat_password_input {
            return Err(Error::KeyEncryptionPasswordMismatch);
        }
        let password = &self.save_password_input;

        Storage::check_create_folder()?;
        let data = Encrypt::encrypt_key(&sk, &password, Encrypt::default_log2_rounds())?;
        let hex_string = hex::encode(data);
        let path = Storage::encrypted_secret_key_file();
        // create empty file
        fs::write(path.as_path(), "")?;
        // set permissions, TODO make it on non-unix as well
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path.as_path(), fs::Permissions::from_mode(0o600))?;
        }
        // write contents
        fs::write(path.as_path(), hex_string.to_string())?;

        Ok(())
    }

    /// Save public key to file.
    pub fn save_public_key(&self) -> Result<(), Error> {
        let pubkey = self.get_public_key()?;
        Storage::check_create_folder()?;
        let npub_string = pubkey.to_bech32()?;
        fs::write(Storage::public_key_file(), npub_string)?;
        Ok(())
    }

    /// Warning: Security-sensitive method!
    /// Save public/secret key to file(s).
    /// Returns if secret key has been saved
    pub fn save_keys(&self) -> Result<bool, Error> {
        if !self.has_unsaved_change {
            return Err(Error::KeyNoChangeToSave);
        }
        // save public key
        self.save_public_key()?;
        // save secret key if set
        if self.is_secret_key_set() {
            self.save_encrypted_secret_key()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Warning: Security-sensitive method!
    /// Load secret key from file
    pub fn load_secret_key(&mut self) -> Result<(), Error> {
        let sk_hex = fs::read_to_string(Storage::encrypted_secret_key_file())?;
        self.import_encrypted_secret_key(&sk_hex, false)?;
        // Also try to decrypt with empty password, set it if successful, ignore if not
        let _ret = self.decrypt_secret_key("");
        Ok(())
    }

    /// Load public key from file
    pub fn load_public_key(&mut self) -> Result<(), Error> {
        let pk_string = fs::read_to_string(Storage::public_key_file())?;
        self.import_public_key(&pk_string)?;
        Ok(())
    }

    /// Warning: Security-sensitive method!
    /// Load public/secret key from file
    pub fn load_keys(&mut self) -> Result<(), Error> {
        let secret_path = Storage::encrypted_secret_key_file();
        if secret_path.as_path().is_file() {
            // secret key file exists, load secret key
            self.load_secret_key()
        } else {
            // load public key
            self.load_public_key()
        }
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
            if security_settings.security_level == SecurityLevel::PersistMandatoryPassword
                && self.save_password_input.is_empty()
            {
                Err(Error::KeyEncryptionPasswordMissing)
            } else {
                self.save_keys()
            }
        };
        match res {
            Err(e) => status.set_error_err(&e),
            Ok(ss) => {
                if ss {
                    // Clear password input
                    self.save_password_input = "".to_string();
                    self.save_repeat_password_input = "".to_string();
                    status.set("Secret key persisted to storage");
                } else {
                    status.set("Public key persisted to storage");
                }
            }
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
            self.load_keys()
        };
        if let Err(e) = res {
            status.set_error_err(&e);
        } else {
            status.set("Keys loaded from storage (may need decryption with password)");
        }
    }

    pub fn unlock_secret_key_action(
        &mut self,
        security_settings: &SecuritySettings,
        status: &mut StatusMessages,
    ) {
        // check if password is set if needed
        let res = if security_settings.security_level == SecurityLevel::PersistMandatoryPassword
            && self.decrypt_password_input.is_empty()
        {
            Err(Error::KeyEncryptionPasswordMissing)
        } else {
            self.decrypt_secret_key(&self.decrypt_password_input.clone())
        };
        match res {
            Err(e) => status.set(&format!(
                "Could not decrypt secret key, check password! ({})",
                e
            )),
            Ok(_) => {
                // cleanup
                self.decrypt_password_input = "".to_string();
                status.set("Secret key decrypted")
            }
        }
    }

    /// Warning: Security-sensitive method!
    /// Import secret key, in 'nsec' bech32 or hex format (pubkey is derived from it)
    pub fn import_secret_key_action(&mut self, status: &mut StatusMessages) {
        match self.import_secret_key(&self.secret_key_input.clone(), true) {
            Err(e) => status.set_error(&format!("Error importing, {}", e.to_string())),
            Ok(_) => status.set("Secret key imported"),
        };
        // cleanup
        self.secret_key_input = String::new();
    }

    pub fn keys_is_set(&self) -> bool {
        self.keys.is_some()
    }

    #[cfg(test)]
    pub fn is_public_key_set(&self) -> bool {
        self.get_public_key().is_ok()
    }

    pub fn is_secret_key_set(&self) -> bool {
        self.get_secret_key().is_ok()
    }

    pub fn is_encrypted_secret_key_set(&self) -> bool {
        self.encrypted_secret_key.is_some()
    }

    /// Warning: Security-sensitive method!
    pub(crate) fn get_keys(&self) -> Result<&Keys, Error> {
        match &self.keys {
            None => Err(Error::KeyNotSet),
            Some(kk) => Ok(kk),
        }
    }

    fn get_public_key(&self) -> Result<XOnlyPublicKey, Error> {
        Ok(self.get_keys()?.public_key())
    }

    /// Warning: Security-sensitive method!
    fn get_secret_key(&self) -> Result<SecretKey, Error> {
        Ok(self.get_keys()?.secret_key()?)
    }

    pub fn get_npub(&self) -> String {
        match self.get_public_key() {
            Err(_e) => "(not set)".to_string(),
            Ok(pk) => match pk.to_bech32() {
                Err(_) => "(conversion error)".to_string(),
                Ok(s) => s,
            },
        }
    }

    /// Warning: Security-sensitive method!
    /// Return secret key as nsec string, if set, and if Hide option is not active.
    pub fn get_nsec(&self) -> String {
        match self.get_secret_key() {
            Err(_) => "(not set)".to_string(),
            Ok(key) => {
                if self.hide_secret_key {
                    "".to_string()
                } else {
                    match key.to_bech32() {
                        Err(_) => "(conversion error)".to_string(),
                        Ok(s) => s,
                    }
                }
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
        k.hide_secret_key = false;
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

        // test hide option
        k.hide_secret_key = true;
        assert_eq!(k.get_nsec(), "".to_string());
    }

    #[test]
    fn test_import_secret_key() {
        let mut k = Keystore::new();
        let _res = k
            .import_secret_key(
                "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae",
                true,
            )
            .unwrap();
        assert!(k.is_public_key_set());
        assert!(k.is_secret_key_set());
        assert_eq!(
            k.get_npub(),
            "npub1rfze4zn25ezp6jqt5ejlhrajrfx0az72ed7cwvq0spr22k9rlnjq93lmd4"
        );
        k.hide_secret_key = false;
        assert_eq!(
            k.get_nsec(),
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae"
        );
    }

    #[test]
    fn test_import_secret_key_hex() {
        let mut k = Keystore::new();
        let _res = k
            .import_secret_key(
                "b2f3673ee3a659283e6599080e0ab0e669a3c2640914375a9b0b357faae08b17",
                true,
            )
            .unwrap();
        k.hide_secret_key = false;
        assert_eq!(
            k.get_nsec(),
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae"
        );
    }

    #[test]
    fn test_import_secret_key_hex_invalid() {
        let mut k = Keystore::new();
        let res = k.import_secret_key("__NOT_A_VALID_KEY__", true);
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
