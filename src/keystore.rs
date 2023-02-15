use nostr_sdk::prelude::{Keys, ToBech32};

pub(crate) struct Keystore {
    pub is_set: bool,
    keys: Keys,
}

impl Keystore {
    pub fn new() -> Self {
        Keystore {
            is_set: false,
            keys: Keys::generate(), // placeholder value initially
        }
    }

    pub fn get_keys(&self) -> Result<Keys, String> {
        if !self.is_set {
            return Err("(not set)".to_string());
        }
        Ok(self.keys.clone())
    }

    pub fn get_npub(&self) -> String {
        if !self.is_set {
            "(not set)".to_string()
        } else {
            match self.keys.public_key().to_bech32() {
                Err(_) => "(conversion error)".to_string(),
                Ok(s) => s,
            }
        }
    }

    pub fn get_nsec(&self) -> String {
        if !self.is_set {
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

    pub fn generate(&mut self) {
        self.keys = Keys::generate();
        self.is_set = true;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new() {
        let k = Keystore::new();
        assert_eq!(k.get_npub(), "(not set)");
        assert_eq!(k.get_nsec(), "(not set)");
        assert!(k.get_keys().is_err());
    }

    #[test]
    fn test_generate() {
        let mut k = Keystore::new();
        k.generate();
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
}
