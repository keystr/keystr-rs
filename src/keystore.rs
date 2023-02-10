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

    pub fn get_keys(&self) -> Keys {
        self.keys.clone()
    }

    pub fn get_npub(&self) -> String {
        if !self.is_set {
            "(no keys set!)".to_string()
        } else {
            match self.keys.public_key().to_bech32() {
                Err(_) => "(conversion error)".to_string(),
                Ok(s) => s,
            }
        }
    }

    pub fn get_nsec(&self) -> String {
        if !self.is_set {
            "(no keys set!)".to_string()
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
