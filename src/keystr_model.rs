use crate::keystore::Keystore;

pub(crate) struct KeystrModel {
    pub keystore: Keystore,
}

impl KeystrModel {
    pub fn new() -> Self {
        KeystrModel {
            keystore: Keystore::new(),
        }
    }
}
