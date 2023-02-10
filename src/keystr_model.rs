use crate::{delegator::Delegator, keystore::Keystore};

pub(crate) struct KeystrModel {
    pub own_keys: Keystore,
    pub delegator: Delegator,
}

impl KeystrModel {
    pub fn new() -> Self {
        KeystrModel {
            own_keys: Keystore::new(),
            delegator: Delegator::new(),
        }
    }
}
