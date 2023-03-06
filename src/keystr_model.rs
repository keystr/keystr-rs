use crate::{
    delegator::Delegator, keystore::Keystore, settings::Settings, status_messages::StatusMessages,
};

pub(crate) struct KeystrModel {
    pub own_keys: Keystore,
    pub delegator: Delegator,
    pub status: StatusMessages,
    pub settings: Settings,
}

impl KeystrModel {
    pub fn new() -> Self {
        let mut model = Self {
            own_keys: Keystore::new(),
            delegator: Delegator::new(),
            status: StatusMessages::new(),
            settings: Settings::default(),
        };
        model.status.set("Keystr started");
        //. Try load settings
        if let Ok(sett) = Settings::load() {
            model.settings = sett;
        }
        //. Try load keys
        if model.settings.security.allows_persist() {
            let _res = model
                .own_keys
                .load_action(&model.settings.security, &mut model.status);
        }
        model
    }
}
