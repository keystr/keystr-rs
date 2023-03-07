use crate::{
    delegator::Delegator, keystore::Keystore, settings::Settings, status_messages::StatusMessages,
};

#[derive(Clone, Debug)]
pub(crate) enum Action {
    DelegateDeeGenerate,
    DelegateSign,
    KeysClearNoConfirm,
    KeysClear,
    KeysGenerate,
    KeysImportPubkey,
    KeysImportSecretkey,
    KeysLoad,
    KeysSave,
    KeysUnlock,
    ConfirmationOk,
    ConfirmationCancel,
}

#[derive(Clone)]
pub(crate) enum Confirmation {
    KeysClearBeforeAction(Option<Action>),
}

pub(crate) struct KeystrModel {
    pub own_keys: Keystore,
    pub delegator: Delegator,
    pub status: StatusMessages,
    pub settings: Settings,
    pub confirmation_dialog: Option<Confirmation>,
}

impl KeystrModel {
    pub fn new() -> Self {
        let mut model = Self {
            own_keys: Keystore::new(),
            delegator: Delegator::new(),
            status: StatusMessages::new(),
            settings: Settings::default(),
            confirmation_dialog: None,
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

    pub fn action(&mut self, action: Action) {
        match action {
            Action::DelegateDeeGenerate => self.delegator.generate_random_delegatee(),
            Action::DelegateSign => {
                match self.own_keys.get_keys() {
                    Err(e) => self.status.set_error(&e.to_string()),
                    Ok(keys) => match self.delegator.create_delegation(&keys) {
                        Err(e) => self.status.set_error(&e.to_string()),
                        Ok(_) => self.status.set("Delegation created"),
                    },
                };
            }
            Action::KeysClearNoConfirm => {
                self.own_keys.clear();
                self.status.set("Keys cleared");
            }
            Action::KeysClear => {
                if self.own_keys.keys_is_set() {
                    self.confirmation_dialog = Some(Confirmation::KeysClearBeforeAction(None));
                } else {
                    self.action(Action::KeysClearNoConfirm);
                }
            }
            Action::KeysGenerate => {
                if self.own_keys.keys_is_set() {
                    self.confirmation_dialog = Some(Confirmation::KeysClearBeforeAction(Some(
                        Action::KeysGenerate,
                    )));
                } else {
                    self.confirmation_dialog = None;
                    self.own_keys.generate();
                    self.status.set("New keypair generated");
                }
            }
            Action::KeysImportPubkey => {
                match self
                    .own_keys
                    .import_public_key(&self.own_keys.public_key_input.clone())
                {
                    Err(e) => self.status.set_error(&e.to_string()),
                    Ok(_) => self.status.set("Public key imported"),
                };
                // cleanup
                self.own_keys.public_key_input = String::new();
            }
            Action::KeysImportSecretkey => {
                self.own_keys.import_secret_key_action(&mut self.status);
            }
            Action::KeysLoad => {
                if self.own_keys.keys_is_set() {
                    self.confirmation_dialog =
                        Some(Confirmation::KeysClearBeforeAction(Some(Action::KeysLoad)));
                } else {
                    self.own_keys
                        .load_action(&self.settings.security, &mut self.status);
                }
            }
            Action::KeysSave => {
                self.own_keys
                    .save_action(&self.settings.security, &mut self.status);
            }
            Action::KeysUnlock => self
                .own_keys
                .unlock_secret_key_action(&self.settings.security, &mut self.status),
            Action::ConfirmationOk => {
                let prev_confirmation = self.confirmation_dialog.clone();
                self.confirmation_dialog = None;
                self.action(Action::KeysClearNoConfirm);
                if let Some(Confirmation::KeysClearBeforeAction(Some(next_action))) =
                    prev_confirmation
                {
                    self.action(next_action);
                }
            }
            Action::ConfirmationCancel => {
                self.confirmation_dialog = None;
            }
        }
    }
}
