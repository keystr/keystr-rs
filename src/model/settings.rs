use crate::base::error::Error;
use crate::base::storage::Storage;
use crate::model::security_settings::{SecurityLevel, SecuritySettings};
use serde::{Deserialize, Serialize};
use std::fs;

/// Settings
#[readonly::make]
#[derive(Default, Serialize, Deserialize)]
pub struct Settings {
    #[readonly]
    pub security: SecuritySettings,
}

impl Settings {
    pub fn set_security_level(&mut self, level: SecurityLevel) {
        self.security.security_level = level;
        let _res = self.save();
    }

    pub fn save(&self) -> Result<(), Error> {
        let str = serde_json::to_string(&self)?;
        Storage::check_create_folder()?;
        fs::write(Storage::settings_file(), str)?;
        Ok(())
    }

    pub fn load() -> Result<Self, Error> {
        let str = fs::read_to_string(Storage::settings_file())?;
        Ok(serde_json::from_str::<Self>(&str)?)
    }
}
