use crate::model::error::Error;
use std::fs;
use std::path::PathBuf;

pub(crate) struct Storage {}

/// Folder used to store data, relative to user data dir (~/.local/share)
const LOCAL_STORAGE_FOLDER: &str = "keystr";
/// Public key storage file name, relative to data folder.
const PUBLIC_KEY_FILENAME: &str = "npub";
/// Encrypted secret key storage file name, relative to data folder.
const ENCRYPTED_SECRET_KEY_FILENAME: &str = ".ncrypt";
/// Public key storage file name, relative to data folder.
const SETTINGS_FILENAME: &str = "settings.json";

impl Storage {
    pub fn public_key_file() -> PathBuf {
        Self::full_file_path(PUBLIC_KEY_FILENAME)
    }

    pub fn encrypted_secret_key_file() -> PathBuf {
        Self::full_file_path(ENCRYPTED_SECRET_KEY_FILENAME)
    }

    pub fn settings_file() -> PathBuf {
        Self::full_file_path(SETTINGS_FILENAME)
    }

    pub fn check_create_folder() -> Result<(), Error> {
        let p = Self::get_storage_folder();
        if p.is_dir() {
            return Ok(());
        }
        fs::create_dir(p)?;
        Ok(())
    }

    fn get_storage_folder() -> PathBuf {
        let mut p = dirs::data_local_dir().unwrap_or(PathBuf::from("."));
        p.push(LOCAL_STORAGE_FOLDER);
        p
    }

    fn full_file_path(file_name: &str) -> PathBuf {
        let mut p = Self::get_storage_folder();
        p.push(file_name);
        p
    }
}
