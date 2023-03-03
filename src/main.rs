mod delegator;
mod encrypt;
mod error;
mod keystore;
mod keystr_model;
// mod kind_filter;
// mod nostr_lib;
mod security_settings;
mod settings;
mod storage;
mod ui_iced;

use crate::ui_iced::KeystrApp;
use iced::{Sandbox, Settings};

fn main() {
    let _res = KeystrApp::run(Settings::default());
}
