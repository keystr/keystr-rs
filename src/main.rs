mod delegator;
mod event_filter;
mod keystore;
mod keystr_model;
mod ui_iced;

use crate::ui_iced::KeystrApp;
use iced::{Sandbox, Settings};

fn main() {
    let _res = KeystrApp::run(Settings::default());
}
