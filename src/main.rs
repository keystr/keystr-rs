mod keystore;
mod keystr_model;
mod ui_iced;

use crate::ui_iced::KeystrApp;
use iced::{Sandbox, Settings};

fn main() {
    println!("keystr!"); // TODO remove

    let _res = KeystrApp::run(Settings::default());
}
