mod model;
mod ui;

use crate::ui::ui_iced::KeystrApp;
use iced::{Sandbox, Settings};

fn main() {
    let _res = KeystrApp::run(Settings::default());
}
