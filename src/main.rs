mod base;
mod model;
mod ui;

use crate::ui::ui_iced::KeystrApp;
use iced::{Sandbox, Settings};

#[tokio::main]
async fn main() {
    let _res = KeystrApp::run(Settings::default());
}
