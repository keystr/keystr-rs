use crate::keystr_model::KeystrModel;

use iced::{Alignment, Element, Sandbox};
use iced::widget::{button, column, text, text_input};

pub(crate) struct KeystrApp {
    pub model: KeystrModel,
}

#[derive(Debug, Clone)]
pub enum Message {
    KeysGenerate,
    ChangedDummy(String),
}

impl Sandbox for KeystrApp {
    type Message = Message;

    fn new() -> Self {
        KeystrApp {
            model: KeystrModel::new(),
        }
    }

    fn title(&self) -> String {
        String::from("Keystr")
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::KeysGenerate => self.model.keystore.generate(),
            Message::ChangedDummy(_s) => {}
        }
    }

    fn view(&self) -> Element<Message> {
        column![
            text("Nostr Keystore").size(25),
            text("Own Keys").size(15),
            text("Public key (npub):").size(15),
            text_input(
                "npub public key",
                &self.model.keystore.get_npub(),
                Message::ChangedDummy,
            ).size(15),
            button("Generate new").on_press(Message::KeysGenerate),
         ]
        .padding(20)
        .align_items(Alignment::Fill)
        .into()
    }
}
