use crate::keystr_model::KeystrModel;

use iced::widget::{button, column, row, text, text_input};
use iced::{Alignment, Element, Sandbox};

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Keys,
    Delegate,
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelect(Tab),
    KeysGenerate,
    DelegateDeeChanged(String),
    DelegateDeeGenerate,
    DelegateDeeSign,
    ChangedDummy(String),
}

pub(crate) struct KeystrApp {
    pub model: KeystrModel,

    current_tab: Tab,
}

impl KeystrApp {
    fn tab_selector(&self) -> Element<Message> {
        row![
            button("Keys").on_press(Message::TabSelect(Tab::Keys)),
            button("Delegate").on_press(Message::TabSelect(Tab::Delegate)),
        ]
        .padding(10)
        .spacing(5)
        .align_items(Alignment::Start)
        .into()
    }

    fn tab_keys(&self) -> Element<Message> {
        column![
            text("Own Keys").size(25),
            text("Public key (npub):").size(15),
            text_input(
                "npub public key",
                &self.model.own_keys.get_npub(),
                Message::ChangedDummy,
            )
            .size(15),
            text("Secret key (nsec) TODO hide:").size(15),
            text_input(
                "nsec secret key",
                &self.model.own_keys.get_nsec(),
                Message::ChangedDummy,
            )
            .size(15),
            button("Generate new").on_press(Message::KeysGenerate),
        ]
        .padding(20)
        .align_items(Alignment::Fill)
        .into()
    }

    fn tab_delegate(&self) -> Element<Message> {
        column![
            text("Delegate").size(25),
            text("Delegatee -- npub to delegate to:").size(15),
            text_input(
                "delegatee npub",
                &self.model.delegator.delegatee_npub,
                Message::DelegateDeeChanged,
            )
            .size(15),
            button("Generate new").on_press(Message::DelegateDeeGenerate),
            button("Sign").on_press(Message::DelegateDeeSign),
            text("Signature:").size(15),
            text_input(
                "signature",
                &self.model.delegator.signature,
                Message::ChangedDummy,
            )
            .size(15),
        ]
        .padding(20)
        .align_items(Alignment::Fill)
        .into()
    }

    fn tabs(&self) -> Element<Message> {
        column![
            text("Nostr Keystore").size(25),
            iced::widget::rule::Rule::horizontal(5),
            self.tab_selector(),
            iced::widget::rule::Rule::horizontal(5),
            match self.current_tab {
                Tab::Keys => self.tab_keys(),
                Tab::Delegate => self.tab_delegate(),
            },
            iced::widget::rule::Rule::horizontal(5),
        ]
        .padding(10)
        .align_items(Alignment::Fill)
        .into()
    }
}

impl Sandbox for KeystrApp {
    type Message = Message;

    fn new() -> Self {
        KeystrApp {
            model: KeystrModel::new(),
            current_tab: Tab::Keys,
        }
    }

    fn title(&self) -> String {
        String::from("Keystr")
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::TabSelect(t) => {
                self.current_tab = t;
            }
            Message::KeysGenerate => self.model.own_keys.generate(),
            Message::DelegateDeeChanged(s) => {
                self.model.delegator.delegatee_npub = s;
                self.model.delegator.validate_input();
            }
            Message::DelegateDeeGenerate => self.model.delegator.generate_random_delegatee(),
            Message::DelegateDeeSign => {
                let _r = self.model.delegator.sign(&self.model.own_keys.get_keys());
            }
            Message::ChangedDummy(_s) => {}
        }
    }

    fn view(&self) -> Element<Message> {
        self.tabs()
    }
}
