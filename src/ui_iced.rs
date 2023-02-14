use crate::keystr_model::KeystrModel;

use iced::widget::{button, column, row, text, text_input};
use iced::{Alignment, Element, Length, Sandbox};

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
    DelegateSign,
    DelegateKindChanged(String),
    DelegateTimeStartChanged(String),
    DelegateTimeEndChanged(String),
    DelegateTimeDaysChanged(String),
    DelegateTimeDaysChangedNoUpdate(String),
    ChangedReadonly(String),
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
                Message::ChangedReadonly,
            )
            .size(15),
            text("Secret key (nsec) TODO hide:").size(15),
            text_input(
                "nsec secret key",
                &self.model.own_keys.get_nsec(),
                Message::ChangedReadonly,
            )
            .size(15),
            button("Generate new").on_press(Message::KeysGenerate),
        ]
        .align_items(Alignment::Fill)
        .spacing(5)
        .padding(20)
        .max_width(600)
        .into()
    }

    fn tab_delegate(&self) -> Element<Message> {
        let label_width = Length::Units(150);
        column![
            text("Delegate").size(25),
            text("Delegatee -- npub to delegate to:").size(15),
            row![
                text_input(
                    "delegatee npub",
                    &self.model.delegator.delegatee_npub,
                    Message::DelegateDeeChanged,
                )
                .size(15),
                button("Generate new").on_press(Message::DelegateDeeGenerate),
            ]
            .align_items(Alignment::Fill)
            .spacing(5),
            iced::widget::rule::Rule::horizontal(5),
            row![
                column![text("Event kinds (eg. 'k=1'):").size(15),]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "kind condition",
                    &self.model.delegator.kind_condition,
                    Message::DelegateKindChanged,
                )
                .size(15),
            ]
            .align_items(Alignment::Center)
            .spacing(5)
            .padding(0),
            iced::widget::rule::Rule::horizontal(5),
            row![
                column![text("Time start:").size(15),]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "time start",
                    &self.model.delegator.time_cond_start,
                    Message::DelegateTimeStartChanged,
                )
                .size(15),
            ]
            .align_items(Alignment::Center)
            .spacing(5)
            .padding(0),
            row![
                column![text("Time end:").size(15),]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "time end",
                    &self.model.delegator.time_cond_end,
                    Message::DelegateTimeEndChanged,
                )
                .size(15),
            ]
            .align_items(Alignment::Center)
            .spacing(5)
            .padding(0),
            row![
                column![text("Time days:").size(15),]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "time duration in days",
                    &self.model.delegator.time_cond_days,
                    Message::DelegateTimeDaysChangedNoUpdate,
                )
                .size(15),
                button("Set").on_press(Message::DelegateTimeDaysChanged(
                    self.model.delegator.time_cond_days.clone()
                )),
            ]
            .align_items(Alignment::Center)
            .spacing(5)
            .padding(0),
            iced::widget::rule::Rule::horizontal(5),
            row![
                column![text("Condition string:").size(15),]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "conditions",
                    &self.model.delegator.conditions,
                    Message::ChangedReadonly,
                )
                .size(15),
            ]
            .align_items(Alignment::Center)
            .spacing(5)
            .padding(0),
            row![
                column![text("Delegation string:").size(15),]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "delegation string",
                    &self.model.delegator.delegation_string,
                    Message::ChangedReadonly,
                )
                .size(15),
            ]
            .align_items(Alignment::Center)
            .spacing(5)
            .padding(0),
            iced::widget::rule::Rule::horizontal(5),
            button("Sign").on_press(Message::DelegateSign),
            row![
                column![text("Signature:").size(15),]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "signature",
                    &self.model.delegator.signature,
                    Message::ChangedReadonly,
                )
                .size(15),
            ]
            .align_items(Alignment::Center)
            .spacing(5)
            .padding(0),
            iced::widget::rule::Rule::horizontal(5),
            text("Delegation tag:").size(15),
            text_input(
                "delegation tag",
                &self.model.delegator.delegation_tag,
                Message::ChangedReadonly,
            )
            .size(15),
        ]
        .align_items(Alignment::Fill)
        .spacing(5)
        .padding(20)
        .max_width(600)
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
                let _r = self.model.delegator.validate_and_update();
            }
            Message::DelegateDeeGenerate => self.model.delegator.generate_random_delegatee(),
            Message::DelegateKindChanged(s) => {
                self.model.delegator.kind_condition = s;
                let _r = self.model.delegator.validate_and_update();
            }
            Message::DelegateTimeStartChanged(s) => {
                self.model.delegator.time_set_start(&s);
            }
            Message::DelegateTimeEndChanged(s) => {
                self.model.delegator.time_set_end(&s);
            }
            Message::DelegateTimeDaysChanged(s) => {
                self.model.delegator.time_set_days(&s);
            }
            Message::DelegateTimeDaysChangedNoUpdate(s) => {
                self.model.delegator.time_cond_days = s;
            }
            Message::DelegateSign => {
                let _r = self.model.delegator.sign(&self.model.own_keys.get_keys());
            }
            Message::ChangedReadonly(_s) => {}
        }
    }

    fn view(&self) -> Element<Message> {
        self.tabs()
    }
}