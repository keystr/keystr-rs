use crate::keystr_model::{KeystrModel, SecurityLevel, SECURITY_LEVELS};

use iced::widget::{button, column, pick_list, row, text, text_input};
use iced::{Alignment, Element, Length, Sandbox};

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Keys,
    Delegate,
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelect(Tab),
    KeysClear,
    KeysGenerate,
    KeysPubkeyInput(String),
    KeysPubkeyImport,
    KeysSecretkeyInput(String),
    KeysSecretkeyImport,
    DelegateDeeChanged(String),
    DelegateDeeGenerate,
    DelegateSign,
    DelegateKindChanged(String),
    DelegateTimeStartChanged(String),
    DelegateTimeEndChanged(String),
    DelegateTimeDaysChanged(String),
    DelegateTimeDaysChangedNoUpdate(String),
    SecurityLevelChange(SecurityLevel),
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
            text("Secret key (nsec):").size(15),
            text_input(
                "nsec secret key",
                &self.model.own_keys.get_nsec(),
                Message::ChangedReadonly,
            )
            .password()
            .size(15),
            row![
                button("Generate new keypair").on_press(Message::KeysGenerate),
                button("Clear keys").on_press(Message::KeysClear),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0),
            row![
                text_input(
                    "npub or hex for public key import",
                    &self.model.own_keys.public_key_input,
                    Message::KeysPubkeyInput,
                )
                .size(15),
                button("Import Public key").on_press(Message::KeysPubkeyImport),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0),
            row![
                text_input(
                    "npub or hex for secret key import",
                    &self.model.own_keys.secret_key_input,
                    Message::KeysSecretkeyInput,
                )
                .password()
                .size(15),
                button("Import Secret key").on_press(Message::KeysSecretkeyImport),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0),
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
                    &self.model.delegator.delegatee_npub_input,
                    Message::DelegateDeeChanged,
                )
                .size(15),
                button("Generate new").on_press(Message::DelegateDeeGenerate),
            ]
            .align_items(Alignment::Fill)
            .spacing(5),
            iced::widget::rule::Rule::horizontal(5),
            row![
                column![text("Event kinds (eg. 'kind=1'):").size(15),]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "kind condition",
                    &self.model.delegator.kind_condition_input,
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
            button("Create Delegation").on_press(Message::DelegateSign),
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
            text("Delegation tag -- Copy this:").size(15),
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

    fn view(&self) -> Element<Message> {
        column![
            text("Nostr Keystore").size(25),
            iced::widget::rule::Rule::horizontal(5),
            text("Check the warnings and set your security level below:").size(20),
            text(&self.model.get_security_warning_secret()).size(15),
            pick_list(
                SECURITY_LEVELS,
                Some(self.model.security_level),
                Message::SecurityLevelChange
            )
            .text_size(15),
            iced::widget::rule::Rule::horizontal(5),
            self.tab_selector(),
            iced::widget::rule::Rule::horizontal(5),
            text(&format!("| {}", &self.model.status.get_butlast())).size(15),
            text(&format!("| {}", &self.model.status.get_last())).size(15),
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
        let mut app = KeystrApp {
            model: KeystrModel::new(),
            current_tab: Tab::Keys,
        };
        app.model.status.set("Keystr started");
        app
    }

    fn title(&self) -> String {
        String::from("Keystr")
    }

    fn update(&mut self, message: Message) {
        match message {
            Message::TabSelect(t) => {
                self.current_tab = t;
            }
            Message::KeysClear => {
                // TODO confirmation
                self.model.own_keys.clear();
                self.model.status.set("Keys cleared");
            }
            Message::KeysGenerate => {
                // TODO confirmation
                self.model.own_keys.generate();
                self.model.status.set("New keypair generated");
            }
            Message::KeysPubkeyInput(s) => self.model.own_keys.public_key_input = s,
            Message::KeysPubkeyImport => {
                match self
                    .model
                    .own_keys
                    .import_public_key(&self.model.own_keys.public_key_input.clone())
                {
                    Err(e) => self.model.status.set_error(&e.to_string()),
                    Ok(_) => self.model.status.set("Public key imported"),
                };
                // cleanup
                self.model.own_keys.public_key_input = String::new();
            }
            Message::KeysSecretkeyInput(s) => self.model.own_keys.secret_key_input = s,
            Message::KeysSecretkeyImport => {
                match self
                    .model
                    .own_keys
                    .import_secret_key(&self.model.own_keys.secret_key_input.clone())
                {
                    Err(e) => self.model.status.set_error(&e.to_string()),
                    Ok(_) => self.model.status.set("Secret key imported"),
                };
                // cleanup
                self.model.own_keys.secret_key_input = String::new();
            }
            Message::DelegateDeeChanged(s) => {
                self.model.delegator.delegatee_npub_input = s;
                if let Err(e) = self.model.delegator.validate_and_update() {
                    self.model.status.set_error(&e.to_string());
                }
            }
            Message::DelegateDeeGenerate => self.model.delegator.generate_random_delegatee(),
            Message::DelegateKindChanged(s) => {
                self.model.delegator.kind_condition_input = s;
                if let Err(e) = self.model.delegator.validate_and_update() {
                    self.model.status.set_error(&e.to_string());
                }
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
                match self.model.own_keys.get_keys() {
                    Err(e) => self.model.status.set_error(&e.to_string()),
                    Ok(keys) => match self.model.delegator.create_delegation(&keys) {
                        Err(e) => self.model.status.set_error(&e.to_string()),
                        Ok(_) => self.model.status.set("Delegation created"),
                    },
                };
            }
            Message::SecurityLevelChange(l) => self.model.security_level = l,
            Message::ChangedReadonly(_s) => {}
        }
    }

    fn view(&self) -> Element<Message> {
        self.view()
    }
}
