use crate::model::keystr_model::{Action, Confirmation, Event, EventSink, KeystrModel, Modal};
use crate::model::security_settings::{SecurityLevel, SECURITY_LEVELS};
use crate::ui::dialog::Dialog;

use iced::executor;
use iced::time;
use iced::widget::{button, column, container, pick_list, row, text, text_input};
use iced::{Alignment, Application, Command, Element, Length, Subscription, Theme};

use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Keys,
    Delegate,
    Signer,
}

#[derive(Debug, Clone)]
pub(crate) enum Message {
    ChangedReadonly(String),
    ModelAction(Action),
    NoOp,
    Refresh,
    SecurityLevelChange(SecurityLevel),
    TabSelect(Tab),

    KeysPubkeyInput(String),
    KeysToggleHideSecretKey,
    KeysSecretkeyInput(String),
    KeysDecryptPasswordInput(String),
    KeysSavePasswordInput(String),
    KeysSaveRepeatPasswordInput(String),

    DelegateDeeChanged(String),
    DelegateKindChanged(String),
    DelegateTimeStartChanged(String),
    DelegateTimeEndChanged(String),
    DelegateTimeDaysChanged(String),
    DelegateTimeDaysChangedNoUpdate(String),

    SignerUriInput(String),
}

pub(crate) struct KeystrApp {
    pub model: KeystrModel,
    current_tab: Tab,
}

struct AppEventSink {}

impl KeystrApp {
    pub fn new() -> Self {
        Self {
            model: KeystrModel::init(),
            current_tab: Tab::Keys,
        }
    }

    fn tab_selector(&self) -> Element<Message> {
        row![
            button("Keys").on_press(Message::TabSelect(Tab::Keys)),
            button("Delegate").on_press(Message::TabSelect(Tab::Delegate)),
            button("Signer").on_press(Message::TabSelect(Tab::Signer)),
        ]
        .padding(10)
        .spacing(5)
        .align_items(Alignment::Start)
        .into()
    }

    fn tab_keys(&self) -> Element<Message> {
        let label_width = Length::Fixed(150.0);

        let unlock_ui = if self.model.own_keys.is_encrypted_secret_key_set() {
            column![row![
                text("Password is needed to unlock secret key:").size(15),
                text_input(
                    "enter password that was used for encrypting secret key",
                    &self.model.own_keys.decrypt_password_input,
                    Message::KeysDecryptPasswordInput,
                )
                .password()
                .size(15),
                button("Unlock").on_press(Message::ModelAction(Action::KeysUnlock)),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0)]
        } else {
            column![]
        }
        .align_items(Alignment::Fill)
        .spacing(5)
        .padding(0);

        column![
            text("Own Keys").size(25),
            unlock_ui,
            row![
                column![text("Public key (npub):").size(15)]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "npub public key",
                    &self.model.own_keys.get_npub(),
                    Message::ChangedReadonly,
                )
                .size(15),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0),
            row![
                column![text("Secret key (nsec):").size(15)]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                button("Copy TODO").on_press(Message::NoOp), // TODO, TODO confirm
                button(if self.model.own_keys.hide_secret_key {
                    "Show"
                } else {
                    "Hide"
                })
                .on_press(Message::KeysToggleHideSecretKey),
                if self.model.own_keys.hide_secret_key {
                    text_input("(hidden)", "(hidden)", Message::ChangedReadonly)
                } else {
                    text_input(
                        "", // empty, placeholder also shows up asterisked
                        &self.model.own_keys.get_nsec(),
                        Message::ChangedReadonly,
                    )
                    .password()
                }
                .size(15),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0),
            text(if self.model.own_keys.has_unsaved_change {
                "There are Unsaved changes!"
            } else {
                "(no changes)"
            })
            .size(15),
            iced::widget::rule::Rule::horizontal(5),
            row![
                button("Load").on_press(Message::ModelAction(Action::KeysLoad)),
                button("Save").on_press(Message::ModelAction(Action::KeysSave)),
                button("Generate new keypair").on_press(Message::ModelAction(Action::KeysGenerate)),
                button("Clear keys").on_press(Message::ModelAction(Action::KeysClear)),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0),
            text("Password to encrypt secret key:").size(15),
            row![
                column![text("Password:").size(15),]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "enter password for encrypting secret key",
                    &self.model.own_keys.save_password_input,
                    Message::KeysSavePasswordInput,
                )
                .password()
                .size(15),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0),
            row![
                column![text("Repeat password:").size(15),]
                    .align_items(Alignment::Start)
                    .width(label_width)
                    .padding(0),
                text_input(
                    "repeat password",
                    &self.model.own_keys.save_repeat_password_input,
                    Message::KeysSaveRepeatPasswordInput,
                )
                .password()
                .size(15),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0),
            iced::widget::rule::Rule::horizontal(5),
            row![
                text_input(
                    "npub or hex for public key import",
                    &self.model.own_keys.public_key_input,
                    Message::KeysPubkeyInput,
                )
                .size(15),
                button("Import Public key")
                    .on_press(Message::ModelAction(Action::KeysImportPubkey)),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0),
            iced::widget::rule::Rule::horizontal(5),
            row![
                text_input(
                    "npub or hex for secret key import",
                    &self.model.own_keys.secret_key_input,
                    Message::KeysSecretkeyInput,
                )
                .password()
                .size(15),
                button("Import Secret key")
                    .on_press(Message::ModelAction(Action::KeysImportSecretkey)),
            ]
            .align_items(Alignment::Fill)
            .spacing(5)
            .padding(0),
            iced::widget::rule::Rule::horizontal(5),
        ]
        .align_items(Alignment::Fill)
        .spacing(5)
        .padding(20)
        .max_width(600)
        .into()
    }

    fn tab_delegate(&self) -> Element<Message> {
        let label_width = Length::Fixed(150.0);
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
                button("Generate new").on_press(Message::ModelAction(Action::DelegateDeeGenerate)),
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
            button("Create Delegation").on_press(Message::ModelAction(Action::DelegateSign)),
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

    fn tab_signer(&self) -> Element<Message> {
        let connection = &self.model.signer.connection;

        let connection_content: Element<Message> = match connection {
            None => {
                column![
                    text("Status:  Not connected").size(15),
                    text("Enter NostrConnect URI:").size(15),
                    row![
                        text_input(
                            "Nostr Connect URI",
                            &self.model.signer.connect_uri_input,
                            Message::SignerUriInput,
                        )
                        .size(15),
                        button("Paste (X)").on_press(Message::NoOp),
                        button("QR (X)").on_press(Message::NoOp),
                    ]
                    .align_items(Alignment::Center)
                    .spacing(5)
                    .padding(0),
                    button("Connect").on_press(Message::ModelAction(Action::SignerConnect)),
                ]
                // .align_items(Alignment::Fill)
                .spacing(5)
                .padding(0)
                .into()
            }
            Some(conn) => {
                column![
                    if conn.get_pending_count() == 0 {
                        // No pending requests
                        column![text("No pending requests").size(15)]
                            .spacing(5)
                            .padding(0)
                    } else {
                        // There are pending requests, show them
                        let first_req_desc = conn.get_first_request_description();
                        column![
                            text(&format!(
                                "There is a request ({})",
                                conn.get_pending_count()
                            ))
                            .size(15),
                            column![
                                text(first_req_desc).size(15),
                                row![
                                    button("SIGN").on_press(Message::ModelAction(
                                        Action::SignerPendingProcessFirst
                                    )),
                                    button("Ignore").on_press(Message::ModelAction(
                                        Action::SignerPendingIgnoreFirst
                                    )),
                                ]
                                .spacing(5)
                                .padding(0)
                            ]
                            .spacing(5)
                            .padding(0)
                        ]
                        .spacing(5)
                        .padding(0)
                    },
                    text(&format!(
                        "Status:  Connected, through relay '{}' to client '{}'",
                        conn.relay_str,
                        conn.get_client_npub(),
                    ))
                    .size(15),
                    button("Disconnect").on_press(Message::ModelAction(Action::SignerDisconnect)),
                    button("DEBUG Refresh").on_press(Message::Refresh),
                ]
                // .align_items(Alignment::Fill)
                .spacing(5)
                .padding(0)
                .into()
            }
        };

        column![text("Signer").size(25), connection_content]
            // .align_items(Alignment::Fill)
            .spacing(5)
            .padding(20)
            .max_width(600)
            .into()
    }

    fn view_dialog(&self, modal: &Modal) -> Element<Message> {
        container(match modal {
            Modal::Confirmation(Confirmation::KeysClearBeforeAction(_)) => column![
                text("Remove existing keys?").size(25),
                row![
                    button("Yes").on_press(Message::ModelAction(Action::ConfirmationYes)),
                    button("No").on_press(Message::ModelAction(Action::ConfirmationNo)),
                ]
                .align_items(Alignment::Fill)
                .width(Length::Fill)
                .spacing(5)
                .padding(0),
                iced::widget::rule::Rule::horizontal(5),
            ]
            .align_items(Alignment::Fill)
            .width(Length::Fill)
            .spacing(5)
            .padding(20),
            // _ => column![text("?").size(25)]
            //     .align_items(Alignment::Fill)
            //     .width(Length::Fill)
            //     .spacing(5)
            //     .padding(20),
        })
        .width(Length::Fixed(300.0))
        .padding(10)
        .style(iced::theme::Container::Box)
        .into()
    }

    fn view(&self) -> Element<Message> {
        let main_content: Element<Message> = container(
            column![
                text("Nostr Keystore").size(25),
                iced::widget::rule::Rule::horizontal(5),
                text("Check the warnings and set your security level below:").size(20),
                text(&self.model.settings.security.get_security_warning_secret()).size(15),
                pick_list(
                    SECURITY_LEVELS,
                    Some(self.model.settings.security.security_level),
                    Message::SecurityLevelChange
                )
                .text_size(15),
                iced::widget::rule::Rule::horizontal(5),
                self.tab_selector(),
                iced::widget::rule::Rule::horizontal(5),
                text(&format!("| {}", &self.model.status.get_last_n(3))).size(15),
                text(&format!("| {}", &self.model.status.get_last_n(2))).size(15),
                text(&format!("| {}", &self.model.status.get_last())).size(15),
                iced::widget::rule::Rule::horizontal(5),
                match self.current_tab {
                    Tab::Keys => self.tab_keys(),
                    Tab::Delegate => self.tab_delegate(),
                    Tab::Signer => self.tab_signer(),
                },
                iced::widget::rule::Rule::horizontal(5),
            ]
            .height(Length::Fill)
            .padding(10)
            .align_items(Alignment::Fill),
        )
        .padding(10)
        .width(Length::Fill)
        .height(Length::Fill)
        .into();

        if let Some(modal) = &self.model.modal {
            let dialog_content = self.view_dialog(modal);

            Dialog::new(main_content, dialog_content)
                // .on_blur(Message::ModalHide) // non-modal
                .into()
        } else {
            main_content.into()
        }
    }
}

impl Application for KeystrApp {
    type Message = Message;
    type Theme = Theme;
    type Executor = executor::Default;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (KeystrApp::new(), Command::none())
    }

    fn title(&self) -> String {
        String::from("Keystr")
    }

    fn subscription(&self) -> Subscription<Message> {
        // TODO: sample implementation: refresh every 5 secs
        time::every(Duration::from_millis(5000)).map(|_| Message::Refresh)
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::TabSelect(t) => {
                self.current_tab = t;
            }
            Message::ModelAction(action) => {
                self.model.action(action);
            }
            Message::KeysPubkeyInput(s) => self.model.own_keys.public_key_input = s,
            Message::KeysToggleHideSecretKey => {
                self.model.own_keys.hide_secret_key = !self.model.own_keys.hide_secret_key
            }
            Message::KeysSecretkeyInput(s) => self.model.own_keys.secret_key_input = s,
            Message::KeysDecryptPasswordInput(s) => self.model.own_keys.decrypt_password_input = s,
            Message::KeysSavePasswordInput(s) => self.model.own_keys.save_password_input = s,
            Message::KeysSaveRepeatPasswordInput(s) => {
                self.model.own_keys.save_repeat_password_input = s
            }
            Message::DelegateDeeChanged(s) => {
                self.model.delegator.delegatee_npub_input = s;
                if let Err(e) = self.model.delegator.validate_and_update() {
                    self.model.status.set_error(&e.to_string());
                }
            }
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
            Message::SecurityLevelChange(l) => self.model.settings.set_security_level(l),
            Message::SignerUriInput(s) => self.model.signer.connect_uri_input = s,
            Message::ChangedReadonly(_s) => {}
            Message::NoOp => {}
            Message::Refresh => {
                // a message refreshes the UI, no extra action needed here
            }
        }
        Command::none()
    }

    fn view(&self) -> Element<Message> {
        self.view()
    }
}

impl EventSink for AppEventSink {
    fn handle_event(&mut self, event: &Event) {
        // TODO proper handle, -> subscription
        match event {
            Event::SignerConnected => {
                // TODO self.model.status.set("Event: Signer connected"),
                println!("Event: Signer connected");
            }
            Event::SignerNewRequest => {
                println!("Event: New Signer request");
            }
            Event::StatusUpdate => {
                println!("Event: Status update");
            }
        }
    }
}
