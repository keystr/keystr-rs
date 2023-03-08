use crate::model::error::Error;
use crate::model::keystore::KeySigner;
use crate::model::status_messages::StatusMessages;

use nostr::nips::nip46::{Message, Request};
use nostr::prelude::{EventBuilder, Filter, Keys, Kind, NostrConnectURI, ToBech32, XOnlyPublicKey};
use nostr_sdk::prelude::{decrypt, Client, Options, RelayPoolNotification, Response, Timestamp};

use crossbeam::channel;
use std::str::FromStr;
use std::time::Duration;
use tokio::runtime::Handle;

/// Model for Signer
#[readonly::make]
pub(crate) struct Signer {
    app_id_keys: Keys,
    #[readonly]
    connection: Option<SignerConnection>,
    pub connect_uri_input: String,
}

/// Represents an active Nostr Connect connection
pub(crate) struct SignerConnection {
    // uri: NostrConnectURI,
    pub client_pubkey: XOnlyPublicKey,
    pub relay_str: String,
    relay_client: Client,
}

impl Signer {
    pub fn new(app_id: &Keys) -> Self {
        Signer {
            app_id_keys: app_id.clone(),
            connection: None,
            connect_uri_input: "nostrconnect://79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3?relay=wss%3A%2F%2Fnos.lol%2F&metadata=%7B%22name%22%3A%22NoConnect-Client%22%2C%22url%22%3A%22https%3A%2F%2Fexample.com%2F%22%7D".to_string(),
                //String::new(),
        }
    }

    fn connect(&mut self, uri_str: &str, key_signer: &KeySigner) -> Result<(), Error> {
        if self.connection.is_some() {
            return Err(Error::SignerAlreadyConnected);
        }
        let handle = tokio::runtime::Handle::current();
        let conn = relay_connect_blocking(uri_str, &self.app_id_keys, key_signer, handle)?;
        self.connection = Some(conn);
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        if let Some(conn) = &self.connection {
            let handle = tokio::runtime::Handle::current();
            let _res = relay_disconnect_blocking(conn.relay_client.clone(), handle)?;
        }
        self.connection = None;
        Ok(())
    }

    pub fn connect_action(&mut self, key_signer: KeySigner, status: &mut StatusMessages) {
        let uri_input = self.connect_uri_input.clone();
        match self.connect(&uri_input, &key_signer) {
            Err(e) => status.set_error(&format!("Could not connect to relay: {}", e.to_string())),
            Ok(_) => status.set(&format!(
                "Signer connected (relay: {}, client npub: {})",
                &self.get_relay_str(),
                &self.get_client_npub(),
            )),
        }
    }

    pub fn disconnect_action(&mut self, status: &mut StatusMessages) {
        if let Some(_conn) = &self.connection {
            let _res_ignore = self.disconnect();
            status.set("Signer disconnected");
        }
        self.connection = None;
    }

    fn get_relay_str(&self) -> String {
        match &self.connection {
            Some(conn) => conn.relay_str.clone(),
            None => "-".to_string(),
        }
    }

    fn get_client_npub(&self) -> String {
        if let Some(conn) = &self.connection {
            conn.client_pubkey.to_bech32().unwrap_or_default()
        } else {
            "-".to_string()
        }
    }
}

impl SignerConnection {
    pub fn get_client_npub(&self) -> String {
        self.client_pubkey.to_bech32().unwrap_or_default()
    }
}

async fn send_message(
    relay_client: &Client,
    msg: &Message,
    receiver_pubkey: &XOnlyPublicKey,
) -> Result<(), Error> {
    let keys = relay_client.keys();
    let event =
        EventBuilder::nostr_connect(&keys, *receiver_pubkey, msg.clone())?.to_event(&keys)?;
    relay_client.send_event(event).await?;
    println!("DEBUG: Message sent, {:?}", msg);
    Ok(())
}

async fn relay_connect(
    uri_str: &str,
    connect_id_keys: &Keys,
    key_signer: &KeySigner,
) -> Result<SignerConnection, Error> {
    let uri = &NostrConnectURI::from_str(uri_str)?;
    let connect_client_id_pubkey = uri.public_key.clone();
    let relay = &uri.relay_url;

    let opts = Options::new().wait_for_send(true);
    let relay_client = Client::new_with_opts(&connect_id_keys, opts);
    relay_client.add_relay(relay.to_string(), None).await?;
    // TODO: SDK does not give an error here
    relay_client.connect().await;

    let _res = start_handler_loop(&relay_client, key_signer, tokio::runtime::Handle::current())?;

    // Send connect ACK
    let msg = Message::request(Request::Connect(connect_id_keys.public_key()));
    let _ = send_message(&relay_client, &msg, &connect_client_id_pubkey).await?;

    Ok(SignerConnection {
        // uri: uri.clone(),
        relay_str: relay.to_string(),
        relay_client,
        client_pubkey: connect_client_id_pubkey,
    })
}

async fn relay_disconnect(relay_client: Client) -> Result<(), Error> {
    let _res = relay_client.disconnect().await?;
    Ok(())
}

fn relay_connect_blocking(
    uri_str: &str,
    connect_id_keys: &Keys,
    key_signer: &KeySigner,
    handle: Handle,
) -> Result<SignerConnection, Error> {
    let (tx, rx) = channel::bounded(1);
    let uri_str_clone = uri_str.to_owned();
    let connect_id_keys_clone = connect_id_keys.clone();
    let key_signer_clone = key_signer.clone();
    handle.spawn(async move {
        let conn_res =
            relay_connect(&uri_str_clone, &connect_id_keys_clone, &key_signer_clone).await;
        let _ = tx.send(conn_res);
    });
    let conn = rx.recv()?;
    conn
}

fn relay_disconnect_blocking(relay_client: Client, handle: Handle) -> Result<(), Error> {
    let (tx, rx) = channel::bounded(1);
    let relay_client_clone = relay_client.clone();
    handle.spawn(async move {
        let disconn_res = relay_disconnect(relay_client_clone).await;
        let _ = tx.send(disconn_res);
    });
    rx.recv()?
}

fn message_method(msg: &Message) -> String {
    match &msg {
        Message::Request { method, .. } => format!("request {method}"),
        Message::Response { .. } => "response".to_string(),
    }
}

/// Start event handling loop in the background, asynchrnous, fire-and-forget
// TODO: Close loop on disconnect!
fn start_handler_loop(
    relay_client: &Client,
    key_signer: &KeySigner,
    handle: Handle,
) -> Result<(), Error> {
    // let (tx, rx) = channel::bounded(1);
    let relay_client_clone = relay_client.clone();
    let key_signer_clone = key_signer.clone();
    handle.spawn(async move {
        let _res = wait_and_handle_messages(&relay_client_clone, &key_signer_clone).await;
        // let _ = tx.send(res);
    });
    // rx.recv()?
    Ok(())
}

async fn wait_and_handle_messages(
    relay_client: &Client,
    key_signer: &KeySigner,
) -> Result<(), Error> {
    let keys = relay_client.keys();

    relay_client
        .subscribe(vec![Filter::new()
            .pubkey(keys.public_key())
            .kind(Kind::NostrConnect)
            .since(Timestamp::now() - Duration::from_secs(10))])
        .await;
    println!("DEBUG: Subscribed to relay events ...");
    println!("DEBUG: Waiting for messages ...");

    loop {
        let mut notifications = relay_client.notifications();
        while let Ok(notification) = notifications.recv().await {
            if let RelayPoolNotification::Event(_url, event) = notification {
                if event.kind == Kind::NostrConnect {
                    match decrypt(&keys.secret_key()?, &event.pubkey, &event.content) {
                        Ok(msg) => {
                            let msg = Message::from_json(msg)?;
                            let _ = handle_request_message(
                                &relay_client,
                                &msg,
                                &event.pubkey,
                                key_signer,
                            )
                            .await?;
                        }
                        Err(e) => eprintln!("DEBUG: Impossible to decrypt NIP46 message: {e}"),
                    }
                }
            }
        }
    }
    // relay_client.unsubscribe().await;
}

async fn handle_request_message(
    relay_client: &Client,
    msg: &Message,
    sender_pubkey: &XOnlyPublicKey,
    key_signer: &KeySigner,
) -> Result<(), Error> {
    println!("DEBUG: New message received {}", message_method(msg));

    if let Message::Request { id, .. } = msg {
        if let Ok(req) = msg.to_request() {
            match req {
                Request::Describe => {
                    println!("DEBUG: Describe received");
                    let values = serde_json::json!(["describe", "get_public_key", "sign_event"]);
                    let response_msg = Message::response(id.clone(), Response::Describe(values));
                    let _ = send_message(relay_client, &response_msg, sender_pubkey).await?;
                }
                Request::GetPublicKey => {
                    println!("DEBUG: GetPublicKey received");
                    let response_msg = Message::response(
                        id.clone(),
                        Response::GetPublicKey(key_signer.get_public_key()),
                    );
                    let _ = send_message(relay_client, &response_msg, sender_pubkey).await?;
                }
                Request::SignEvent(unsigned_event) => {
                    println!("DEBUG: SignEvent received");
                    let unsigned_id = unsigned_event.id;
                    let signature = key_signer.sign(unsigned_id.as_bytes().to_vec())?;
                    let response_msg =
                        Message::response(id.clone(), Response::SignEvent(signature));
                    let _ = send_message(relay_client, &response_msg, sender_pubkey).await?;
                }
                _ => {
                    println!("DEBUG: Unhandled Request {:?}", msg.to_request());
                }
            };
        } else {
            println!("DEBUG: Could not extract Request, ignoring");
        }
    } else {
        println!("DEBUG: Not a Request, ignoring");
    }
    Ok(())
}
