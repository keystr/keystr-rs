use crate::model::error::Error;
use crate::model::keystore::KeySigner;
use crate::model::status_messages::StatusMessages;

use nostr::nips::nip46::{Message, Request};
use nostr::prelude::{EventBuilder, Filter, Keys, Kind, NostrConnectURI, ToBech32, XOnlyPublicKey};
use nostr_sdk::prelude::{decrypt, Client, Options, RelayPoolNotification, Response, Timestamp};

use crossbeam::channel;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Handle;

/// Model for Signer
#[readonly::make]
pub(crate) struct Signer {
    app_id_keys: Keys,
    #[readonly]
    connection: Option<Arc<SignerConnection>>,
    pub connect_uri_input: String,
}

/// Represents an active Nostr Connect connection
pub(crate) struct SignerConnection {
    // uri: NostrConnectURI,
    pub client_pubkey: XOnlyPublicKey,
    pub relay_str: String,
    relay_client: Client,
    key_signer: KeySigner,
    /// Holds pending requests (mostly Sign requests), and can handle them
    requests: Mutex<Vec<SignatureReqest>>,
}

#[derive(Clone)]
pub(crate) struct SignatureReqest {
    req: Message,
    sender_pubkey: XOnlyPublicKey,
}

impl Signer {
    pub fn new(app_id: &Keys) -> Self {
        Signer {
            app_id_keys: app_id.clone(),
            connection: None,
            connect_uri_input: String::new(),
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

    pub fn pending_process_first_action(&mut self, status: &mut StatusMessages) {
        if let Some(conn) = &self.connection {
            let first_desc = conn.get_first_request_description();
            conn.action_first_req_process();
            status.set(&format!("Processed request '{}'", first_desc));
        }
    }

    pub fn pending_ignore_first_action(&mut self, status: &mut StatusMessages) {
        if let Some(conn) = &self.connection {
            let first_desc = conn.get_first_request_description();
            conn.action_first_req_remove();
            status.set(&format!("Removed request '{}'", first_desc));
        }
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

    pub fn add_request(&self, req: Message, sender_pubkey: XOnlyPublicKey) {
        self.requests
            .lock()
            .unwrap()
            .push(SignatureReqest { req, sender_pubkey });
    }

    pub fn get_pending_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    pub fn get_first_request_description(&self) -> String {
        let locked = self.requests.lock().unwrap();
        let first = locked.get(0);
        match first {
            None => "-".to_string(),
            Some(f) => f.description(),
        }
    }

    pub fn action_first_req_process(&self) {
        let mut locked = self.requests.lock().unwrap();
        let first = locked.first();
        if let Some(req) = first {
            if let Message::Request { id, .. } = &req.req {
                if let Ok(request) = &req.req.to_request() {
                    match request {
                        Request::SignEvent(unsigned_event) => {
                            let unsigned_id = unsigned_event.id;
                            if let Ok(signature) =
                                self.key_signer.sign(unsigned_id.as_bytes().to_vec())
                            {
                                let response_msg =
                                    Message::response(id.clone(), Response::SignEvent(signature));
                                let _ = send_message_blocking(
                                    &self.relay_client,
                                    &response_msg,
                                    &req.sender_pubkey,
                                    tokio::runtime::Handle::current(),
                                );
                            }
                        }
                        // ignore other requests
                        _ => {}
                    }
                }
            }
        }
        let _ = locked.remove(0);
    }

    pub fn action_first_req_remove(&self) {
        let _ = self.requests.lock().unwrap().remove(0);
    }
}

const PREVIEW_CONTENT_LEN: usize = 100;

fn shortened_text(text: &str, max_len: usize) -> String {
    if text.len() < max_len {
        text.to_string()
    } else {
        format!("{}..", text[0..max_len].to_string())
    }
}

impl SignatureReqest {
    pub fn description(&self) -> String {
        match self.req.to_request() {
            Err(_) => "(not request, no action needed)".to_string(),
            Ok(req) => match req {
                Request::SignEvent(unsigned_event) => {
                    format!(
                        "Signature requested for message: '{}'",
                        shortened_text(&unsigned_event.content, PREVIEW_CONTENT_LEN)
                    )
                }
                _ => format!("({}, no action needed)", req.method()),
            },
        }
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

fn send_message_blocking(
    relay_client: &Client,
    msg: &Message,
    receiver_pubkey: &XOnlyPublicKey,
    handle: Handle,
) -> Result<(), Error> {
    let (tx, rx) = channel::bounded(1);
    let relay_client_clone = relay_client.clone();
    let msg_clone = msg.clone();
    let receiver_pubkey_clone = receiver_pubkey.clone();
    handle.spawn(async move {
        let res = send_message(&relay_client_clone, &msg_clone, &receiver_pubkey_clone).await;
        let _ = tx.send(res);
    });
    let res = rx.recv()?;
    res
}

async fn relay_connect(
    uri_str: &str,
    connect_id_keys: &Keys,
    key_signer: KeySigner,
) -> Result<Arc<SignerConnection>, Error> {
    let uri = &NostrConnectURI::from_str(uri_str)?;
    let connect_client_id_pubkey = uri.public_key.clone();
    let relay = &uri.relay_url;

    let opts = Options::new().wait_for_send(true);
    let relay_client = Client::new_with_opts(&connect_id_keys, opts);
    relay_client.add_relay(relay.to_string(), None).await?;
    // TODO: SDK does not give an error here
    relay_client.connect().await;

    let connection = Arc::new(SignerConnection {
        // uri: uri.clone(),
        relay_str: relay.to_string(),
        relay_client,
        client_pubkey: connect_client_id_pubkey,
        key_signer: key_signer.clone(),
        requests: Mutex::new(Vec::new()),
    });

    let _res = start_handler_loop(connection.clone(), tokio::runtime::Handle::current())?;

    // Send connect ACK
    let msg = Message::request(Request::Connect(connect_id_keys.public_key()));
    let _ = send_message(&connection.relay_client, &msg, &connect_client_id_pubkey).await?;

    Ok(connection)
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
) -> Result<Arc<SignerConnection>, Error> {
    let (tx, rx) = channel::bounded(1);
    let uri_str_clone = uri_str.to_owned();
    let connect_id_keys_clone = connect_id_keys.clone();
    let key_signer_clone = key_signer.clone();
    handle.spawn(async move {
        let conn_res =
            relay_connect(&uri_str_clone, &connect_id_keys_clone, key_signer_clone).await;
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
fn start_handler_loop(connection: Arc<SignerConnection>, handle: Handle) -> Result<(), Error> {
    // let (tx, rx) = channel::bounded(1);
    let connection_clone = connection.clone();
    handle.spawn(async move {
        let _res = wait_and_handle_messages(connection_clone).await;
        // let _ = tx.send(res);
    });
    // rx.recv()?
    Ok(())
}

async fn wait_and_handle_messages(connection: Arc<SignerConnection>) -> Result<(), Error> {
    let relay_client = &connection.relay_client;
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
                            let _ = handle_request_message(connection.clone(), &msg, &event.pubkey)
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
    connection: Arc<SignerConnection>,
    msg: &Message,
    sender_pubkey: &XOnlyPublicKey,
) -> Result<(), Error> {
    println!("DEBUG: New message received {}", message_method(msg));
    let relay_client = &connection.relay_client;
    let key_signer = &connection.key_signer;

    if let Message::Request { id, .. } = msg {
        if let Ok(req) = &msg.to_request() {
            match req {
                Request::Describe => {
                    println!("DEBUG: Describe received");
                    let values = serde_json::json!(["describe", "get_public_key", "sign_event"]);
                    let response_msg = Message::response(id.clone(), Response::Describe(values));
                    let _ = send_message(relay_client, &response_msg, sender_pubkey).await?;
                }
                Request::GetPublicKey => {
                    // Return the signer pubkey
                    println!("DEBUG: GetPublicKey received");
                    let response_msg = Message::response(
                        id.clone(),
                        Response::GetPublicKey(key_signer.get_public_key()),
                    );
                    let _ = send_message(relay_client, &response_msg, sender_pubkey).await?;
                }
                Request::SignEvent(_) => {
                    // This request needs user processing, store it
                    connection.add_request(msg.clone(), sender_pubkey.clone());
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
