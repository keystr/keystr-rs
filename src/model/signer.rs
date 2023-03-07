use crate::model::error::Error;
use crate::model::status_messages::StatusMessages;
use crate::ui::ui_iced::KeystrApp;
use crossbeam::channel;
use nostr::nips::nip46::{Message, Request};
use nostr::prelude::{EventBuilder, Keys, NostrConnectURI, XOnlyPublicKey};
use nostr_sdk::client::{Client, Options};
use std::str::FromStr;
use tokio::io::AsyncReadExt;
use tokio::runtime::Handle;
use tokio::task;

/// Model for Signer
pub(crate) struct Signer {
    app_id_keys: Keys,
    connection: Option<SignerConnection>,
    pub connect_uri_input: String,
}

/// Represents an active Nostr Connect connection
struct SignerConnection {
    uri: NostrConnectURI,
    relay_str: String,
    // relay_client: Client,
    app_pubkey: XOnlyPublicKey,
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

    pub fn connect(&mut self, uri_str: &str) -> Result<(), Error> {
        if self.connection.is_some() {
            return Err(Error::SignerAlreadyConnected);
        }
        let uri = &NostrConnectURI::from_str(uri_str)?;
        let app_pubkey = uri.public_key.clone();
        let relay = &uri.relay_url;
        println!("Relay {relay}");

        // let opts = Options::new().wait_for_send(true);
        // let relay_client = Client::new_with_opts(&self.app_id_keys, opts);
        // relay_client.add_relay(relay.to_string(), None).await?;
        // relay_client.connect().await;

        self.connection = Some(SignerConnection {
            uri: uri.clone(),
            relay_str: relay.to_string(),
            // relay_client,
            app_pubkey,
        });
        Ok(())
    }

    /*
    pub fn connect_block(&mut self, uri_str: &str, handle: Handle) -> Result<(), Error> {
        let (tx, rx) = channel::bounded(1);
        handle.spawn(async move {
            let conn_res = self.connect(uri_str).await;
            let _ = tx.send(conn_res);
        });
        Ok(rx.recv()??)
    }
    */

    pub fn connect_action(&mut self, signer_keys: &Keys, status: &mut StatusMessages) {
        let uri_input = self.connect_uri_input.clone();
        let handle = tokio::runtime::Handle::current();
        let res = self.connect(&uri_input);
        let res = connect_block(uri_input, &self.app_id_keys, signer_keys, handle);
        //, handle);
        match res {
            Err(e) => status.set_error_err(&e),
            Ok(_) => status.set(&format!(
                "Signer connected, relay {}",
                &self.get_relay_str()
            )),
        }
    }

    fn get_relay_str(&self) -> String {
        match &self.connection {
            None => "-".to_string(),
            Some(conn) => conn.relay_str.clone(),
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
    println!("Message sent, {:?}", msg);
    Ok(())
}

async fn connect_async(uri_str: &str, app_id_keys: &Keys, signer_keys: &Keys) -> Result<(), Error> {
    let uri = &NostrConnectURI::from_str(uri_str)?;
    let app_pubkey = uri.public_key.clone();
    let relay = &uri.relay_url;
    println!("Relay {relay}");

    let opts = Options::new().wait_for_send(true);
    let relay_client = Client::new_with_opts(&app_id_keys, opts);
    relay_client.add_relay(relay.to_string(), None).await?;
    relay_client.connect().await;

    // Send connect ACK
    let msg = Message::request(Request::Connect(signer_keys.public_key()));
    let _ = send_message(&relay_client, &msg, &app_pubkey).await?;

    Ok(())
}

fn connect_block(
    uri_str: String,
    app_id_keys: &Keys,
    signer_keys: &Keys,
    handle: Handle,
) -> Result<(), Error> {
    let (tx, rx) = channel::bounded(1);
    let uri_str_clone = uri_str.clone();
    let app_id_keys_clone = app_id_keys.clone();
    let signer_keys_clone = signer_keys.clone();
    handle.spawn(async move {
        let conn_res = connect_async(&uri_str_clone, &app_id_keys_clone, &signer_keys_clone).await;
        let _ = tx.send(conn_res);
    });
    Ok(rx.recv()??)
}
