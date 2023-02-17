#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    // Key not set (secret key or public key)
    #[error("key is not set")]
    KeyNotSet,
    /// Key error
    #[error(transparent)]
    KeyError(#[from] nostr_sdk::nostr::key::Error),
    /// NostrLib error
    #[error(transparent)]
    NostrLibError(#[from] crate::nostr_lib::Error),
    /// Nip19 error
    #[error(transparent)]
    SignatureError(#[from] nostr_sdk::nostr::nips::nip19::Error),
    /// Nip26 error
    #[error(transparent)]
    Nip26Error(#[from] nostr_sdk::nostr::nips::nip26::Error),
}
