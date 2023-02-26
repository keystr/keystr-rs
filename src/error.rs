#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Key not set (secret key or public key)
    #[error("Key not set")]
    KeyNotSet,
    /// No unsaved changes to save
    #[error("No changes to save")]
    KeyNoChangeToSave,
    /// Saving not allowed
    #[error("Saving not allowed, check settings")]
    KeySaveNotAllowed,
    /// Loading not allowed
    #[error("Loading not allowed, check settings")]
    KeyLoadNotAllowed,
    /// Key error
    #[error(transparent)]
    KeyError(#[from] nostr::key::Error),
    /// NostrLib error
    #[error(transparent)]
    NostrLibError(#[from] crate::nostr_lib::Error),
    /// Nip19 error
    #[error(transparent)]
    SignatureError(#[from] nostr::nips::nip19::Error),
    /// Nip26 error
    #[error(transparent)]
    Nip26Error(#[from] nostr::nips::nip26::Error),
    /// IO error, e.g. file/folder error
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}
