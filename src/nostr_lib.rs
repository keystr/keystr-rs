use nostr_sdk::prelude::schnorr::Signature;
use nostr_sdk::prelude::{
    sha256, sign_delegation, Hash, Keys, Message, Secp256k1, ToBech32, XOnlyPublicKey,
};

// Ideally functionality here should come from a library, such as rust-nostr/nostr

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// Secp256k1 error
    #[error(transparent)]
    Secp256k1(#[from] nostr_sdk::nostr::secp256k1::Error),
    /// Nip19 error
    #[error(transparent)]
    SignatureError(#[from] nostr_sdk::nostr::nips::nip19::Error),
    /// Nip26 error
    #[error(transparent)]
    Nip26Error(#[from] nostr_sdk::nostr::nips::nip26::Error),
}

fn delegation_token(delegatee_pk: &XOnlyPublicKey, conditions: &str) -> String {
    format!("nostr:delegation:{delegatee_pk}:{conditions}")
}

/// Verify delegation signature
pub fn verify_delegation_signature(
    keys: &Keys,
    signature: &Signature,
    delegatee_pk: XOnlyPublicKey,
    conditions: String,
) -> Result<(), Error> {
    let secp = Secp256k1::new();
    let unhashed_token: String = delegation_token(&delegatee_pk, &conditions);
    let hashed_token = sha256::Hash::hash(unhashed_token.as_bytes());
    let message = Message::from_slice(&hashed_token)?;
    secp.verify_schnorr(signature, &message, &keys.public_key())?;
    Ok(())
}

/*
// TODO
struct Conditions {}
*/

/// Delegation tag, as defined in NIP-26
pub struct DelegationTag {
    delegator_pubkey: XOnlyPublicKey,
    conditions: String,
    signature: Signature,
}

impl DelegationTag {
    pub fn get_signature(&self) -> Signature {
        self.signature
    }

    pub fn to_string(&self) -> String {
        match self.to_json(false) {
            Err(_e) => String::new(),
            Ok(s) => s,
        }
    }

    // TODO from_string()

    pub(crate) fn to_json(&self, multiline: bool) -> Result<String, Error> {
        let delegator_npub = self.delegator_pubkey.to_bech32()?;
        let separator = if multiline { "\n" } else { " " };
        let tabulator = if multiline { "\t" } else { "" };
        Ok(format!(
            "[{}{}\"delegation\",{}{}\"{}\",{}{}\"{}\",{}{}\"{}\"{}]",
            separator,
            tabulator,
            separator,
            tabulator,
            delegator_npub,
            separator,
            tabulator,
            self.conditions,
            separator,
            tabulator,
            self.signature.to_string(),
            separator
        ))
    }
}

pub fn create_delegation_tag(
    delegator_keys: &Keys,
    delegatee_pubkey: XOnlyPublicKey,
    conditions_string: &String,
) -> Result<DelegationTag, Error> {
    let signature = sign_delegation(delegator_keys, delegatee_pubkey, conditions_string.clone())?;
    Ok(DelegationTag {
        delegator_pubkey: delegator_keys.public_key(),
        conditions: conditions_string.clone(),
        signature,
    })
}

/*
// TODO
pub fn verify_delegation_tag(
    // tag
) {
}
*/

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use nostr_sdk::prelude::{FromBech32, Keys, SecretKey};

    #[test]
    fn test_delegation_tag_to_json() {
        let delegator_sk = SecretKey::from_bech32(
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae",
        )
        .unwrap();
        let delegator_pubkey = Keys::new(delegator_sk).public_key();
        let conditions = "k=1&reated_at<1678659553".to_string();
        let signature = Signature::from_str("435091ab4c4a11e594b1a05e0fa6c2f6e3b6eaa87c53f2981a3d6980858c40fdcaffde9a4c461f352a109402a4278ff4dbf90f9ebd05f96dac5ae36a6364a976").unwrap();
        let d = DelegationTag {
            delegator_pubkey,
            conditions,
            signature,
        };
        let tag = d.to_json(false).unwrap();
        assert_eq!(tag, "[ \"delegation\", \"npub1rfze4zn25ezp6jqt5ejlhrajrfx0az72ed7cwvq0spr22k9rlnjq93lmd4\", \"k=1&reated_at<1678659553\", \"435091ab4c4a11e594b1a05e0fa6c2f6e3b6eaa87c53f2981a3d6980858c40fdcaffde9a4c461f352a109402a4278ff4dbf90f9ebd05f96dac5ae36a6364a976\" ]");
        let tag2 = d.to_json(true).unwrap();
        assert_eq!(tag2, "[\n\t\"delegation\",\n\t\"npub1rfze4zn25ezp6jqt5ejlhrajrfx0az72ed7cwvq0spr22k9rlnjq93lmd4\",\n\t\"k=1&reated_at<1678659553\",\n\t\"435091ab4c4a11e594b1a05e0fa6c2f6e3b6eaa87c53f2981a3d6980858c40fdcaffde9a4c461f352a109402a4278ff4dbf90f9ebd05f96dac5ae36a6364a976\"\n]");
    }

    #[test]
    fn test_create_delegation_tag() {
        let sk = SecretKey::from_bech32(
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae",
        )
        .unwrap();
        let keys = Keys::new(sk);
        let delegatee_pubkey = XOnlyPublicKey::from_bech32(
            "npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez",
        )
        .unwrap();
        let conditions = "k=1&created_at>1676067553&created_at<1678659553".to_string();

        let tag = create_delegation_tag(&keys, delegatee_pubkey, &conditions).unwrap();

        // verify signature (it's variable)
        let verify_result =
            verify_delegation_signature(&keys, &tag.get_signature(), delegatee_pubkey, conditions);
        assert!(verify_result.is_ok());

        // signature changes, cannot compare to expected constant, use signature from result
        let expected = format!(
            "[ \"delegation\", \"npub1rfze4zn25ezp6jqt5ejlhrajrfx0az72ed7cwvq0spr22k9rlnjq93lmd4\", \"k=1&created_at>1676067553&created_at<1678659553\", \"{}\" ]",
            &tag.signature.to_string());
        assert_eq!(tag.to_string(), expected);

        assert_eq!(tag.to_json(false).unwrap(), expected);
        let expected_multiline = format!(
            "[\n\t\"delegation\",\n\t\"npub1rfze4zn25ezp6jqt5ejlhrajrfx0az72ed7cwvq0spr22k9rlnjq93lmd4\",\n\t\"k=1&created_at>1676067553&created_at<1678659553\",\n\t\"{}\"\n]",
            &tag.signature.to_string());
        assert_eq!(tag.to_json(true).unwrap(), expected_multiline);
    }
}
