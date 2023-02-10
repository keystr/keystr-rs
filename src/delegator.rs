use nostr_sdk::prelude::{sign_delegation, FromBech32, Keys, ToBech32, XOnlyPublicKey};

/// Model for Delegator
pub struct Delegator {
    // Input for delegatee
    pub delegatee_npub: String,
    pub conditions: String,
    pub signature: String,
}

impl Delegator {
    pub fn new() -> Self {
        Delegator {
            delegatee_npub: String::new(),
            conditions: String::from("k=1"),
            signature: String::new(),
        }
    }

    pub fn validate_input(&self) {
        // TODO
    }

    pub fn generate_random_delegatee(&mut self) {
        let key = Keys::generate().public_key();
        self.delegatee_npub = key.to_bech32().unwrap();
    }

    /// Delegatee and conditions are taken from self
    pub fn sign(&mut self, keys: &Keys) -> Result<String, String> {
        let delegatee_key = XOnlyPublicKey::from_bech32(self.delegatee_npub.clone()).unwrap(); // TODO handle error
        let sig = match sign_delegation(keys, delegatee_key, self.conditions.clone()) {
            Err(e) => return Err(e.to_string()),
            Ok(s) => s,
        };
        self.signature = sig.to_string();
        Ok(self.signature.to_string())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nostr_sdk::prelude::schnorr::Signature;
    use nostr_sdk::prelude::Hash;
    use nostr_sdk::prelude::{sha256, KeyPair, Message, Secp256k1, SecretKey};
    use std::str::FromStr;

    #[test]
    fn test_sign_and_verify_lowlevel() {
        let sk = SecretKey::from_bech32(
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae",
        )
        .unwrap();
        let secp = Secp256k1::new();
        let keypair = KeyPair::from_secret_key(&secp, &sk);
        let dummy_message = "Dummy message to be hashed and signed";
        let msg_hash = sha256::Hash::hash(dummy_message.as_bytes());
        let message = Message::from_slice(&msg_hash).unwrap();
        let signature = secp.sign_schnorr(&message, &keypair);

        // signature is changing, validate by verify
        let (pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
        let verify_result = secp.verify_schnorr(&signature, &message, &pubkey);
        assert!(verify_result.is_ok());
    }

    #[test]
    fn test_sign() {
        let sk = SecretKey::from_bech32(
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae",
        )
        .unwrap();
        let keys = Keys::new(sk);

        let mut d = Delegator::new();
        d.delegatee_npub =
            "npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez".to_string();
        d.conditions = "k=1".to_string();
        let sig = d.sign(&keys).unwrap();

        // signature is changing, validate by verify (Note: some internals of sign are reproduced here; sdk should have a verify)
        let delegatee_key = XOnlyPublicKey::from_bech32(d.delegatee_npub.clone()).unwrap();
        let unhashed_token: String = format!("nostr:delegation:{}:{}", delegatee_key, d.conditions);
        assert_eq!(
            unhashed_token,
            "nostr:delegation:bea8aeb6c1657e33db5ac75a83910f77e8ec6145157e476b5b88c6e85b1fab34:k=1"
        );
        let hashed_token = sha256::Hash::hash(unhashed_token.as_bytes());
        let message = Message::from_slice(&hashed_token).unwrap();
        let secp = Secp256k1::new();
        let verify_result = secp.verify_schnorr(
            &Signature::from_str(&sig).unwrap(),
            &message,
            &keys.public_key(),
        );
        assert!(verify_result.is_ok());
    }
}
