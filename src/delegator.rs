use nostr_sdk::prelude::{sign_delegation, FromBech32, Keys, ToBech32, XOnlyPublicKey};

use std::time::{SystemTime, UNIX_EPOCH};

/// Model for Delegator
pub(crate) struct Delegator {
    // Input for delegatee
    pub delegatee_npub: String,
    // Kind condition (direct input TODO)
    pub kind_condition: String,
    // Validity start time, can be empty
    pub time_cond_start: String,
    // Validity end time, can be empty
    pub time_cond_end: String,
    // Validity in days
    pub time_cond_days: String,
    // Compiled conditions string
    pub conditions: String,
    // Compiled delegation string
    pub delegation_string: String,
    // Resulting signature
    pub signature: String,
    // Compiled delegation tag (contains pubkey, conditions, signature)
    pub delegation_tag: String,
}

impl Delegator {
    pub fn new() -> Self {
        let mut d = Delegator {
            delegatee_npub: String::new(),
            kind_condition: String::new(),
            time_cond_start: String::new(),
            time_cond_end: String::new(),
            time_cond_days: "90".to_string(),
            conditions: String::new(),
            delegation_string: String::new(),
            signature: String::new(),
            delegation_tag: String::new(),
        };
        let _r = d.validate_and_update();
        d
    }

    pub fn validate_and_update(&mut self) -> Result<(), String> {
        let mut cond = Vec::new();
        if self.kind_condition.len() > 0 {
            cond.push(self.kind_condition.clone());
        }
        if self.time_cond_start.len() > 0 {
            cond.push(format!("created_at>{}", self.time_cond_start));
        }
        if self.time_cond_end.len() > 0 {
            cond.push(format!("created_at<{}", self.time_cond_end));
        }
        self.conditions = cond.join("&");

        let delegatee_key = match XOnlyPublicKey::from_bech32(self.delegatee_npub.clone()) {
            Err(e) => return Err(e.to_string()),
            Ok(k) => k,
        };

        // TODO: should come form SDK
        self.delegation_string = format!(
            "nostr:delegation:{}:{}",
            delegatee_key.to_string(),
            self.conditions
        );
        Ok(())
    }

    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub fn time_set_start(&mut self, start: &str) {
        if let Ok(n) = start.parse::<u64>() {
            self.time_cond_start = n.to_string();
            self.time_cond_days = "".to_string();
            let _r = self.validate_and_update();
        }
    }

    pub fn time_set_end(&mut self, end: &str) {
        if let Ok(n) = end.parse::<u64>() {
            self.time_cond_end = n.to_string();
            self.time_cond_days = "".to_string();
            let _r = self.validate_and_update();
        }
    }

    pub fn time_set_days(&mut self, days: &str) {
        if let Ok(n) = days.parse::<u64>() {
            self.time_cond_days = days.to_string();
            let now = Self::current_time();
            self.time_cond_start = now.to_string();
            self.time_cond_end = (now + n * 24 * 3600).to_string();
            let _r = self.validate_and_update();
        }
    }

    pub fn generate_random_delegatee(&mut self) {
        let key = Keys::generate().public_key();
        self.delegatee_npub = key.to_bech32().unwrap();
        let _r = self.validate_and_update();
    }

    pub fn compile_delegation_tag(&self, multiline: bool) -> String {
        let separator = if multiline { "\n" } else { " " };
        let tabulator = if multiline { "\t" } else { "" };
        format!(
            "[{}{}\"delegation\",{}{}\"{}\",{}{}\"{}\",{}{}\"{}\"{}]",
            separator,
            tabulator,
            separator,
            tabulator,
            self.delegatee_npub,
            separator,
            tabulator,
            self.conditions,
            separator,
            tabulator,
            self.signature,
            separator
        )
    }

    /// Create signature. Delegatee pubkey and conditions are taken from self.
    /// Result signature and also updated delegation tag are places in self.
    pub fn sign(&mut self, keys: &Keys) -> Result<(), String> {
        self.validate_and_update()?;
        let delegatee_key = XOnlyPublicKey::from_bech32(self.delegatee_npub.clone()).unwrap(); // TODO handle error
        let sig = match sign_delegation(keys, delegatee_key, self.conditions.clone()) {
            Err(e) => return Err(e.to_string()),
            Ok(s) => s,
        };
        self.signature = sig.to_string();
        self.delegation_tag = self.compile_delegation_tag(false);
        Ok(())
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
        d.kind_condition = "k=1".to_string();
        d.time_cond_start = 1676067553.to_string();
        d.time_cond_end = 1678659553.to_string();
        let _res = d.sign(&keys).unwrap();

        // signature is changing, validate by verify (Note: some internals of sign are reproduced here; sdk should have a verify)
        let delegatee_key = XOnlyPublicKey::from_bech32(d.delegatee_npub.clone()).unwrap();
        let unhashed_token: String = format!("nostr:delegation:{}:{}", delegatee_key, d.conditions);
        assert_eq!(
            unhashed_token,
            "nostr:delegation:bea8aeb6c1657e33db5ac75a83910f77e8ec6145157e476b5b88c6e85b1fab34:k=1&created_at>1676067553&created_at<1678659553"
        );
        let hashed_token = sha256::Hash::hash(unhashed_token.as_bytes());
        let message = Message::from_slice(&hashed_token).unwrap();
        let secp = Secp256k1::new();
        let verify_result = secp.verify_schnorr(
            &Signature::from_str(&d.signature).unwrap(),
            &message,
            &keys.public_key(),
        );
        assert!(verify_result.is_ok());
    }

    #[test]
    fn test_time_set_start() {
        let mut d = Delegator::new();
        d.delegatee_npub =
            "npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez".to_string();
        d.time_set_start("1676067553");
        assert_eq!(d.delegation_string, "nostr:delegation:bea8aeb6c1657e33db5ac75a83910f77e8ec6145157e476b5b88c6e85b1fab34:created_at>1676067553");
    }

    #[test]
    fn test_time_set_end() {
        let mut d = Delegator::new();
        d.delegatee_npub =
            "npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez".to_string();
        d.time_set_end("1678659553");
        assert_eq!(d.delegation_string, "nostr:delegation:bea8aeb6c1657e33db5ac75a83910f77e8ec6145157e476b5b88c6e85b1fab34:created_at<1678659553");
    }

    #[test]
    fn test_time_set_days() {
        let mut d = Delegator::new();
        d.delegatee_npub =
            "npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez".to_string();
        d.time_set_days("11");
        assert_eq!(
            d.time_cond_end.parse::<i64>().unwrap() - d.time_cond_start.parse::<i64>().unwrap(),
            11 * 24 * 60 * 60
        );
    }

    #[test]
    fn test_compile_delegation_tag() {
        let mut d = Delegator::new();
        d.delegatee_npub =
            "npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez".to_string();
        d.conditions = "k=1&reated_at<1678659553".to_string();
        d.signature = "435091ab4c4a11e594b1a05e0fa6c2f6e3b6eaa87c53f2981a3d6980858c40fdcaffde9a4c461f352a109402a4278ff4dbf90f9ebd05f96dac5ae36a6364a976".to_string();
        let tag = d.compile_delegation_tag(true);
        assert_eq!(tag, "[\n\t\"delegation\",\n\t\"npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez\",\n\t\"k=1&reated_at<1678659553\",\n\t\"435091ab4c4a11e594b1a05e0fa6c2f6e3b6eaa87c53f2981a3d6980858c40fdcaffde9a4c461f352a109402a4278ff4dbf90f9ebd05f96dac5ae36a6364a976\"\n]");
        let tag = d.compile_delegation_tag(false);
        assert_eq!(tag, "[ \"delegation\", \"npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez\", \"k=1&reated_at<1678659553\", \"435091ab4c4a11e594b1a05e0fa6c2f6e3b6eaa87c53f2981a3d6980858c40fdcaffde9a4c461f352a109402a4278ff4dbf90f9ebd05f96dac5ae36a6364a976\" ]");
    }
}
