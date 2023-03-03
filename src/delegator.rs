use crate::error::Error;

use nostr::prelude::{
    Conditions, DelegationTag, DelegationToken, FromBech32, Keys, ToBech32, XOnlyPublicKey,
};

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Model for Delegator
pub(crate) struct Delegator {
    // Input for delegatee
    pub delegatee_npub_input: String,
    // Kind condition
    pub kind_condition_input: String,
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
            delegatee_npub_input: String::new(),
            kind_condition_input: String::new(),
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

    pub fn validate_and_update(&mut self) -> Result<(), Error> {
        let mut cond = Vec::new();
        if self.kind_condition_input.len() > 0 {
            cond.push(self.kind_condition_input.clone());
        }
        if self.time_cond_start.len() > 0 {
            cond.push(format!("created_at>{}", self.time_cond_start));
        }
        if self.time_cond_end.len() > 0 {
            cond.push(format!("created_at<{}", self.time_cond_end));
        }
        self.conditions = cond.join("&");

        let delegatee_key = XOnlyPublicKey::from_bech32(self.delegatee_npub_input.clone())?;

        let conditions_struct = Conditions::from_str(&self.conditions)?;
        self.delegation_string = DelegationToken::new(delegatee_key, conditions_struct).to_string();
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
        self.delegatee_npub_input = key.to_bech32().unwrap();
        let _r = self.validate_and_update();
    }

    /// Create delegation tag (incl. signature). Delegatee pubkey and conditions are taken from self.
    /// Result signature and also updated delegation tag are places in self.
    pub fn create_delegation(&mut self, keys: &Keys) -> Result<(), Error> {
        self.validate_and_update()?;
        let delegatee_key = XOnlyPublicKey::from_bech32(self.delegatee_npub_input.clone())?;

        let tag = DelegationTag::new(
            &keys,
            delegatee_key,
            Conditions::from_str(&self.conditions.clone())?,
        )?;
        self.delegation_tag = tag.to_string();
        self.signature = tag.signature().to_string();
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nostr::prelude::SecretKey;

    #[test]
    fn test_create_delegation() {
        let sk = SecretKey::from_bech32(
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae",
        )
        .unwrap();
        let keys = Keys::new(sk);

        let mut d = Delegator::new();
        d.delegatee_npub_input =
            "npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez".to_string();
        d.kind_condition_input = "kind=1".to_string();
        d.time_cond_start = 1676067553.to_string();
        d.time_cond_end = 1678659553.to_string();

        let _res = d.create_delegation(&keys).unwrap();

        // // verify signature (it's variable)
        // let verify_result = verify_delegation_signature(
        //     &keys.public_key(),
        //     &Signature::from_str(&d.signature).unwrap(),
        //     XOnlyPublicKey::from_bech32(&d.delegatee_npub_input).unwrap(),
        //     d.conditions.clone(),
        // );
        // assert!(verify_result.is_ok());

        // validate tag
        let expected_tag = format!("[\"delegation\",\"1a459a8a6aa6441d480ba665fb8fb21a4cfe8bcacb7d87300f8046a558a3fce4\",\"kind=1&created_at>1676067553&created_at<1678659553\",\"{}\"]", d.signature);
        assert_eq!(d.delegation_tag, expected_tag);
    }

    #[test]
    fn test_time_set_start() {
        let mut d = Delegator::new();
        d.delegatee_npub_input =
            "npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez".to_string();
        d.time_set_start("1676067553");
        assert_eq!(d.delegation_string, "nostr:delegation:bea8aeb6c1657e33db5ac75a83910f77e8ec6145157e476b5b88c6e85b1fab34:created_at>1676067553");
    }

    #[test]
    fn test_time_set_end() {
        let mut d = Delegator::new();
        d.delegatee_npub_input =
            "npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez".to_string();
        d.time_set_end("1678659553");
        assert_eq!(d.delegation_string, "nostr:delegation:bea8aeb6c1657e33db5ac75a83910f77e8ec6145157e476b5b88c6e85b1fab34:created_at<1678659553");
    }

    #[test]
    fn test_time_set_days() {
        let mut d = Delegator::new();
        d.delegatee_npub_input =
            "npub1h652adkpv4lr8k66cadg8yg0wl5wcc29z4lyw66m3rrwskcl4v6qr82xez".to_string();
        d.time_set_days("11");
        assert_eq!(
            d.time_cond_end.parse::<i64>().unwrap() - d.time_cond_start.parse::<i64>().unwrap(),
            11 * 24 * 60 * 60
        );
    }
}
