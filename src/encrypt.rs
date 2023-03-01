use crate::error::Error;
use nostr::prelude::SecretKey;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

/// Two-way encryption, used for secret keys
struct Encrypt {}

const DEFAULT_LOG_N: u8 = 13;

impl Encrypt {
    /// Encrypt a key.
    /// It is recommend to zeroize() the password after use.
    pub(crate) fn encrypt_key(
        key: &SecretKey,
        password: &str,
        log2_rounds: u8,
    ) -> Result<Vec<u8>, Error> {
        // Generate a random 16-byte salt
        let salt = {
            let mut salt: [u8; 16] = [0; 16];
            OsRng.fill_bytes(&mut salt);
            salt
        };

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        // placeholder for key security
        let associated_data: Vec<u8> = vec![1];

        let ciphertext = {
            let cipher = {
                let symmetric_key = Self::password_to_key(password, &salt, log2_rounds)?;
                XChaCha20Poly1305::new((&symmetric_key).into())
            };

            // The inner secret. We don't have to drop this because we are encrypting-in-place
            let mut inner_secret: Vec<u8> = key.secret_bytes().to_vec();

            let payload = Payload {
                msg: &inner_secret,
                aad: &associated_data,
            };

            let ciphertext = cipher
                .encrypt(&nonce, payload)
                .map_err(|_e| Error::KeyEncryption)?;

            inner_secret.zeroize();

            ciphertext
        };

        // Combine salt, IV and ciphertext
        let mut concat: Vec<u8> = Vec::new();
        concat.push(0x1); // 1 byte version number
        concat.push(log2_rounds); // 1 byte for scrypt N (rounds)
        concat.extend(salt); // 16 bytes of salt
        concat.extend(nonce); // 24 bytes of nonce
        concat.extend(associated_data); // 1 byte of key security
        concat.extend(ciphertext); // 48 bytes of ciphertext expected
        // Total length is 91 = 1 + 1 + 16 + 24 + 1 + 32

        Ok(concat)
    }

    /// Decrypt a key encrypted using `encrypt_key`
    /// It is recommend to zeroize() the password after use.
    pub(crate) fn decrypt_key(encrypted: &Vec<u8>, password: &str) -> Result<SecretKey, Error> {
        if encrypted.len() < 91 {
            return Err(Error::KeyInvalidEncrypted);
        }

        // Break into parts
        let version: u8 = encrypted[0];
        if version != 1 {
            return Err(Error::KeyInvalidEncryptionVersion);
        }
        let log2_rounds: u8 = encrypted[1];
        let salt: [u8; 16] = encrypted[2..2 + 16]
            .try_into()
            .map_err(|_e| Error::KeyInvalidEncrypted)?;
        let nonce = &encrypted[2 + 16..2 + 16 + 24];
        let associated_data = &encrypted[2 + 16 + 24..2 + 16 + 24 + 1];
        let ciphertext = &encrypted[2 + 16 + 24 + 1..];

        let cipher = {
            let symmetric_key = Self::password_to_key(password, &salt, log2_rounds)?;
            XChaCha20Poly1305::new((&symmetric_key).into())
        };

        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        let mut inner_secret = cipher
            .decrypt(nonce.into(), payload)
            .map_err(|_e| Error::KeyEncryption)?;

        if associated_data.is_empty() {
            return Err(Error::KeyInvalidEncrypted);
        }
        let key_security = associated_data[0];
        if key_security != 1 {
            return Err(Error::KeyEncryption);
        }

        let secret_key = SecretKey::from_slice(&inner_secret)?;
        inner_secret.zeroize();

        Ok(secret_key)
    }

    // Hash/Stretch password with scrypt into a 32-byte (256-bit) key
    fn password_to_key(password: &str, salt: &[u8; 16], log_n: u8) -> Result<[u8; 32], Error> {
        let params = scrypt::Params::new(log_n, 8, 1).map_err(|_e| Error::KeyEncryption)?;
        let mut key: [u8; 32] = [0; 32];
        if scrypt::scrypt(password.as_bytes(), salt, &params, &mut key).is_err() {
            return Err(Error::KeyEncryption);
        }
        Ok(key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nostr::prelude::{FromBech32, ToBech32};

    #[test]
    fn test_encrypt_and_decrypt() {
        let sk = SecretKey::from_bech32(
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae",
        )
        .unwrap();
        let password = "password".to_string();
        let encrypted = Encrypt::encrypt_key(&sk, &password, 13).unwrap();

        let _decrypted = Encrypt::decrypt_key(&encrypted, &password).unwrap();
    }

    #[test]
    fn test_encrypt() {
        let sk = SecretKey::from_bech32(
            "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae",
        )
        .unwrap();
        let password = "password".to_string();
        let encrypted = Encrypt::encrypt_key(&sk, &password, 13).unwrap();
        // Encrypted result is variable, cannot compare to const
        assert_eq!(encrypted.len(), 91);
        assert_eq!(hex::encode(encrypted)[0..4], "010d".to_string());
    }

    #[test]
    fn test_decrypt() {
        let encrypted = hex::decode("010d6a32e0decd8553f02372df251c7f06dd0a54ba09bc0e8b2ea52e816c50f430fd0f051b2f7abcae05017f3c6f8a1ff7f3d694db4e624ef7dece7e3152b1ff536bc954eab1c85b3dbeb8e29140e84f0db5c473822e550d53a66e").unwrap();
        let password = "password".to_string();

        let decrypted = Encrypt::decrypt_key(&encrypted, &password).unwrap();
        assert_eq!(decrypted.to_bech32().unwrap(), "nsec1ktekw0hr5evjs0n9nyyquz4sue568snypy2rwk5mpv6hl2hq3vtsk0kpae");
    }
}
