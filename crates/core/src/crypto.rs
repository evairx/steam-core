//! Cryptographic primitives for Steam password encryption (RSA PKCS#1 v1.5).

use base64::Engine;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use std::fmt;

use crate::error::{Result, SteamError};

/// Container for an encrypted password and its corresponding Steam key timestamp.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedPassword {
    /// The Base64-encoded RSA ciphertext.
    pub encrypted_password: String,
    /// The timestamp associated with the RSA key used for encryption.
    pub timestamp: u64,
}

impl fmt::Debug for EncryptedPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedPassword")
            .field("encrypted_password", &"[REDACTED]")
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

/// Encrypts a plaintext password using Steam's RSA modulus, exponent, and timestamp.
///
/// Steam provides the public key components as hexadecimal strings.
/// The encryption standard required by Steam is **RSA PKCS#1 v1.5**.
/// The resulting encrypted payload is returned as a standard Base64 string.
pub fn encrypt_password(
    password: &str,
    publickey_mod: &str,
    publickey_exp: &str,
    timestamp: u64,
) -> Result<EncryptedPassword> {
    let mod_bytes = hex::decode(publickey_mod.trim())
        .map_err(|_| SteamError::Crypto("Invalid public key modulus hex".into()))?;
    let exp_bytes = hex::decode(publickey_exp.trim())
        .map_err(|_| SteamError::Crypto("Invalid public key exponent hex".into()))?;

    let n = BigUint::from_bytes_be(&mod_bytes);
    let e = BigUint::from_bytes_be(&exp_bytes);

    let pub_key = RsaPublicKey::new(n, e)
        .map_err(|_| SteamError::Crypto("Failed to construct RSA public key".into()))?;

    let mut rng = rand::thread_rng();
    let encrypted = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, password.as_bytes())
        .map_err(|_| SteamError::Crypto("RSA encryption failure".into()))?;

    let base64_encrypted = base64::prelude::BASE64_STANDARD.encode(&encrypted);

    Ok(EncryptedPassword {
        encrypted_password: base64_encrypted,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    #[test]
    fn test_rsa_encrypt_decrypt_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0x0052_5341);
        let priv_key = RsaPrivateKey::new(&mut rng, 1024).expect("generate rsa key");
        let pub_key = RsaPublicKey::from(&priv_key);

        let mod_hex = hex::encode(pub_key.n().to_bytes_be());
        let exp_hex = hex::encode(pub_key.e().to_bytes_be());

        let plain = "SuperSecretPassword123!";
        let encrypted =
            encrypt_password(plain, &mod_hex, &exp_hex, 1700000000).expect("encrypt password");

        assert_eq!(encrypted.timestamp, 1700000000);
        assert!(!encrypted.encrypted_password.is_empty());

        // Verify standard RSA decryption can recover the exact plaintext
        let cipher_bytes = base64::prelude::BASE64_STANDARD
            .decode(&encrypted.encrypted_password)
            .expect("base64 decode");

        let decrypted = priv_key
            .decrypt(Pkcs1v15Encrypt, &cipher_bytes)
            .expect("rsa decrypt");

        assert_eq!(String::from_utf8(decrypted).expect("utf8"), plain);
    }

    #[test]
    fn encrypted_password_debug_is_redacted() {
        let encrypted = EncryptedPassword {
            encrypted_password: "secret-encrypted-password".into(),
            timestamp: 1700000000,
        };
        for debug in [format!("{encrypted:?}"), format!("{encrypted:#?}")] {
            assert!(!debug.contains(&encrypted.encrypted_password));
            assert!(debug.contains("[REDACTED]"));
            assert!(debug.contains("1700000000"));
        }
    }

    #[test]
    fn invalid_key_errors_are_sanitized() {
        use std::error::Error;

        for (modulus, exponent) in [
            ("secret-modulus", "010001"),
            ("ff", "secret-exponent"),
            ("00", "00"),
        ] {
            let error = encrypt_password("secret-password", modulus, exponent, 0).unwrap_err();
            assert!(!format!("{error} {error:?}").contains("secret-"));
            assert!(error.source().is_none());
            match error {
                SteamError::Crypto(reason) => assert!(!reason.contains("secret-")),
                _ => panic!("expected a cryptographic error"),
            }
        }
    }
}
