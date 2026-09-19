use base64::Engine;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use steam_core::{
    encrypt_password, EAuthSessionGuardType, EAuthTokenPlatformType, EResult, ESessionPersistence,
    SteamApiClient, SteamError,
};

#[test]
fn crypto_supports_utf8_and_special_characters() {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 1024).expect("generate rsa key");
    let public_key = RsaPublicKey::from(&private_key);

    let modulus = hex::encode(public_key.n().to_bytes_be());
    let exponent = hex::encode(public_key.e().to_bytes_be());
    let passwords = [
        "StandardPass123",
        "PassWithSymbols!@#$%^&*()_+-=",
        "ContrasenaConTildesYÑáéíóú",
        "ContrasenaUnicode日本語",
    ];

    for password in passwords {
        let encrypted = encrypt_password(password, &modulus, &exponent, 123456789)
            .expect("encryption succeeds");
        let cipher_bytes = base64::prelude::BASE64_STANDARD
            .decode(&encrypted.encrypted_password)
            .expect("base64 decode");
        let decrypted = private_key
            .decrypt(Pkcs1v15Encrypt, &cipher_bytes)
            .expect("rsa decrypt");

        assert_eq!(encrypted.timestamp, 123456789);
        assert_eq!(String::from_utf8(decrypted).expect("valid utf8"), password);
    }
}

#[test]
fn enums_serialize_round_trip() {
    let platform = EAuthTokenPlatformType::WebBrowser;
    let json = serde_json::to_string(&platform).expect("serialize platform");
    assert_eq!(
        serde_json::from_str::<EAuthTokenPlatformType>(&json).unwrap(),
        platform
    );

    let guard = EAuthSessionGuardType::DeviceConfirmation;
    let json = serde_json::to_string(&guard).expect("serialize guard");
    assert_eq!(
        serde_json::from_str::<EAuthSessionGuardType>(&json).unwrap(),
        guard
    );

    let persistence = ESessionPersistence::Persistent;
    let json = serde_json::to_string(&persistence).expect("serialize persistence");
    assert_eq!(
        serde_json::from_str::<ESessionPersistence>(&json).unwrap(),
        persistence
    );
}

#[test]
fn client_builder_accepts_custom_configuration() {
    let client = SteamApiClient::builder()
        .user_agent("SteamCoreTests/1.0")
        .timeout(std::time::Duration::from_secs(30))
        .build();

    assert!(client.is_ok());
}

#[test]
fn qr_generation_accepts_a_steam_url() {
    let challenge_url = "https://s.team/q/1/1234567890123456789";
    let code = qrcode::QrCode::new(challenge_url.as_bytes());

    assert!(code.is_ok());
    assert!(!code
        .unwrap()
        .render::<qrcode::render::unicode::Dense1x2>()
        .build()
        .is_empty());
}

#[test]
fn error_hierarchy_preserves_steam_result() {
    let err = SteamError::InvalidToken("expired token".into());
    assert!(!err.to_string().contains("expired token"));
    assert!(err.to_string().contains("REDACTED"));

    let api_err = SteamError::SteamApi {
        eresult: i32::from(EResult::RateLimitExceeded),
        message: "Too many requests".into(),
    };
    assert!(api_err.to_string().contains("84"));
}

#[test]
fn jwt_expiration_requires_a_valid_exp_claim() {
    use steam_core::{decode_jwt, is_token_expired};

    let future_exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let payload =
        format!(r#"{{"sub":"76561198000000001","exp":{future_exp},"iss":"steam","aud":["web"]}}"#);
    let encoded_payload = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let token = format!("eyJhbGciOiJIUzI1NiJ9.{encoded_payload}.sig");

    let claims = decode_jwt(&token).expect("decode valid jwt");
    assert_eq!(claims.sub.as_deref(), Some("76561198000000001"));
    assert_eq!(claims.exp, Some(future_exp));
    assert!(!is_token_expired(&token, 60));
    assert!(is_token_expired(&token, 7200));
    assert!(is_token_expired("invalid.token", 0));

    let no_exp_payload =
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(r#"{"sub":"76561198000000001"}"#);
    let no_exp_token = format!("eyJhbGciOiJIUzI1NiJ9.{no_exp_payload}.sig");
    assert!(is_token_expired(&no_exp_token, 0));
}
