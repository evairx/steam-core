use base64::Engine;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use steam_auth::{
    encrypt_password, EAuthSessionGuardType, EAuthTokenPlatformType, EResult,
    ESessionPersistence, SteamApiClient, SteamError,
};

#[test]
fn test_crypto_utf8_and_special_characters() {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 1024).expect("generate rsa key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let mod_hex = hex::encode(pub_key.n().to_bytes_be());
    let exp_hex = hex::encode(pub_key.e().to_bytes_be());

    let passwords = vec![
        "StandardPass123",
        "PassWithSymbols!@#$%^&*()_+-=",
        "ContraseñaConTildesYÑáéíóú",
        "EmojiPassword🛡️🔥🚀",
    ];

    for plain in passwords {
        let encrypted = encrypt_password(plain, &mod_hex, &exp_hex, 123456789)
            .expect("encryption succeeds");

        assert_eq!(encrypted.timestamp, 123456789);

        let cipher_bytes = base64::prelude::BASE64_STANDARD
            .decode(&encrypted.encrypted_password)
            .expect("base64 decode");

        let decrypted = priv_key
            .decrypt(Pkcs1v15Encrypt, &cipher_bytes)
            .expect("rsa decrypt");

        assert_eq!(String::from_utf8(decrypted).expect("valid utf8"), plain);
    }
}

#[test]
fn test_enums_serde() {
    let platform = EAuthTokenPlatformType::WebBrowser;
    let json = serde_json::to_string(&platform).expect("serialize platform");
    let deserialized: EAuthTokenPlatformType = serde_json::from_str(&json).expect("deserialize platform");
    assert_eq!(platform, deserialized);

    let guard = EAuthSessionGuardType::DeviceConfirmation;
    let json_guard = serde_json::to_string(&guard).expect("serialize guard");
    let deserialized_guard: EAuthSessionGuardType = serde_json::from_str(&json_guard).expect("deserialize guard");
    assert_eq!(guard, deserialized_guard);

    let persistence = ESessionPersistence::Persistent;
    let json_persistence = serde_json::to_string(&persistence).expect("serialize persistence");
    let deserialized_persistence: ESessionPersistence = serde_json::from_str(&json_persistence).expect("deserialize persistence");
    assert_eq!(persistence, deserialized_persistence);
}

#[test]
fn test_client_builder_defaults() {
    let client = SteamApiClient::builder()
        .user_agent("CustomBot/1.0")
        .timeout(std::time::Duration::from_secs(30))
        .build();

    assert!(client.is_ok());
}

#[test]
fn test_qr_generation_from_steam_url() {
    let challenge_url = "https://s.team/q/1/1234567890123456789";
    let code = qrcode::QrCode::new(challenge_url.as_bytes());
    assert!(code.is_ok());

    let rendered = code.unwrap()
        .render::<qrcode::render::unicode::Dense1x2>()
        .build();

    assert!(!rendered.is_empty());
}

#[test]
fn test_error_hierarchy() {
    let err = SteamError::InvalidToken("expired token".into());
    assert!(err.to_string().contains("expired token"));

    let api_err = SteamError::SteamApi {
        eresult: i32::from(EResult::RateLimitExceeded),
        message: "Too many requests".into(),
    };
    assert!(api_err.to_string().contains("84"));
}

#[test]
fn test_jwt_decode_and_expiration_logic() {
    use steam_auth::{decode_jwt, is_token_expired};

    // Construct a JWT with a fixed future timestamp
    let future_exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 3600; // 1 hour from now

    let payload = format!(
        r#"{{"sub":"76561198000000001","exp":{},"iss":"steam","aud":["web"]}}"#,
        future_exp
    );
    let encoded_payload = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let token = format!("eyJhbGciOiJIUzI1NiJ9.{encoded_payload}.sig");

    let claims = decode_jwt(&token).expect("decode valid jwt");
    assert_eq!(claims.sub.as_deref(), Some("76561198000000001"));
    assert_eq!(claims.exp, Some(future_exp));
    assert_eq!(claims.iss.as_deref(), Some("steam"));

    // Not expired with a small margin
    assert!(!is_token_expired(&token, 60));
    // Expired if safety margin is larger than 1 hour (e.g. 7200 seconds)
    assert!(is_token_expired(&token, 7200));

    // Malformed token returns expired / error
    assert!(is_token_expired("invalid.token", 0));
}

#[test]
fn test_saved_session_persistence_roundtrip() {
    use steam_auth::{SavedSession, SteamWebCookies};

    let session = SavedSession {
        account_name: "steam_developer".into(),
        steam_id: 76561198123456789,
        refresh_token: "eyRefreshTokenPayload".into(),
        access_token: "eyAccessTokenPayload".into(),
        cookies: SteamWebCookies {
            session_id: "deadbeef01020304".into(),
            steam_login_secure: Some("76561198123456789||eyAccessTokenPayload".into()),
            all_cookies: vec![
                "sessionid=deadbeef01020304".into(),
                "steamLoginSecure=76561198123456789||eyAccessTokenPayload".into(),
            ],
        },
        saved_at: 1710000000,
    };

    let json = serde_json::to_string(&session).expect("serialize saved session");
    let recovered: SavedSession = serde_json::from_str(&json).expect("deserialize saved session");

    assert_eq!(session, recovered);
    assert_eq!(recovered.account_name, "steam_developer");
    assert_eq!(recovered.cookies.session_id, "deadbeef01020304");
}

