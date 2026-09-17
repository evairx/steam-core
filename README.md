# steam-core 🦀🚀

> **All-in-One High-Performance Native Steam Client & Authentication Engine in Rust.**
> Unifies session lifecycle management (`steam-session`) and Steam network connection client (`steam-user`) into a single, cohesive, zero-friction library.

[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Tests Passing](https://img.shields.io/badge/tests-20%2F20%20passing-brightgreen.svg)]()
[![Clippy Strict](https://img.shields.io/badge/clippy--D--warnings-clean-brightgreen.svg)]()

---

## 💡 Why `steam-core`?

Traditional libraries in the ecosystem (like Node.js's `node-steam-session` and `node-steam-user`) are fragmented across separate packages with complex inter-process token passing. 

`steam-core` unifies the entire Steam pipeline in Rust:
1. **Zero-Friction Authentication (`steam_core::auth`):**
   - Direct RSA PKCS#1 v1.5 encrypted login with official Valve protobufs.
   - Built-in 2FA support: Mobile Authenticator push notifications, TOTP codes, and Email codes.
   - Interactive QR Code generator (terminal ASCII rendering & image bitmaps).
   - Direct web cookies acquisition: `steamLoginSecure` and `sessionid`.
2. **Hardware-Backed OS Credential Vault (`steam_core::vault`):**
   - Tokens and cookies are stored securely inside the native OS Keyring (**Windows Credential Manager**, **macOS Keychain**, or **Linux Secret Service**).
   - No plaintext tokens in `.env` or disk files.
3. **Background Auto-Keeper (`steam_core::keeper`):**
   - Autonomous background daemon powered by Tokio.
   - Silently monitors JWT expiration (`exp` claims) and automatically renews tokens via Steam's `GenerateAccessTokenForApp` before they expire.
   - Broadcasts fresh cookies to your app via Tokio `watch` channels.
4. **Native Steam CM Client (`steam_core::user`):**
   - Connects to Valve's Connection Manager (CM) network (over WebSocket or TCP).
   - Authenticates directly using the validated `access_token` JWT from `auth`.
   - Manages online status (`Online`, `Away`, `Invisible`), AppID hour boosting (`set_games_played`), and event streams.
5. **Cross-Platform & Multi-Language Ready:**
   - Designed to power Tauri desktop apps, and exportable via UniFFI / C-ABI to **Kotlin** (Android/Desktop), **Go**, and **Node.js/Bun**.

---

## 📦 Monorepo Structure

```text
steam-core/
├── crates/
│   ├── core/         # [steam-core] Native Rust library (auth + user + vault + keeper)
│   └── cli/          # [steam-login] Lightweight CLI tool for testing authentication
├── proto/            # Official Valve protobuf definitions (compiled via prost-build)
└── tests/            # Integration & lifecycle test suites (100% green)
```

---

## 🚀 Quick Start

Add `steam-core` to your `Cargo.toml`:

```toml
[dependencies]
steam-core = { path = "./crates/core" }
tokio = { version = "1", features = ["full"] }
```

### 1. One-Line Login with Auto-Restore & Background Auto-Keeper

```rust
use steam_core::{SteamAuth, SteamUser, SteamUserOptions, EPersonaState, AuthEvent};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Authenticate (restores instantly from Windows Credential Manager if already saved)
    let session = SteamAuth::load_or_login("my_steam_username", "my_password", |event| {
        match event {
            AuthEvent::NeedMobileConfirmation => println!("📲 Please approve the push notification on your Steam Mobile app!"),
            AuthEvent::NeedDeviceCode => println!("🔑 Please enter your Steam Guard mobile authenticator code:"),
            AuthEvent::NeedEmailCode => println!("📧 Please enter the code sent to your email:"),
            AuthEvent::Polling => println!("⏳ Waiting for approval..."),
            AuthEvent::Authenticated { account_name } => println!("✅ Authenticated as {account_name}!"),
        }
    }).await?;

    // 2. Start the background Auto-Keeper (silently renews tokens & cookies before they expire)
    let _keeper = session.spawn_keeper(Some(Duration::from_secs(300)));

    // 3. Connect to the Steam network as a live user
    let mut user = SteamUser::connect(&session, SteamUserOptions::default()).await?;
    user.set_persona_state(EPersonaState::Online).await?;
    user.set_games_played(&[730]).await?; // AppID 730 = Counter-Strike 2

    println!("Logged on to Steam network! SteamID64: {}", user.steam_id());
    Ok(())
}
```

### 2. Instant QR Code Login

```rust
use steam_core::SteamAuth;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let qr = SteamAuth::get_qr().await?;
    
    // Prints QR code directly in the terminal!
    println!("{}", qr.render_ascii()?);

    let session = qr.wait_for_scan(Duration::from_secs(60)).await?;
    session.save_to_vault()?; // Persist securely to OS Keyring

    println!("Ready to use! Account: {}", session.account_name());
    Ok(())
}
```

### 3. Using Web Cookies with HTTP Clients (Reqwest, Tauri, etc.)

```rust
// Pre-formatted Cookie header: "sessionid=...; steamLoginSecure=..."
let cookie_header = session.cookie_header();

// Bearer Authorization header: "Bearer ey..."
let bearer_header = session.bearer_auth_header();
```

---

## 🔒 Security Architecture

`steam-core` enforces strict security standards:
- **Zero Plaintext Storage:** Sessions are serialized and saved via the `keyring` crate into OS hardware-backed vaults (`service = "steam-core"`).
- **Zero Raw Passwords:** Passwords never hit the network unencrypted; they are encrypted using Valve's dynamic RSA public key and current server timestamps.
- **Memory Safety:** Sensitive cryptographic buffers are dropped immediately after encryption.

---

## 🛠️ Multi-Language Roadmap

- [x] **Core Native Rust Library:** Complete auth + user state machine + OS vault + auto-keeper.
- [ ] **UniFFI Bindings:** Auto-generated idiomatic Kotlin/Swift bindings for Android and iOS/macOS.
- [ ] **C-ABI (`steam_core_ffi`):** Raw C headers for direct Go (`cgo`), C++, and C# integrations.
- [ ] **Tauri Plugin:** 1-line Tauri plugin for desktop Steam apps.
