# 🗺️ Master Plan & Roadmap: `steam-core` 🦀

> **Target Audience:** Future AI Agents, Senior Engineers, and Core Contributors.  
> **Repository:** `https://github.com/evairx/steam-core.git`  
> **Working Directory:** `C:\Users\akong\OneDrive\Escritorio\trabajos\steam-session`  
> **Crate Name:** `steam-core` (located at `crates/core`)  
> **Current Status:** Phase 1 (Auth Engine, OS Vault, Auto-Keeper, Unified Skeleton) is **100% COMPLETE and TESTED (20/20 tests green, 0 clippy warnings)**.

---

## 🎯 1. Project Vision & Architecture

`steam-core` is an all-in-one native Rust library replacing fragmented Node.js solutions (`node-steam-session` + `node-steam-user`). It unifies:
1. **Authentication & Session Lifecycle (`steam_core::auth`)**: Credentials RSA encryption, Steam Guard 2FA, QR codes, OS hardware-backed credential vault, and background token auto-renewal.
2. **Network Connection Client (`steam_core::user`)**: Real-time connection to Steam's Connection Manager (CM) servers over WebSocket or TCP, persona state management, game idling, and friend interactions.
3. **Multi-Language Exportability**: Designed to be consumed natively by **Tauri**, or exported cleanly to **Kotlin (Android/Desktop)** and **Go** via UniFFI / C-ABI.

### Workspace Structure
```text
steam-core/
├── crates/
│   ├── core/                    # [steam-core] Primary library
│   │   ├── src/
│   │   │   ├── auth.rs          # SteamAuth facade, AuthenticatedSession, QrChallenge
│   │   │   ├── client.rs        # SteamApiClient, HTTP/Protobuf transport, cookie jar
│   │   │   ├── crypto.rs        # RSA PKCS#1 v1.5 encryption matching Valve spec
│   │   │   ├── enums.rs         # Strongly-typed Valve enums & EResult
│   │   │   ├── error.rs         # thiserror SteamError hierarchy (zero unwrap)
│   │   │   ├── keeper.rs        # AutoKeeper background renewal daemon
│   │   │   ├── session.rs       # LoginSession state machine (credentials & QR)
│   │   │   ├── tokens.rs        # JWT decoding & expiration inspection
│   │   │   ├── user.rs          # SteamUser Connection Manager client coordinator
│   │   │   ├── vault.rs         # SessionVault (Windows Credential Manager / Keychain / Secret Service)
│   │   │   └── lib.rs           # Public exports
│   │   ├── tests/
│   │   │   └── auth_tests.rs    # Integration & doc-test suite (20/20 tests passing)
│   │   ├── build.rs             # Prost protobuf compilation with automatic protoc fallback
│   │   └── Cargo.toml
│   └── cli/                     # [steam-login] Internal CLI tool for manual tests
├── proto/                       # Valve official Protobufs
└── Cargo.toml                   # Workspace manifest
```

---

## ✅ 2. What is Already Completed & Verified

The following modules are fully production-grade, tested, and passing with zero compiler or Clippy warnings:

| Module | Features & Capabilities |
| :--- | :--- |
| **`crypto.rs`** | RSA PKCS#1 v1.5 encryption with 64-bit timestamps. Tested against UTF-8, symbols, emojis, and special chars. |
| **`client.rs`** | Protobuf over HTTPS transport for `IAuthenticationService`. Full domain cookie transfers for `steamcommunity.com` and `store.steampowered.com`. Proxy support (HTTP/SOCKS5). |
| **`session.rs`** | `LoginSession` state machine: credentials login, QR code login, Steam Guard 2FA submission (Device Push, TOTP, Email), and `renew()` access token rotation. |
| **`vault.rs`** | `SessionVault` utilizing the OS native credential store (**Windows Credential Manager**, **macOS Keychain**, **Linux Secret Service**). Zero plaintext tokens in files. |
| **`tokens.rs`** | Lightweight JWT parser (`decode_jwt`) and expiration checker (`is_token_expired`) without external heavy crypto crates. |
| **`keeper.rs`** | Autonomous background daemon (`AutoKeeper`) running on Tokio. Monitors JWT expiration and silently renews access tokens and web cookies before they expire. Broadcasts updates via `tokio::sync::watch`. |
| **`auth.rs`** | 1-line developer API (`SteamAuth::load_or_login()`, `SteamAuth::login()`, `SteamAuth::get_qr()`, `SteamAuth::from_token()`). |
| **`user.rs`** | Scaffolding for `SteamUser`, `SteamUserOptions`, `EPersonaState`, and seamless integration with `AuthenticatedSession`. |

---

## 🚀 3. Step-by-Step Implementation Plan for the Next Agent

Any incoming agent should follow these distinct, self-contained phases:

### Phase 1: Steam Connection Manager (CM) Network Pipeline
**Goal:** Enable `SteamUser` to establish a live connection to Steam's CM network and authenticate with `access_token`.

1. **CM Server Discovery:**
   - In `crates/core/src/user.rs` or `crates/core/src/network/directory.rs`, implement `fetch_cm_list()`.
   - Query endpoint: `https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=0`.
   - Filter for WebSocket endpoints (`wss://.../cmp/`) or TCP endpoints (`ip:port`).
2. **WebSocket Transport (`tokio-tungstenite`):**
   - Add `tokio-tungstenite = { version = "0.24", features = ["rustls-tls-native-roots"] }` to `crates/core/Cargo.toml`.
   - Implement frame encoding and decoding:
     - Steam packet structure: `[EMsg (u32, with proto mask 0x80000000)] + [Header Length (u32)] + [Protobuf Header (CMsgProtoBufHeader)] + [Protobuf Body]`.
3. **Logon Handshake:**
   - Send `k_EMsgClientLogon` (703):
     - Body: `CMsgClientLogon` with `client_supplied_steamid = session.steam_id()` and `access_token = session.access_token()`.
   - Receive `k_EMsgClientLogonResponse` (751):
     - If `eresult == 1` (`k_EResultOK`), set `is_connected = true` and emit `SteamUserEvent::LoggedOn`.
4. **Heartbeat Daemon:**
   - Spawn a Tokio task sending `k_EMsgClientHeartBeat` (704) according to `heartbeat_seconds` returned in the logon response.

### Phase 2: Steam Community & Rich Presence Features
**Goal:** Allow the user to idle games, change status, and interact with friends.

1. **Persona State:**
   - Implement `SteamUser::set_persona_state(state: EPersonaState)`.
   - Encodes and sends `k_EMsgClientChangeStatus` (`CMsgClientChangeStatus`).
2. **Game Playing / Hour Boosting:**
   - Implement `SteamUser::set_games_played(&[u32])`.
   - Encodes and sends `k_EMsgClientGamesPlayed` (`CMsgClientGamesPlayed`) passing `game_id` and AppIDs (e.g. `730` for CS2, `440` for TF2).
3. **Chat & Friends Event Stream:**
   - Decode incoming `k_EMsgClientPersonaState` (friend status changes) and `k_EMsgClientFriendMsg` (incoming chat messages).
   - Expose via `tokio::sync::broadcast::Receiver<SteamUserEvent>`.

### Phase 3: Multi-Language Bindings (Kotlin, Go, Tauri, JS)
**Goal:** Make `steam-core` consumable from any application stack.

1. **Tauri Plugin / Module:**
   - In a future `crates/tauri-plugin-steam`, expose Tauri commands:
     - `tauri_steam_login(username, password)`
     - `tauri_steam_get_qr()`
     - `tauri_steam_get_cookies()`
2. **UniFFI for Kotlin (Android & Desktop):**
   - Create `crates/uniffi` defining `steam_core.udl` or proc-macro attributes.
   - Generates pure Kotlin bindings wrapping the compiled `.dll` / `.so` / `.dylib`.
3. **C-ABI for Go (`crates/ffi`):**
   - Expose `#[no_mangle] pub extern "C" fn steam_auth_login(...)`.
   - Provide a Go package using `cgo` for 100% native Go performance without reimplementing crypto.

---

## 🛠️ 4. Build, Test, & Environment Reference

### Environment Setup
When executing Cargo commands, ensure the environment includes Rust binaries and the `protoc` compiler:
```powershell
$env:Path = "C:\Users\akong\.cargo\bin;C:\Users\akong\AppData\Local\Microsoft\WinGet\Packages\Google.Protobuf_Microsoft.Winget.Source_8wekyb3d8bbwe\bin;$env:Path"
```
*(Note: `crates/core/build.rs` already contains an automatic detection fallback for `protoc` if not present in the subshell PATH).*

### Quality Verification Commands
Always verify with zero warnings before committing changes:
```powershell
# 1. Run full test suite (unit tests, integration tests, doc-tests)
cargo test -p steam-core

# 2. Strict Clippy check (must have 0 warnings)
cargo clippy -p steam-core --all-targets -- -D warnings

# 3. Check CLI internal package
cargo check -p steam-login
```

### Git Workflow
- Branch: `main`
- Remote: `origin` (`https://github.com/evairx/steam-core.git`)
- Conventional commits: `feat(...)`, `fix(...)`, `refactor(...)`.
