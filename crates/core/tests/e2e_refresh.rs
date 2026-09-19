//! Opt-in Steam browser refresh-token smoke test. It is ignored by default and never prints secrets.

use steam_core::SteamAuth;

#[tokio::test]
#[ignore = "requires STEAM_CORE_E2E_BROWSER_REFRESH_TOKEN"]
async fn refresh_token_derives_browser_cookies() {
    let refresh_token = std::env::var("STEAM_CORE_E2E_BROWSER_REFRESH_TOKEN")
        .expect("set STEAM_CORE_E2E_BROWSER_REFRESH_TOKEN for this ignored test");

    let cookies = SteamAuth::web_cookies_from_refresh_token(refresh_token)
        .await
        .expect("refresh-token browser cookie derivation");
    assert!(cookies.export_steam_login_secure().is_some());
}
