use std::io::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=../../proto/steammessages_auth.steamclient.proto");
    println!("cargo:rerun-if-changed=../../proto/steammessages_base.proto");
    println!("cargo:rerun-if-changed=../../proto/steammessages_unified_base.steamclient.proto");
    println!("cargo:rerun-if-changed=../../proto/enums.proto");

    // Automatic fallback for protoc if not set in current process PATH
    if std::env::var("PROTOC").is_err() {
        let default_winget = PathBuf::from(
            r"C:\Users\akong\AppData\Local\Microsoft\WinGet\Packages\Google.Protobuf_Microsoft.Winget.Source_8wekyb3d8bbwe\bin\protoc.exe",
        );
        if default_winget.exists() {
            std::env::set_var("PROTOC", &default_winget);
        }
    }

    let mut config = prost_build::Config::new();
    config.compile_protos(
        &[
            "../../proto/steammessages_auth.steamclient.proto",
        ],
        &[
            "../../proto",
        ],
    )?;
    Ok(())
}
