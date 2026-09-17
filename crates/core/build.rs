use std::io::Result;

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=../../proto/steammessages_auth.steamclient.proto");
    println!("cargo:rerun-if-changed=../../proto/steammessages_base.proto");
    println!("cargo:rerun-if-changed=../../proto/steammessages_unified_base.steamclient.proto");
    println!("cargo:rerun-if-changed=../../proto/enums.proto");

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
