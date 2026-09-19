fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../proto/steammessages_auth.steamclient.proto");
    println!("cargo:rerun-if-changed=../../proto/steammessages_base.proto");
    println!("cargo:rerun-if-changed=../../proto/steammessages_unified_base.steamclient.proto");
    println!("cargo:rerun-if-changed=../../proto/enums.proto");

    // Use a vendored compiler when the host has not configured one explicitly.
    if std::env::var("PROTOC").is_err() {
        if let Ok(path) = protoc_bin_vendored::protoc_bin_path() {
            std::env::set_var("PROTOC", path);
        }
    }

    let mut config = prost_build::Config::new();
    config.skip_debug(["."]);
    config.compile_protos(
        &["../../proto/steammessages_auth.steamclient.proto"],
        &["../../proto"],
    )?;

    // prost 0.13 requires Message: Debug even with skip_debug. Use only type
    // names, never fields, including nested messages and oneof payloads.
    let generated_path =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?)
            .join("_.rs");
    let mut generated = std::fs::read_to_string(&generated_path)?;
    let mut implementations = String::new();
    let mut modules: Vec<(usize, &str)> = Vec::new();
    // These declarations and their indentation are emitted by prost-build,
    // not arbitrary Rust source. Missing a declaration fails the Debug bound.
    for line in generated.lines() {
        let declaration = line.trim_start();
        let indent = line.len() - declaration.len();
        if let Some(module) = declaration.strip_prefix("pub mod ") {
            modules.retain(|(level, _)| *level < indent);
            modules.push((
                indent,
                module
                    .split_whitespace()
                    .next()
                    .ok_or("missing module name")?,
            ));
        } else if let Some(ty) = declaration
            .strip_prefix("pub struct ")
            .or_else(|| declaration.strip_prefix("pub enum "))
        {
            modules.retain(|(level, _)| *level < indent);
            let ty = ty.split_whitespace().next().ok_or("missing type name")?;
            let path = modules
                .iter()
                .map(|(_, name)| *name)
                .chain(std::iter::once(ty))
                .collect::<Vec<_>>()
                .join("::");
            implementations.push_str(&format!(
                "impl ::core::fmt::Debug for {path} {{\n\
                 fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {{\n\
                 f.write_str(\"{ty} {{ [REDACTED] }}\")\n\
                 }}\n}}\n"
            ));
        }
    }
    generated.push_str(&implementations);
    std::fs::write(generated_path, generated)?;
    Ok(())
}
