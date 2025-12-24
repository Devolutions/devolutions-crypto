use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use std::env;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let udl_file = if args.len() > 1 {
        Utf8PathBuf::from(&args[1])
    } else {
        Utf8PathBuf::from("../devolutions-crypto-uniffi/src/devolutions_crypto.udl")
    };

    let out_dir = if args.len() > 2 {
        Utf8PathBuf::from(&args[2])
    } else {
        Utf8PathBuf::from("../../wrappers/dart/lib/src/generated")
    };

    // Find the crate root (where Cargo.toml and uniffi.toml are located)
    let crate_root = udl_file
        .parent()
        .and_then(|p| p.parent())
        .context("Failed to determine crate root")?;

    let config_file = crate_root.join("uniffi.toml");

    println!("Generating Dart bindings for devolutions-crypto...");
    println!("  UDL file: {}", udl_file);
    println!("  Output dir: {}", out_dir);
    println!("  Config file: {}", config_file);

    std::fs::create_dir_all(&out_dir)
        .context("Failed to create output directory")?;

    uniffi_bindgen::generate_external_bindings(
        &uniffi_dart::gen::DartBindingGenerator {},
        &udl_file,
        Some(&config_file),
        Some(&out_dir),
        None::<&Utf8PathBuf>,
        None,
        false,
    )
    .context("Failed to generate Dart bindings")?;

    println!("✓ Dart bindings generated successfully!");

    Ok(())
}
