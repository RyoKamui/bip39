use std::env;

fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=assets/BIP39Tool.ico");
        winresource::WindowsResource::new()
            .set_icon("assets/BIP39Tool.ico")
            .compile()
            .expect("failed to embed the Windows application icon");
    }

    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=BIP39_ALLOW_UNSANITIZED_RELEASE");

    if env::var("PROFILE").as_deref() != Ok("release") {
        return;
    }

    if env::var_os("BIP39_ALLOW_UNSANITIZED_RELEASE").is_some() {
        return;
    }

    let flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let has_remap = flags.contains("--remap-path-prefix=");
    let has_scope = flags.contains("--remap-path-scope=all");

    if !has_remap || !has_scope {
        panic!(
            "release builds must use path-remap rustflags to avoid embedding local filesystem paths; use scripts/build-release.sh or scripts/cargo-sanitized.sh build --release --locked"
        );
    }
}
