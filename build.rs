use slint_build::{CompilerConfiguration, DefaultTranslationContext};

fn main() {
    let config = CompilerConfiguration::new()
        .with_style("fluent-dark".into())
        .with_bundled_translations("lang")
        .with_default_translation_context(DefaultTranslationContext::None);
    slint_build::compile_with_config("ui/app.slint", config).unwrap();

    // The version in the resource comes from Cargo.toml, so the copy autostart runs can
    // be told apart from an older or newer exe.
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut commas: Vec<&str> = version.split('.').collect();
    commas.resize(4, "0");
    let res = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("res");
    let rc = std::fs::read_to_string(res.join("vantix.rc"))
        .unwrap()
        .replace("@RES@", &res.to_string_lossy().replace('\\', "/"))
        .replace("@COMMAS@", &commas.join(","))
        .replace("@VERSION@", &version);
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("vantix.rc");
    std::fs::write(&out, rc).unwrap();
    embed_resource::compile(&out, embed_resource::NONE).manifest_required().unwrap();
    println!("cargo:rerun-if-changed=res");
    println!("cargo:rerun-if-changed=lang");
}
