use slint_build::{CompilerConfiguration, DefaultTranslationContext};

fn main() {
    let config = CompilerConfiguration::new()
        .with_style("fluent-dark".into())
        .with_bundled_translations("lang")
        .with_default_translation_context(DefaultTranslationContext::None);
    slint_build::compile_with_config("ui/app.slint", config).unwrap();

    embed_resource::compile("res/easytune.rc", embed_resource::NONE).manifest_required().unwrap();
    println!("cargo:rerun-if-changed=res");
    println!("cargo:rerun-if-changed=lang");
}
