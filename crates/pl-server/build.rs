// Без UI_DIST встраиваем страницу-заглушку, чтобы сборка не зависела от фронтенда.
fn main() {
    println!("cargo:rerun-if-env-changed=UI_DIST");
    println!("cargo:rerun-if-changed=ui-stub");
    if std::env::var_os("UI_DIST").is_none() {
        let stub = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
            .join("ui-stub");
        println!("cargo:rustc-env=UI_DIST={}", stub.display());
    }
}
