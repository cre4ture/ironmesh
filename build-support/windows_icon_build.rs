use std::env;
use std::path::PathBuf;

pub fn embed_icon(relative_icon_path: &str) {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let icon_path = manifest_dir.join(relative_icon_path);
    println!("cargo:rerun-if-changed={}", icon_path.display());

    #[cfg(windows)]
    {
        let icon_path_str = icon_path.to_string_lossy().into_owned();
        let mut resources = winres::WindowsResource::new();
        resources.set_icon(&icon_path_str);
        resources
            .compile()
            .expect("failed to embed Windows icon resource");
    }
}
