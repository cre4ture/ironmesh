use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let legacy_ui_dir = manifest_dir.join("src").join("ui");
    let server_admin_dist_dir = manifest_dir
        .join("..")
        .join("..")
        .join("web")
        .join("apps")
        .join("server-admin")
        .join("dist");

    println!("cargo:rerun-if-changed={}", legacy_ui_dir.display());
    println!("cargo:rerun-if-changed={}", server_admin_dist_dir.display());

    let generated_index = out_dir.join("server_admin_index.html");
    let generated_css = out_dir.join("server_admin_app.css");
    let generated_js = out_dir.join("server_admin_app.js");

    let built_index_path = server_admin_dist_dir.join("index.html");
    if built_index_path.exists() {
        println!("cargo:rerun-if-changed={}", built_index_path.display());
        let index_html = fs::read_to_string(&built_index_path).unwrap_or_else(|error| {
            panic!("failed reading {}: {error}", built_index_path.display())
        });
        let script_path = extract_attr(&index_html, "src").unwrap_or_else(|| {
            panic!(
                "failed locating script src in {}",
                built_index_path.display()
            )
        });
        let stylesheet_path = extract_attr(&index_html, "href").unwrap_or_else(|| {
            panic!(
                "failed locating stylesheet href in {}",
                built_index_path.display()
            )
        });

        let script_file = resolve_dist_asset(&server_admin_dist_dir, &script_path);
        let stylesheet_file = resolve_dist_asset(&server_admin_dist_dir, &stylesheet_path);
        println!("cargo:rerun-if-changed={}", script_file.display());
        println!("cargo:rerun-if-changed={}", stylesheet_file.display());

        let script = fs::read_to_string(&script_file)
            .unwrap_or_else(|error| panic!("failed reading {}: {error}", script_file.display()));
        let stylesheet = fs::read_to_string(&stylesheet_file).unwrap_or_else(|error| {
            panic!("failed reading {}: {error}", stylesheet_file.display())
        });
        let rewritten_index = index_html
            .replace(&script_path, "/ui/app.js")
            .replace(&stylesheet_path, "/ui/app.css");

        fs::write(&generated_index, rewritten_index).unwrap_or_else(|error| {
            panic!("failed writing {}: {error}", generated_index.display())
        });
        fs::write(&generated_css, stylesheet)
            .unwrap_or_else(|error| panic!("failed writing {}: {error}", generated_css.display()));
        fs::write(&generated_js, script)
            .unwrap_or_else(|error| panic!("failed writing {}: {error}", generated_js.display()));
        println!("cargo:rustc-env=IRONMESH_SERVER_ADMIN_UI_MODE=built");
        return;
    }

    let legacy_index = legacy_ui_dir.join("index.html");
    let legacy_css = legacy_ui_dir.join("app.css");
    let legacy_js = legacy_ui_dir.join("app.js");
    println!("cargo:rerun-if-changed={}", legacy_index.display());
    println!("cargo:rerun-if-changed={}", legacy_css.display());
    println!("cargo:rerun-if-changed={}", legacy_js.display());

    fs::copy(&legacy_index, &generated_index)
        .unwrap_or_else(|error| panic!("failed copying {}: {error}", legacy_index.display()));
    fs::copy(&legacy_css, &generated_css)
        .unwrap_or_else(|error| panic!("failed copying {}: {error}", legacy_css.display()));
    fs::copy(&legacy_js, &generated_js)
        .unwrap_or_else(|error| panic!("failed copying {}: {error}", legacy_js.display()));
    println!("cargo:rustc-env=IRONMESH_SERVER_ADMIN_UI_MODE=fallback");
}

fn extract_attr(html: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=\"");
    let start = html.find(&needle)? + needle.len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_string())
}

fn resolve_dist_asset(dist_dir: &Path, asset_path: &str) -> PathBuf {
    dist_dir.join(asset_path.trim_start_matches('/'))
}
