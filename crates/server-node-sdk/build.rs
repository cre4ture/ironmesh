use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let web_workspace_dir = manifest_dir.join("..").join("..").join("web");
    let source_server_admin_dist_dir = manifest_dir
        .join("..")
        .join("..")
        .join("web")
        .join("apps")
        .join("server-admin")
        .join("dist");
    let prebuilt_web_dir = env::var_os("IRONMESH_PREBUILT_WEB_DIR").map(PathBuf::from);

    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir.join("package.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir.join("pnpm-lock.yaml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir.join("pnpm-workspace.yaml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir.join("tsconfig.base.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("apps")
            .join("server-admin")
            .join("src")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("apps")
            .join("server-admin")
            .join("index.html")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("apps")
            .join("server-admin")
            .join("package.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("apps")
            .join("server-admin")
            .join("tsconfig.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("apps")
            .join("server-admin")
            .join("vite.config.ts")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("packages")
            .join("ui")
            .join("src")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("packages")
            .join("ui")
            .join("package.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("packages")
            .join("ui")
            .join("tsconfig.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("packages")
            .join("api")
            .join("src")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("packages")
            .join("api")
            .join("package.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("packages")
            .join("api")
            .join("tsconfig.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("packages")
            .join("config")
            .join("src")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("packages")
            .join("config")
            .join("vite")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("packages")
            .join("config")
            .join("package.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("packages")
            .join("config")
            .join("tsconfig.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir
            .join("..")
            .join("..")
            .join("docs")
            .join("assets")
            .join("ironmesh-favicon.svg")
            .display()
    );
    println!("cargo:rerun-if-env-changed=PATH");
    println!("cargo:rerun-if-env-changed=IRONMESH_PREBUILT_WEB_DIR");
    if let Some(prebuilt_web_dir) = prebuilt_web_dir.as_deref() {
        println!(
            "cargo:rerun-if-changed={}",
            prebuilt_web_dir.join("server-admin").display()
        );
    }

    let generated_index = out_dir.join("server_admin_index.html");
    let generated_css = out_dir.join("server_admin_app.css");
    let generated_js = out_dir.join("server_admin_app.js");
    let generated_assets = out_dir.join("server_admin_assets.rs");
    let server_admin_dist_dir = match prebuilt_web_dir.as_deref() {
        Some(prebuilt_web_dir) => resolve_prebuilt_dist_dir(prebuilt_web_dir, "server-admin"),
        None => {
            run_frontend_build(&web_workspace_dir);
            source_server_admin_dist_dir.clone()
        }
    };

    let built_index_path = server_admin_dist_dir.join("index.html");
    let index_html = fs::read_to_string(&built_index_path).unwrap_or_else(|error| {
        panic!(
            "failed reading built server-admin HTML at {} after `pnpm build`: {error}",
            built_index_path.display()
        )
    });
    let script_path = extract_script_src(&index_html).unwrap_or_else(|| {
        panic!(
            "failed locating script src in built server-admin HTML {}",
            built_index_path.display()
        )
    });
    let stylesheet_path = extract_stylesheet_href(&index_html).unwrap_or_else(|| {
        panic!(
            "failed locating stylesheet href in built server-admin HTML {}",
            built_index_path.display()
        )
    });

    let script_file = resolve_dist_asset(&server_admin_dist_dir, &script_path);
    let stylesheet_file = resolve_dist_asset(&server_admin_dist_dir, &stylesheet_path);
    let script = fs::read_to_string(&script_file)
        .unwrap_or_else(|error| panic!("failed reading {}: {error}", script_file.display()));
    let stylesheet = fs::read_to_string(&stylesheet_file)
        .unwrap_or_else(|error| panic!("failed reading {}: {error}", stylesheet_file.display()));
    let rewritten_index = index_html
        .replace(&script_path, "/ui/app.js")
        .replace(&stylesheet_path, "/ui/app.css");

    fs::write(&generated_index, rewritten_index)
        .unwrap_or_else(|error| panic!("failed writing {}: {error}", generated_index.display()));
    fs::write(&generated_css, stylesheet)
        .unwrap_or_else(|error| panic!("failed writing {}: {error}", generated_css.display()));
    fs::write(&generated_js, script)
        .unwrap_or_else(|error| panic!("failed writing {}: {error}", generated_js.display()));
    generate_embedded_assets_module(&server_admin_dist_dir, &generated_assets);
}

fn generate_embedded_assets_module(dist_dir: &Path, generated_file: &Path) {
    let assets_dir = dist_dir.join("assets");
    let mut assets = Vec::new();

    if assets_dir.is_dir() {
        collect_embedded_assets(&assets_dir, &assets_dir, &mut assets);
    }

    assets.sort_by(|left, right| left.0.cmp(&right.0));

    let mut source = String::from(
        "pub(crate) fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {\n    match path {\n",
    );
    for (relative_path, absolute_path) in assets {
        source.push_str(&format!(
            "        {} => Some((include_bytes!({}), {})),\n",
            rust_string_literal(&format!("assets/{relative_path}")),
            rust_string_literal(&absolute_path.to_string_lossy()),
            rust_string_literal(content_type_for_asset(&relative_path))
        ));
    }
    source.push_str("        _ => None,\n    }\n}\n");

    fs::write(generated_file, source)
        .unwrap_or_else(|error| panic!("failed writing {}: {error}", generated_file.display()));
}

fn collect_embedded_assets(dir: &Path, root: &Path, assets: &mut Vec<(String, PathBuf)>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed reading asset dir {}: {error}", dir.display()));

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_embedded_assets(&path, root, assets);
            continue;
        }

        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        assets.push((relative_path, path));
    }
}

fn content_type_for_asset(path: &str) -> &'static str {
    if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".json") || path.ends_with(".map") {
        "application/json; charset=utf-8"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
        "image/jpeg"
    } else if path.ends_with(".webp") {
        "image/webp"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else if path.ends_with(".woff") {
        "font/woff"
    } else if path.ends_with(".ttf") {
        "font/ttf"
    } else {
        "application/octet-stream"
    }
}

fn rust_string_literal(value: &str) -> String {
    format!("{value:?}")
}

fn extract_script_src(html: &str) -> Option<String> {
    extract_tag_attr(html, "script", "src", &["src=\""])
}

fn extract_stylesheet_href(html: &str) -> Option<String> {
    extract_tag_attr(html, "link", "href", &["rel=\"stylesheet\""])
}

fn extract_tag_attr(
    html: &str,
    tag_name: &str,
    attr_name: &str,
    required_snippets: &[&str],
) -> Option<String> {
    let tag_start = format!("<{tag_name}");
    let attr_needle = format!("{attr_name}=\"");
    let mut search_start = 0;

    while let Some(tag_offset) = html[search_start..].find(&tag_start) {
        let tag_start_index = search_start + tag_offset;
        let tag_end_offset = html[tag_start_index..].find('>')?;
        let tag_end_index = tag_end_offset + tag_start_index;
        let tag = &html[tag_start_index..=tag_end_index];

        if required_snippets
            .iter()
            .all(|snippet| tag.contains(snippet))
            && let Some(attr_offset) = tag.find(&attr_needle)
        {
            let attr_start = attr_offset + attr_needle.len();
            if let Some(attr_end_offset) = tag[attr_start..].find('"') {
                let attr_end = attr_end_offset + attr_start;
                return Some(tag[attr_start..attr_end].to_string());
            }
        }

        search_start = tag_end_index + 1;
    }

    None
}

fn resolve_dist_asset(dist_dir: &Path, asset_path: &str) -> PathBuf {
    dist_dir.join(asset_path.trim_start_matches('/'))
}

fn resolve_prebuilt_dist_dir(prebuilt_web_dir: &Path, app_name: &str) -> PathBuf {
    let candidate = prebuilt_web_dir.join(app_name);
    if candidate.join("index.html").is_file() {
        return candidate;
    }

    panic!(
        "prebuilt web assets requested via IRONMESH_PREBUILT_WEB_DIR={}, but {} is missing index.html",
        prebuilt_web_dir.display(),
        candidate.display()
    );
}

fn run_frontend_build(web_workspace_dir: &Path) {
    if !web_workspace_dir.exists() {
        panic!(
            "frontend workspace missing at {}. The server-admin UI must be built during cargo builds.",
            web_workspace_dir.display()
        );
    }

    let status = run_pnpm_command(web_workspace_dir, &["build"]).unwrap_or_else(|error| {
        panic!(
            "failed to execute `pnpm build` in {}: {error}. Install Node.js and pnpm, then ensure `pnpm` is on PATH.",
            web_workspace_dir.display()
        )
    });

    if !status.success() {
        panic!(
            "`pnpm build` failed in {}. Fix the frontend build before running cargo again.",
            web_workspace_dir.display()
        );
    }
}

fn run_pnpm_command(
    web_workspace_dir: &Path,
    args: &[&str],
) -> Result<std::process::ExitStatus, io::Error> {
    let mut commands = vec!["pnpm"];
    if cfg!(windows) {
        commands.insert(0, "pnpm.cmd");
    }

    let mut last_error = None;
    for program in commands {
        match Command::new(program)
            .args(args)
            .current_dir(web_workspace_dir)
            .status()
        {
            Ok(status) => return Ok(status),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }

    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "pnpm executable not found")))
}
