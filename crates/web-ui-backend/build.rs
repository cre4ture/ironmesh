use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let web_workspace_dir =
        canonicalize_or_fallback(manifest_dir.join("..").join("..").join("web"));
    let generated_dist_dir = out_dir.join("client-ui-dist");
    let mut client_ui_dist_candidates = client_ui_dist_candidates(&web_workspace_dir);

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
            .join("client-ui")
            .join("src")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("apps")
            .join("client-ui")
            .join("index.html")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("apps")
            .join("client-ui")
            .join("package.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("apps")
            .join("client-ui")
            .join("tsconfig.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        web_workspace_dir
            .join("apps")
            .join("client-ui")
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

    let generated_index = out_dir.join("client_ui_index.html");
    let generated_css = out_dir.join("client_ui_app.css");
    let generated_js = out_dir.join("client_ui_app.js");
    let generated_assets = out_dir.join("client_ui_assets.rs");
    let generated_assets_dir = out_dir.join("client_ui_embedded_assets");
    run_frontend_build(&web_workspace_dir, &generated_dist_dir);

    client_ui_dist_candidates.insert(0, generated_dist_dir.clone());
    client_ui_dist_candidates.extend(discover_dist_dirs(&web_workspace_dir));
    client_ui_dist_candidates = dedupe_paths_preserving_order(client_ui_dist_candidates);
    let client_ui_dist_dir = locate_dist_dir(&client_ui_dist_candidates).unwrap_or_else(|| {
        panic!(
            "failed locating built client-ui dist after frontend build; checked: {}",
            format_path_list(&client_ui_dist_candidates)
        )
    });
    let built_index_path = client_ui_dist_dir.join("index.html");
    let index_html = fs::read_to_string(&built_index_path).unwrap_or_else(|error| {
        panic!(
            "failed reading built client-ui HTML at {} after `pnpm --filter @ironmesh/client-ui build`: {error}",
            built_index_path.display()
        )
    });
    let script_path = extract_script_src(&index_html).unwrap_or_else(|| {
        panic!(
            "failed locating script src in built client-ui HTML {}",
            built_index_path.display()
        )
    });
    let stylesheet_path = extract_stylesheet_href(&index_html).unwrap_or_else(|| {
        panic!(
            "failed locating stylesheet href in built client-ui HTML {}",
            built_index_path.display()
        )
    });

    let script_file = resolve_dist_asset(&client_ui_dist_dir, &script_path);
    let stylesheet_file = resolve_dist_asset(&client_ui_dist_dir, &stylesheet_path);
    let script = fs::read_to_string(&script_file)
        .unwrap_or_else(|error| panic!("failed reading {}: {error}", script_file.display()));
    let stylesheet = fs::read_to_string(&stylesheet_file)
        .unwrap_or_else(|error| panic!("failed reading {}: {error}", stylesheet_file.display()));
    let rewritten_index = index_html
        .replace(&script_path, "/app.js")
        .replace(&stylesheet_path, "/app.css");

    fs::write(&generated_index, rewritten_index)
        .unwrap_or_else(|error| panic!("failed writing {}: {error}", generated_index.display()));
    fs::write(&generated_css, stylesheet)
        .unwrap_or_else(|error| panic!("failed writing {}: {error}", generated_css.display()));
    fs::write(&generated_js, script)
        .unwrap_or_else(|error| panic!("failed writing {}: {error}", generated_js.display()));
    generate_embedded_assets_module(
        &client_ui_dist_dir,
        &generated_assets_dir,
        &generated_assets,
    );
}

fn generate_embedded_assets_module(
    dist_dir: &Path,
    generated_assets_dir: &Path,
    generated_file: &Path,
) {
    let assets_dir = dist_dir.join("assets");
    let mut assets = Vec::new();

    if generated_assets_dir.exists() {
        fs::remove_dir_all(generated_assets_dir).unwrap_or_else(|error| {
            panic!(
                "failed cleaning generated embedded asset dir {}: {error}",
                generated_assets_dir.display()
            )
        });
    }

    if assets_dir.is_dir() {
        collect_embedded_assets(&assets_dir, &assets_dir, generated_assets_dir, &mut assets);
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

fn collect_embedded_assets(
    dir: &Path,
    root: &Path,
    generated_root: &Path,
    assets: &mut Vec<(String, PathBuf)>,
) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed reading asset dir {}: {error}", dir.display()));

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_embedded_assets(&path, root, generated_root, assets);
            continue;
        }

        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let generated_asset_path = relative_path
            .split('/')
            .fold(generated_root.to_path_buf(), |path, segment| {
                path.join(segment)
            });
        if let Some(parent) = generated_asset_path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|error| {
                panic!(
                    "failed creating embedded asset dir {}: {error}",
                    parent.display()
                )
            });
        }
        fs::copy(&path, &generated_asset_path).unwrap_or_else(|error| {
            panic!(
                "failed copying embedded asset {} to {}: {error}",
                path.display(),
                generated_asset_path.display()
            )
        });
        assets.push((relative_path, generated_asset_path));
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

fn client_ui_dist_candidates(web_workspace_dir: &Path) -> Vec<PathBuf> {
    vec![
        web_workspace_dir
            .join("apps")
            .join("client-ui")
            .join("dist"),
        web_workspace_dir.join("dist"),
    ]
}

fn canonicalize_or_fallback(path: PathBuf) -> PathBuf {
    fs::canonicalize(&path).unwrap_or(path)
}

fn locate_dist_dir(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|candidate| candidate.join("index.html").is_file())
        .cloned()
}

fn dedupe_paths_preserving_order(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut deduped = Vec::new();
    for path in paths {
        if !deduped.contains(&path) {
            deduped.push(path);
        }
    }
    deduped
}

fn discover_dist_dirs(root: &Path) -> Vec<PathBuf> {
    let mut matches = Vec::new();
    discover_dist_dirs_recursive(root, 0, 4, &mut matches);
    matches
}

fn discover_dist_dirs_recursive(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    matches: &mut Vec<PathBuf>,
) {
    if depth > max_depth {
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        if path.file_name().is_some_and(|segment| segment == "dist")
            && path.join("index.html").is_file()
        {
            matches.push(path);
            continue;
        }

        discover_dist_dirs_recursive(&path, depth + 1, max_depth, matches);
    }
}

fn format_path_list(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn run_frontend_build(web_workspace_dir: &Path, generated_dist_dir: &Path) {
    if !web_workspace_dir.exists() {
        panic!(
            "frontend workspace missing at {}. The client-ui must be built during cargo builds.",
            web_workspace_dir.display()
        );
    }

    if generated_dist_dir.exists() {
        fs::remove_dir_all(generated_dist_dir).unwrap_or_else(|error| {
            panic!(
                "failed cleaning generated client-ui dist {} before rebuild: {error}",
                generated_dist_dir.display()
            )
        });
    }

    let generated_dist_arg = generated_dist_dir.to_string_lossy().into_owned();
    let args = [
        "--filter",
        "@ironmesh/client-ui",
        "exec",
        "vite",
        "build",
        "--outDir",
        generated_dist_arg.as_str(),
    ];

    let status = run_pnpm_command(web_workspace_dir, &args).unwrap_or_else(|error| {
        panic!(
            "failed to execute `pnpm --filter @ironmesh/client-ui exec vite build --outDir {}` in {}: {error}. Install Node.js and pnpm, then ensure `pnpm` is on PATH.",
            generated_dist_dir.display(),
            web_workspace_dir.display()
        )
    });

    if !status.success() {
        panic!(
            "frontend build failed in {} while generating {}. Fix the client-ui build before running cargo again.",
            web_workspace_dir.display(),
            generated_dist_dir.display()
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
