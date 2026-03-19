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
    let client_ui_dist_dir = web_workspace_dir
        .join("apps")
        .join("client-ui")
        .join("dist");

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
    println!("cargo:rerun-if-env-changed=PATH");

    let generated_index = out_dir.join("client_ui_index.html");
    let generated_css = out_dir.join("client_ui_app.css");
    let generated_js = out_dir.join("client_ui_app.js");
    run_frontend_build(&web_workspace_dir);

    let built_index_path = client_ui_dist_dir.join("index.html");
    let index_html = fs::read_to_string(&built_index_path).unwrap_or_else(|error| {
        panic!(
            "failed reading built client-ui HTML at {} after `pnpm --filter @ironmesh/client-ui build`: {error}",
            built_index_path.display()
        )
    });
    let script_path = extract_attr(&index_html, "src").unwrap_or_else(|| {
        panic!(
            "failed locating script src in built client-ui HTML {}",
            built_index_path.display()
        )
    });
    let stylesheet_path = extract_attr(&index_html, "href").unwrap_or_else(|| {
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

fn run_frontend_build(web_workspace_dir: &Path) {
    if !web_workspace_dir.exists() {
        panic!(
            "frontend workspace missing at {}. The client-ui must be built during cargo builds.",
            web_workspace_dir.display()
        );
    }

    let status = run_pnpm_command(web_workspace_dir, &["--filter", "@ironmesh/client-ui", "build"])
        .unwrap_or_else(|error| {
            panic!(
                "failed to execute `pnpm --filter @ironmesh/client-ui build` in {}: {error}. Install Node.js and pnpm, then ensure `pnpm` is on PATH.",
                web_workspace_dir.display()
            )
        });

    if !status.success() {
        panic!(
            "`pnpm --filter @ironmesh/client-ui build` failed in {}. Fix the frontend build before running cargo again.",
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
