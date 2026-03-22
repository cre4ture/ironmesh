#[path = "../../build-support/windows_icon_build.rs"]
mod windows_icon_build;

fn main() {
    windows_icon_build::embed_icon("../../assets/windows/ironmesh.ico");
}
