#![cfg(windows)]

const DEFAULT_REMOTE_SNAPSHOT_CACHE_FILE_NAME: &str = ".ironmesh-remote-snapshot.json";

pub fn is_internal_remote_snapshot_relative_path(path: &str) -> bool {
    let normalized = path.trim().trim_matches(['/', '\\']).replace('\\', "/");
    normalized == DEFAULT_REMOTE_SNAPSHOT_CACHE_FILE_NAME
        || normalized.ends_with(&format!("/{DEFAULT_REMOTE_SNAPSHOT_CACHE_FILE_NAME}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_remote_snapshot_path_detection_matches_nested_and_root_relative_paths() {
        assert!(is_internal_remote_snapshot_relative_path(
            ".ironmesh-remote-snapshot.json"
        ));
        assert!(is_internal_remote_snapshot_relative_path(
            "nested/.ironmesh-remote-snapshot.json"
        ));
        assert!(!is_internal_remote_snapshot_relative_path(
            "nested/not-remote-snapshot.json"
        ));
    }
}
