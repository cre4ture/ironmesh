use anyhow::Result;
use normpath::PathExt;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub(crate) fn hresult_nonneg(hr: i32, operation: &str) -> Result<()> {
    if hr >= 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{operation} failed with HRESULT 0x{:08X}",
            hr as u32
        ))
    }
}

pub fn normalize_path(path: &str) -> String {
    path.trim()
        .trim_start_matches(['/', '\\'])
        .replace('\\', "/")
}

pub fn utf16_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn utf16_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn path_to_relative(sync_root: &Path, normalized_path: &str) -> String {
    let root = expand_path_if_possible(sync_root);
    let root_string = pathbuf_to_windows_string(&root);
    let root_trimmed = root_string.trim_end_matches('\\').to_string();
    let root_lower = root_trimmed.to_ascii_lowercase();

    let mut candidate = normalized_path.trim().replace('/', "\\");

    // CFAPI may omit the drive letter and return a leading '\' absolute path.
    if candidate.starts_with('\\')
        && !candidate.starts_with("\\\\")
        && let Some(drive) = drive_prefix(&root_trimmed)
    {
        candidate = format!("{drive}{candidate}");
    }

    let candidate_path = PathBuf::from(&candidate);
    let candidate_expanded = expand_path_if_possible(&candidate_path);
    let candidate_string = pathbuf_to_windows_string(&candidate_expanded);
    let candidate_lower = candidate_string.to_ascii_lowercase();

    // Primary path: use diff after path expansion/normalization.
    if let Some(diff) = pathdiff::diff_paths(&candidate_expanded, &root) {
        let candidate_relative = normalize_path(&diff.to_string_lossy());
        if !candidate_relative.is_empty() && !candidate_relative.starts_with("../") {
            return candidate_relative;
        }
    }

    // Fallback string-prefix path for CFAPI variants and case differences.
    if let Some(stripped) =
        strip_prefix_case_insensitive(&candidate_string, &candidate_lower, &root_lower)
    {
        return normalize_path(stripped.trim_start_matches(['\\', '/']));
    }

    // CFAPI sometimes provides a NormalizedPath like "\sync-root-name\file.txt".
    let trimmed_leading = candidate_string.trim_start_matches(['\\', '/']);
    if let Some(root_name_os) = root.file_name()
        && let Some(stripped) = strip_to_after_root_name_case_insensitive(
            trimmed_leading,
            &root_name_os.to_string_lossy(),
        )
    {
        return normalize_path(stripped.trim_start_matches(['\\', '/']));
    }

    normalize_path(trimmed_leading)
}

fn expand_path_if_possible(path: &Path) -> PathBuf {
    path.expand()
        .map(|expanded| expanded.to_path_buf())
        .unwrap_or_else(|_| path.to_path_buf())
}

fn pathbuf_to_windows_string(path: &Path) -> String {
    path.as_os_str().to_string_lossy().replace('/', "\\")
}

fn drive_prefix(path: &str) -> Option<&str> {
    if path.as_bytes().get(1) == Some(&b':') {
        Some(&path[..2])
    } else {
        None
    }
}

fn strip_prefix_case_insensitive<'a>(
    original_candidate: &'a str,
    candidate_lower: &str,
    root_lower: &str,
) -> Option<&'a str> {
    if !candidate_lower.starts_with(root_lower) {
        return None;
    }

    let root_len = root_lower.len();
    let remainder = &original_candidate[root_len..];
    Some(remainder)
}

fn strip_to_after_root_name_case_insensitive<'a>(
    candidate: &'a str,
    root_name: &str,
) -> Option<&'a str> {
    let candidate_lower = candidate.to_ascii_lowercase();
    let root_name_lower = root_name.to_ascii_lowercase();

    if let Some(rest) = candidate_lower.strip_prefix(&root_name_lower) {
        let consumed = candidate.len() - rest.len();
        return Some(&candidate[consumed..]);
    }

    let needle = format!("\\{root_name_lower}\\");
    let pos = candidate_lower.find(&needle)?;
    let start = pos + needle.len();
    Some(&candidate[start..])
}

#[cfg(test)]
mod tests {
    use super::path_to_relative;
    use std::path::Path;

    #[test]
    fn path_to_relative_strips_full_root_prefix_with_drive() {
        let sync_root = Path::new(r"C:\Users\hornu\AppData\Local\Temp\ironmesh-sync");
        let normalized_path = r"C:\Users\hornu\AppData\Local\Temp\ironmesh-sync\docs\readme.txt";

        let relative = path_to_relative(sync_root, normalized_path);
        assert_eq!(relative, "docs/readme.txt");
    }

    #[test]
    fn path_to_relative_handles_root_name_prefixed_path() {
        let sync_root = Path::new(r"C:\sync\ironmesh-sync2");
        let normalized_path = r"\ironmesh-sync2\folder\file.txt";

        let relative = path_to_relative(sync_root, normalized_path);
        assert_eq!(relative, "folder/file.txt");
    }

    #[test]
    fn path_to_relative_handles_missing_drive_letter_in_normalized_path() {
        let sync_root = Path::new(
            r"C:\Users\hornu\AppData\Local\Temp\ironmesh-cfapi-monitor-sync-root-1772014035705750400",
        );
        let normalized_path = r"\Users\hornu\AppData\Local\Temp\ironmesh-cfapi-monitor-sync-root-1772014035705750400\monitor_test.txt";

        let relative = path_to_relative(sync_root, normalized_path);
        assert_eq!(relative, "monitor_test.txt");
    }

    #[test]
    fn path_to_relative_handles_short_sync_root_and_full_user_path_without_drive() {
        let sync_root = Path::new(
            r"C:\Users\RUNNER~1\AppData\Local\Temp\ironmesh-cfapi-monitor-sync-root-parameterized-1772260118959530900",
        );
        let normalized_path = r"\Users\runneradmin\AppData\Local\Temp\ironmesh-cfapi-monitor-sync-root-parameterized-1772260118959530900\monitor_test.txt";

        let relative = path_to_relative(sync_root, normalized_path);
        assert_eq!(relative, "monitor_test.txt");
    }
}
