use anyhow::Result;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

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
    let normalized_root = sync_root
        .as_os_str()
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_string();
    let normalized_root_without_drive = normalized_root
        .strip_prefix("\\\\")
        .map(|_| normalized_root.as_str())
        .unwrap_or_else(|| {
            if normalized_root.as_bytes().get(1) == Some(&b':') {
                &normalized_root[2..]
            } else {
                normalized_root.as_str()
            }
        });

    let mut candidate = normalized_path.replace('/', "\\");
    if let Some(stripped) = candidate.strip_prefix(&normalized_root) {
        candidate = stripped.to_string();
    } else if let Some(stripped) = candidate.strip_prefix(normalized_root_without_drive) {
        candidate = stripped.to_string();
    } else {
        // CFAPI sometimes provides a NormalizedPath that starts with a leading
        // backslash and the sync-root name (e.g. "\\ironmesh-sync2\\file.txt").
        // In that case, strip the leading separators and then remove the
        // sync-root folder name if present.
        let trimmed_leading = candidate.trim_start_matches(['\\', '/']).to_string();
        if let Some(root_name_os) = sync_root.file_name() {
            let root_name = root_name_os.to_string_lossy();
            if let Some(stripped) = trimmed_leading.strip_prefix(root_name.as_ref()) {
                candidate = stripped.to_string();
            }
        }
    }

    normalize_path(candidate.trim_start_matches(['\\', '/']))
}

#[cfg(test)]
mod tests {
    use super::path_to_relative;
    use std::path::Path;

    #[test]
    fn path_to_relative_strips_full_root_prefix_with_drive() {
        let sync_root = Path::new(r"C:\Users\hornu\AppData\Local\Temp\ironmesh-sync");
        let normalized_path =
            r"C:\Users\hornu\AppData\Local\Temp\ironmesh-sync\docs\readme.txt";

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
}
