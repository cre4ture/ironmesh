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

    let mut candidate = normalized_path.replace('/', "\\");
    if let Some(stripped) = candidate.strip_prefix(&normalized_root) {
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
