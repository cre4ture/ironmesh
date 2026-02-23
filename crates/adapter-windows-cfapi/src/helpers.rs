use std::path::Path;
use std::os::windows::ffi::OsStrExt;
use anyhow::Result;

pub fn cf_convert_to_placeholder(file: &std::fs::File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::CloudFilters::CfConvertToPlaceholder;

    let hr = unsafe {
        CfConvertToPlaceholder(
            file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            std::ptr::null(),
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    hresult_nonneg(hr, "CfConvertToPlaceholder")
}

pub fn cf_get_placeholder_info(file: &std::fs::File) -> Result<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::CloudFilters::CfGetPlaceholderInfo;
    use core::ffi::c_void;

    let mut info_buf = vec![0u8; 1024];
    let mut returned: u32 = 0;
    let hr_info = unsafe {
        CfGetPlaceholderInfo(
            file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            0,
            info_buf.as_mut_ptr() as *mut c_void,
            info_buf.len() as u32,
            &mut returned,
        )
    };
    hresult_nonneg(hr_info, "CfGetPlaceholderInfo")?;
    Ok(returned)
}

pub fn get_and_log_placeholder_info(
    file: &std::fs::File,
    label: &str,
    rel_path: &str,
) -> Result<u32> {
    match cf_get_placeholder_info(file) {
        Ok(returned) => {
            eprintln!("{}: CfGetPlaceholderInfo for {}: returned={}", label, rel_path, returned);
            Ok(returned)
        }
        Err(err) => {
            eprintln!("{}: CfGetPlaceholderInfo error for {}: {}", label, rel_path, err);
            Err(err)
        }
    }
}

pub fn is_placeholder(file: &std::fs::File) -> bool {
    get_and_log_placeholder_info(file, "", "").unwrap_or(0) > 0
}

pub fn path_is_placeholder(path: &Path) -> bool {
    match std::fs::File::open(path) {
        Ok(file) => is_placeholder(&file),
        Err(_) => false,
    }
}

fn hresult_nonneg(hr: i32, operation: &str) -> Result<()> {
    if hr >= 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("{operation} failed with HRESULT 0x{:08X}", hr as u32))
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

