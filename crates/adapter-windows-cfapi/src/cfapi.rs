use crate::helpers::hresult_nonneg;
use anyhow::Result;
use std::os::windows::fs::MetadataExt;
use std::path::Path;

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
    use core::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::CloudFilters::CfGetPlaceholderInfo;

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
            eprintln!(
                "{}: CfGetPlaceholderInfo for {}: returned={}",
                label, rel_path, returned
            );
            Ok(returned)
        }
        Err(err) => {
            eprintln!(
                "{}: CfGetPlaceholderInfo error for {}: {}",
                label, rel_path, err
            );
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

pub fn try_convert_materialized_file(
    file_path: &Path,
    rel_path: &str,
    metadata: &std::fs::Metadata,
) {
    {
        let attrs = metadata.file_attributes();
        eprintln!(
            "monitor: attempting convert path={} attrs=0x{:08x} size={}",
            file_path.display(),
            attrs,
            metadata.len()
        );
    }
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(file_path)
    {
        Ok(fh_file) => {
            if is_placeholder(&fh_file) {
                eprintln!(
                    "x: skipping convert for {} because placeholder info present",
                    rel_path
                );
            } else {
                let result = cf_convert_to_placeholder(&fh_file);
                if result.is_ok() {
                    eprintln!(
                        "x: converted materialized file to placeholder: {}",
                        rel_path
                    );
                } else {
                    eprintln!(
                        "x: failed to convert materialized file to placeholder {}: {:?}",
                        rel_path,
                        result.err()
                    );
                    if let Ok(m) = std::fs::metadata(file_path) {
                        let attrs = m.file_attributes();
                        eprintln!("x: post-fail attrs=0x{:08x} size={}", attrs, m.len());
                    }
                }
            }
        }
        Err(err) => {
            eprintln!(
                "x: failed to open materialized file {} for conversion: {}",
                rel_path, err
            );
        }
    }
}
