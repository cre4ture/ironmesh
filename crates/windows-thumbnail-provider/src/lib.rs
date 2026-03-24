#![cfg(windows)]

use std::ffi::c_void;
use std::ptr::{copy_nonoverlapping, null_mut};
use std::sync::Mutex;

use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_NOINTERFACE, E_POINTER, S_FALSE,
};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateDIBSection, DIB_RGB_COLORS, HBITMAP,
};
use windows::Win32::System::Com::{CoTaskMemFree, IClassFactory, IClassFactory_Impl};
use windows::Win32::UI::Shell::{
    IInitializeWithItem, IInitializeWithItem_Impl, IShellItem, IThumbnailProvider,
    IThumbnailProvider_Impl, SIGDN_FILESYSPATH, WTS_ALPHATYPE, WTSAT_ARGB,
};
use windows_core::{BOOL, GUID, HRESULT, IUnknown, Interface, PWSTR, Ref, Result, implement};

pub const THUMBNAIL_PROVIDER_CLSID: GUID = GUID::from_u128(0xd2e0fd2a_1d7b_4be4_920a_8a6d019454cb);
pub const CUSTOM_STATE_HANDLER_CLSID: GUID =
    GUID::from_u128(0x2a69ab09_87fb_4af7_93c4_6ca7d4853fd0);
pub const EXTENDED_PROPERTY_HANDLER_CLSID: GUID =
    GUID::from_u128(0x7d0f3be1_4d8f_4f40_b4fd_8c098d7b96a2);
pub const BANNERS_HANDLER_CLSID: GUID = GUID::from_u128(0x8a98e31d_1d95_4d26_9dd9_32e2bb3c652a);
pub const CONTEXT_MENU_HANDLER_CLSID: GUID =
    GUID::from_u128(0x8d3bf08a_6c23_40bf_9fcb_46bb6f6be13a);
pub const CONTENT_URI_SOURCE_CLSID: GUID = GUID::from_u128(0xf1aa7371_0c71_4519_8c04_a41dc77f6af1);
pub const STATUS_UI_SOURCE_FACTORY_CLSID: GUID =
    GUID::from_u128(0x47e87ba5_1eb9_4f16_a944_4684850839b5);

const MIN_THUMBNAIL_SIZE: u32 = 32;
const MAX_THUMBNAIL_SIZE: u32 = 512;

#[implement(IInitializeWithItem, IThumbnailProvider)]
struct IronmeshThumbnailProvider {
    source_path: Mutex<Option<String>>,
}

impl IronmeshThumbnailProvider {
    fn new() -> Self {
        Self {
            source_path: Mutex::new(None),
        }
    }
}

#[allow(non_snake_case)]
impl IInitializeWithItem_Impl for IronmeshThumbnailProvider_Impl {
    fn Initialize(&self, psi: Ref<'_, IShellItem>, _grfmode: u32) -> Result<()> {
        let resolved = psi
            .as_ref()
            .and_then(|item| unsafe { shell_item_path(item) });
        *self
            .source_path
            .lock()
            .expect("thumbnail path lock poisoned") = resolved;
        Ok(())
    }
}

#[allow(non_snake_case)]
impl IThumbnailProvider_Impl for IronmeshThumbnailProvider_Impl {
    fn GetThumbnail(
        &self,
        cx: u32,
        phbmp: *mut HBITMAP,
        pdwalpha: *mut WTS_ALPHATYPE,
    ) -> Result<()> {
        if phbmp.is_null() || pdwalpha.is_null() {
            return Err(E_POINTER.into());
        }

        let bitmap =
            unsafe { create_prototype_bitmap(cx.clamp(MIN_THUMBNAIL_SIZE, MAX_THUMBNAIL_SIZE))? };
        unsafe {
            *phbmp = bitmap;
            *pdwalpha = WTSAT_ARGB;
        }
        Ok(())
    }
}

#[implement(IClassFactory)]
struct IronmeshThumbnailProviderFactory;

#[allow(non_snake_case)]
impl IClassFactory_Impl for IronmeshThumbnailProviderFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut c_void,
    ) -> Result<()> {
        if !punkouter.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        if riid.is_null() || ppvobject.is_null() {
            return Err(E_POINTER.into());
        }

        unsafe {
            *ppvobject = null_mut();
        }

        let unknown: IUnknown = IronmeshThumbnailProvider::new().into();
        unsafe { unknown.query(riid, ppvobject).ok() }
    }

    fn LockServer(&self, _flock: BOOL) -> Result<()> {
        Ok(())
    }
}

#[implement(IClassFactory)]
struct UnsupportedHandlerFactory;

#[allow(non_snake_case)]
impl IClassFactory_Impl for UnsupportedHandlerFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, IUnknown>,
        _riid: *const GUID,
        _ppvobject: *mut *mut c_void,
    ) -> Result<()> {
        if !punkouter.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        Err(E_NOINTERFACE.into())
    }

    fn LockServer(&self, _flock: BOOL) -> Result<()> {
        Ok(())
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
/// # Safety
///
/// COM/Explorer must provide valid output pointers when requesting the class object.
/// The `rclsid`, `riid`, and `ppv` pointers must be non-null and valid for reads/writes
/// according to the standard `DllGetClassObject` contract.
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        return E_POINTER;
    }

    unsafe {
        *ppv = null_mut();
    }

    let clsid = unsafe { *rclsid };
    let factory: IUnknown = if clsid == THUMBNAIL_PROVIDER_CLSID {
        IronmeshThumbnailProviderFactory.into()
    } else if is_unsupported_handler_clsid(clsid) {
        UnsupportedHandlerFactory.into()
    } else {
        return CLASS_E_CLASSNOTAVAILABLE;
    };

    match unsafe { factory.query(riid, ppv.cast()).ok() } {
        Ok(()) => HRESULT(0),
        Err(error) => error.code(),
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_FALSE
}

fn is_unsupported_handler_clsid(clsid: GUID) -> bool {
    clsid == CUSTOM_STATE_HANDLER_CLSID
        || clsid == EXTENDED_PROPERTY_HANDLER_CLSID
        || clsid == BANNERS_HANDLER_CLSID
        || clsid == CONTEXT_MENU_HANDLER_CLSID
        || clsid == CONTENT_URI_SOURCE_CLSID
        || clsid == STATUS_UI_SOURCE_FACTORY_CLSID
}

unsafe fn shell_item_path(item: &IShellItem) -> Option<String> {
    let value = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }.ok()?;
    let result = pwstr_to_string(value);
    unsafe {
        CoTaskMemFree(Some(value.0.cast()));
    }
    result
}

fn pwstr_to_string(value: PWSTR) -> Option<String> {
    if value.is_null() {
        return None;
    }
    unsafe { value.to_string().ok() }
}

unsafe fn create_prototype_bitmap(size: u32) -> Result<HBITMAP> {
    let pixels = prototype_bgra_pixels(size);
    let mut bits = null_mut();
    let bitmap_info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: size as i32,
            biHeight: -(size as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            biSizeImage: (pixels.len()) as u32,
            ..Default::default()
        },
        ..Default::default()
    };

    let bitmap =
        unsafe { CreateDIBSection(None, &bitmap_info, DIB_RGB_COLORS, &mut bits, None, 0)? };
    if bits.is_null() {
        return Err(E_POINTER.into());
    }

    unsafe {
        copy_nonoverlapping(pixels.as_ptr(), bits.cast::<u8>(), pixels.len());
    }
    Ok(bitmap)
}

fn prototype_bgra_pixels(size: u32) -> Vec<u8> {
    let size = size.clamp(MIN_THUMBNAIL_SIZE, MAX_THUMBNAIL_SIZE) as usize;
    let mut pixels = vec![0u8; size * size * 4];

    let background_top = [24u8, 48u8, 70u8, 255u8];
    let background_bottom = [9u8, 26u8, 44u8, 255u8];
    let mesh = [109u8, 223u8, 212u8, 255u8];
    let node = [234u8, 252u8, 251u8, 255u8];

    for y in 0..size {
        let blend = y as f32 / (size.saturating_sub(1).max(1)) as f32;
        let color = lerp_color(background_top, background_bottom, blend);
        for x in 0..size {
            put_pixel(&mut pixels, size, x, y, color);
        }
    }

    let margin = size / 5;
    let center = size / 2;
    let upper = size / 3;
    let lower = size - upper;

    draw_line(&mut pixels, size, margin, upper, center, margin, mesh);
    draw_line(
        &mut pixels,
        size,
        center,
        margin,
        size - margin,
        upper,
        mesh,
    );
    draw_line(&mut pixels, size, margin, upper, center, lower, mesh);
    draw_line(&mut pixels, size, size - margin, upper, center, lower, mesh);
    draw_line(&mut pixels, size, center, margin, center, lower, mesh);

    let radius = (size / 14).max(3);
    fill_circle(&mut pixels, size, margin, upper, radius, node);
    fill_circle(&mut pixels, size, center, margin, radius, node);
    fill_circle(&mut pixels, size, size - margin, upper, radius, node);
    fill_circle(&mut pixels, size, center, lower, radius, node);

    pixels
}

fn lerp_color(a: [u8; 4], b: [u8; 4], t: f32) -> [u8; 4] {
    let mix = |start: u8, end: u8| -> u8 {
        ((start as f32) + ((end as f32) - (start as f32)) * t)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    [
        mix(a[0], b[0]),
        mix(a[1], b[1]),
        mix(a[2], b[2]),
        mix(a[3], b[3]),
    ]
}

fn put_pixel(buffer: &mut [u8], size: usize, x: usize, y: usize, color: [u8; 4]) {
    if x >= size || y >= size {
        return;
    }
    let offset = (y * size + x) * 4;
    buffer[offset..offset + 4].copy_from_slice(&color);
}

fn draw_line(
    buffer: &mut [u8],
    size: usize,
    x0: usize,
    y0: usize,
    x1: usize,
    y1: usize,
    color: [u8; 4],
) {
    let (mut x0, mut y0, x1, y1) = (x0 as isize, y0 as isize, x1 as isize, y1 as isize);
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;

    loop {
        for offset_y in -1..=1 {
            for offset_x in -1..=1 {
                let px = x0 + offset_x;
                let py = y0 + offset_y;
                if px >= 0 && py >= 0 {
                    put_pixel(buffer, size, px as usize, py as usize, color);
                }
            }
        }

        if x0 == x1 && y0 == y1 {
            break;
        }

        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x0 += sx;
        }
        if e2 <= dx {
            err += dx;
            y0 += sy;
        }
    }
}

fn fill_circle(
    buffer: &mut [u8],
    size: usize,
    center_x: usize,
    center_y: usize,
    radius: usize,
    color: [u8; 4],
) {
    let radius_sq = (radius * radius) as isize;
    let center_x = center_x as isize;
    let center_y = center_y as isize;

    for y in -(radius as isize)..=(radius as isize) {
        for x in -(radius as isize)..=(radius as isize) {
            if x * x + y * y <= radius_sq {
                let px = center_x + x;
                let py = center_y + y;
                if px >= 0 && py >= 0 {
                    put_pixel(buffer, size, px as usize, py as usize, color);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_THUMBNAIL_SIZE, MIN_THUMBNAIL_SIZE, prototype_bgra_pixels};

    #[test]
    fn prototype_bitmap_respects_size_bounds() {
        let tiny = prototype_bgra_pixels(1);
        assert_eq!(
            tiny.len(),
            (MIN_THUMBNAIL_SIZE * MIN_THUMBNAIL_SIZE * 4) as usize
        );

        let huge = prototype_bgra_pixels(10_000);
        assert_eq!(
            huge.len(),
            (MAX_THUMBNAIL_SIZE * MAX_THUMBNAIL_SIZE * 4) as usize
        );
    }

    #[test]
    fn prototype_bitmap_is_opaque() {
        let pixels = prototype_bgra_pixels(64);
        assert!(pixels.chunks_exact(4).all(|pixel| pixel[3] == 255));
    }
}
