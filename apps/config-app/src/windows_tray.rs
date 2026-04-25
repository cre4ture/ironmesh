#![cfg(windows)]
#![allow(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use desktop_status::{
    DesktopStatusDocument, StatusFacet, StatusSnapshot, build_status_document, read_status_document,
};
use std::mem::{size_of, zeroed};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
    Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DestroyWindow,
    DispatchMessageW, GetCursorPos, GetMessageW, HICON, IDI_APPLICATION, IDI_ERROR, IDI_WARNING,
    LoadIconW, MF_STRING, MSG, PostQuitMessage, RegisterClassW, SetForegroundWindow, SetTimer,
    TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu, TranslateMessage, WM_APP, WM_DESTROY,
    WM_LBUTTONUP, WM_RBUTTONUP, WM_TIMER, WNDCLASSW,
};

const TRAY_TIMER_ID: usize = 1;
const TRAY_POLL_INTERVAL_MS: u32 = 1_000;
const TRAY_ICON_UID: u32 = 1;
const TRAY_CALLBACK_MESSAGE: u32 = WM_APP + 7;
const TRAY_MENU_OPEN_ID: usize = 1;
const EMBEDDED_ICON_RESOURCE_ID: usize = 1;

pub struct WindowsConfigTrayHandle {
    running: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl WindowsConfigTrayHandle {
    pub fn spawn(status_file: PathBuf, web_ui_url: String) -> Result<Self> {
        let running = Arc::new(AtomicBool::new(true));
        let shared = Arc::new(TraySharedState {
            running: running.clone(),
            icon_added: AtomicBool::new(false),
            status_file,
            web_ui_url,
        });

        {
            let mut slot = tray_shared_state()
                .lock()
                .map_err(|_| anyhow!("Windows config tray shared state lock poisoned"))?;
            if slot.is_some() {
                return Err(anyhow!(
                    "Windows config tray is already running in this process"
                ));
            }
            *slot = Some(shared);
        }

        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = match thread::Builder::new()
            .name("ironmesh-config-windows-tray".to_string())
            .spawn(move || {
                let result = tray_thread_main(ready_tx);
                if let Err(error) = result {
                    eprintln!("windows-tray: tray loop exited early: {error:#}");
                }
                if let Ok(mut slot) = tray_shared_state().lock() {
                    *slot = None;
                }
            }) {
            Ok(thread) => thread,
            Err(error) => {
                if let Ok(mut slot) = tray_shared_state().lock() {
                    *slot = None;
                }
                return Err(error).context("failed to spawn Windows config tray thread");
            }
        };

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                running,
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(error) => {
                let _ = thread.join();
                Err(anyhow!(error)).context("failed to receive Windows config tray startup result")
            }
        }
    }
}

impl Drop for WindowsConfigTrayHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct TraySharedState {
    running: Arc<AtomicBool>,
    icon_added: AtomicBool,
    status_file: PathBuf,
    web_ui_url: String,
}

fn tray_thread_main(ready_tx: mpsc::Sender<Result<()>>) -> Result<()> {
    let class_name = utf16_null("IronMeshConfigTrayStatus");
    let instance = unsafe { GetModuleHandleW(null()) };
    if instance.is_null() {
        let error = anyhow!("failed to load current module handle for config tray window");
        let _ = ready_tx.send(Err(anyhow!("{error:#}")));
        return Err(error);
    }

    let window_class = WNDCLASSW {
        lpfnWndProc: Some(tray_window_proc),
        hInstance: instance,
        lpszClassName: class_name.as_ptr(),
        ..unsafe { zeroed() }
    };
    unsafe {
        RegisterClassW(&window_class);
    }

    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if hwnd.is_null() {
        let error = anyhow!("failed to create hidden config tray window");
        let _ = ready_tx.send(Err(anyhow!("{error:#}")));
        return Err(error);
    }

    match update_tray_icon(hwnd, true) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!(
                "windows-tray: failed to add notification-area icon; will retry while running"
            );
        }
        Err(error) => {
            eprintln!("windows-tray: failed to add notification-area icon: {error:#}");
        }
    }
    unsafe {
        SetTimer(hwnd, TRAY_TIMER_ID, TRAY_POLL_INTERVAL_MS, None);
    }
    let _ = ready_tx.send(Ok(()));

    let mut message: MSG = unsafe { zeroed() };
    loop {
        let code = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
        if code == -1 {
            return Err(anyhow!("Windows config tray message loop failed"));
        }
        if code == 0 {
            break;
        }
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    Ok(())
}

unsafe extern "system" fn tray_window_proc(
    hwnd: HWND,
    msg: u32,
    _wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_TIMER => {
            let Some(shared) = current_tray_shared_state() else {
                unsafe { DestroyWindow(hwnd) };
                return 0;
            };
            if !shared.running.load(Ordering::SeqCst) {
                unsafe { DestroyWindow(hwnd) };
                return 0;
            }
            let add_icon = !shared.icon_added.load(Ordering::SeqCst);
            if let Err(error) = update_tray_icon(hwnd, add_icon) {
                eprintln!("windows-tray: tray icon refresh failed: {error:#}");
            }
            0
        }
        TRAY_CALLBACK_MESSAGE => {
            if matches!(lparam as u32, WM_LBUTTONUP | WM_RBUTTONUP) {
                show_tray_menu(hwnd);
            }
            0
        }
        WM_DESTROY => {
            let _ = remove_tray_icon(hwnd);
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, _wparam, lparam) },
    }
}

fn current_tray_shared_state() -> Option<Arc<TraySharedState>> {
    tray_shared_state()
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().cloned())
}

fn update_tray_icon(hwnd: HWND, add_icon: bool) -> Result<bool> {
    let shared = current_tray_shared_state()
        .ok_or_else(|| anyhow!("Windows config tray shared state disappeared"))?;
    let document = read_status_document(&shared.status_file)
        .unwrap_or_else(|_| fallback_document(&shared.status_file, &shared.web_ui_url));
    let icon = load_icon_for_state(document.overall.state.as_str());

    let mut data: NOTIFYICONDATAW = unsafe { zeroed() };
    data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = TRAY_ICON_UID;
    data.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    data.uCallbackMessage = TRAY_CALLBACK_MESSAGE;
    data.hIcon = icon;
    copy_utf16_truncated(&build_tooltip(&document), &mut data.szTip);

    let command = if add_icon { NIM_ADD } else { NIM_MODIFY };
    let updated = unsafe { Shell_NotifyIconW(command, &data) } != 0;
    if updated {
        shared.icon_added.store(true, Ordering::SeqCst);
    }
    Ok(updated)
}

fn remove_tray_icon(hwnd: HWND) -> Result<()> {
    let shared = current_tray_shared_state();
    if shared
        .as_ref()
        .is_some_and(|shared| !shared.icon_added.load(Ordering::SeqCst))
    {
        return Ok(());
    }

    let mut data: NOTIFYICONDATAW = unsafe { zeroed() };
    data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = TRAY_ICON_UID;
    let removed = unsafe { Shell_NotifyIconW(NIM_DELETE, &data) } != 0;
    if removed {
        if let Some(shared) = shared {
            shared.icon_added.store(false, Ordering::SeqCst);
        }
        Ok(())
    } else {
        Err(anyhow!(
            "failed to remove Windows config notification-area icon"
        ))
    }
}

fn show_tray_menu(hwnd: HWND) {
    let Some(shared) = current_tray_shared_state() else {
        return;
    };

    let menu = unsafe { CreatePopupMenu() };
    if menu.is_null() {
        return;
    }

    let label = utf16_null("Open IronMesh Config");
    unsafe {
        AppendMenuW(menu, MF_STRING, TRAY_MENU_OPEN_ID, label.as_ptr());
        SetForegroundWindow(hwnd);
    }

    let mut point: POINT = unsafe { zeroed() };
    if unsafe { GetCursorPos(&mut point) } == 0 {
        unsafe {
            DestroyMenu(menu);
        }
        return;
    }

    let selected = unsafe {
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON | TPM_RETURNCMD,
            point.x,
            point.y,
            0,
            hwnd,
            null(),
        )
    };
    unsafe {
        DestroyMenu(menu);
    }

    if selected as usize == TRAY_MENU_OPEN_ID {
        open_config_url(&shared.web_ui_url);
    }
}

fn open_config_url(url: &str) {
    let _ = std::process::Command::new("explorer.exe").arg(url).spawn();
}

fn fallback_document(status_file: &std::path::Path, web_ui_url: &str) -> DesktopStatusDocument {
    let snapshot = StatusSnapshot {
        connection: StatusFacet::new(
            "unknown",
            "Connection status pending",
            "Waiting for the config app to publish service status",
            "dialog-question-symbolic",
        ),
        sync: StatusFacet::new(
            "starting",
            "Starting IronMesh desktop status",
            "The config app is preparing the merged status document",
            "view-refresh-symbolic",
        ),
        replication: StatusFacet::new(
            "unknown",
            "Replication status pending",
            "Waiting for service telemetry",
            "dialog-question-symbolic",
        ),
    };
    let mut document = build_status_document("IronMesh", status_file, web_ui_url, &snapshot);
    document.web_ui_url = Some(web_ui_url.to_string());
    document
}

fn build_tooltip(document: &DesktopStatusDocument) -> String {
    match document.overall.state.as_str() {
        "syncing" => format!("IronMesh: {}", document.sync.detail),
        "error" | "warning" => format!("IronMesh: {}", document.overall.summary),
        _ => format!("IronMesh: {}", document.overall.summary),
    }
}

fn load_icon_for_state(state: &str) -> HICON {
    unsafe {
        match state {
            "error" => LoadIconW(null_mut(), IDI_ERROR),
            "warning" => LoadIconW(null_mut(), IDI_WARNING),
            _ => {
                let instance = GetModuleHandleW(null());
                let embedded = LoadIconW(instance, EMBEDDED_ICON_RESOURCE_ID as *const u16);
                if !embedded.is_null() {
                    embedded
                } else {
                    LoadIconW(null_mut(), IDI_APPLICATION)
                }
            }
        }
    }
}

fn copy_utf16_truncated(value: &str, target: &mut [u16]) {
    if target.is_empty() {
        return;
    }

    let mut encoded = value.encode_utf16();
    let mut index = 0usize;
    while index + 1 < target.len() {
        let Some(code_unit) = encoded.next() else {
            break;
        };
        target[index] = code_unit;
        index += 1;
    }
    target[index] = 0;
}

fn utf16_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn tray_shared_state() -> &'static Mutex<Option<Arc<TraySharedState>>> {
    static SHARED: std::sync::OnceLock<Mutex<Option<Arc<TraySharedState>>>> =
        std::sync::OnceLock::new();
    SHARED.get_or_init(|| Mutex::new(None))
}
