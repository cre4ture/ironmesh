#![cfg(windows)]
#![allow(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use client_sdk::IronMeshClient;
use desktop_status::{
    DesktopStatusDocument, RemoteStatusUpdate, StatusFacet, StatusSnapshot, build_status_document,
    poll_remote_status, sleep_with_stop, starting_snapshot, write_status_document,
};
use std::mem::{size_of, zeroed};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, HICON,
    IDI_APPLICATION, IDI_ERROR, IDI_WARNING, LoadIconW, MSG, PostQuitMessage, RegisterClassW,
    SetTimer, TranslateMessage, WM_DESTROY, WM_TIMER, WNDCLASSW,
};

use crate::hydration_control::active_hydration_marker_count;

const STATUS_ICON_TIMER_ID: usize = 1;
const STATUS_ICON_POLL_INTERVAL_MS: u32 = 500;
const STATUS_TRAY_ICON_UID: u32 = 1;
const EMBEDDED_ICON_RESOURCE_ID: usize = 1;

#[derive(Debug, Clone)]
pub struct WindowsStatusOptions {
    pub profile_label: String,
    pub root_dir: PathBuf,
    pub connection_target: String,
    pub status_file: PathBuf,
}

pub struct WindowsStatusPublisher {
    profile_label: String,
    root_dir: PathBuf,
    connection_target: String,
    status_file: PathBuf,
    snapshot: Mutex<StatusSnapshot>,
}

impl WindowsStatusPublisher {
    pub fn new(options: &WindowsStatusOptions) -> Result<Self> {
        let publisher = Self {
            profile_label: options.profile_label.clone(),
            root_dir: options.root_dir.clone(),
            connection_target: options.connection_target.clone(),
            status_file: options.status_file.clone(),
            snapshot: Mutex::new(starting_snapshot(
                &options.root_dir,
                &options.connection_target,
            )),
        };
        publisher.persist()?;
        Ok(publisher)
    }

    pub fn update_sync_state(
        &self,
        state: impl Into<String>,
        summary: impl Into<String>,
        detail: impl Into<String>,
        icon_name: impl Into<String>,
    ) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.sync = StatusFacet::new(state, summary, detail, icon_name);
        self.persist_locked(&snapshot)
    }

    pub fn update_remote(&self, update: &RemoteStatusUpdate) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.connection = update.connection.clone();
        snapshot.replication = update.replication.clone();
        self.persist_locked(&snapshot)
    }

    pub fn update_remote_error(&self, error: &anyhow::Error) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.connection = StatusFacet::new(
            "error",
            "Connection unavailable",
            format!("{error:#}"),
            "network-error-symbolic",
        );
        snapshot.replication = StatusFacet::new(
            "unknown",
            "Replication unavailable",
            "Waiting for a successful server connection",
            "dialog-question-symbolic",
        );
        self.persist_locked(&snapshot)
    }

    pub fn current_document(&self) -> Result<DesktopStatusDocument> {
        let snapshot = self.lock_snapshot()?.clone();
        Ok(build_status_document(
            self.profile_label.clone(),
            &self.root_dir,
            self.connection_target.clone(),
            &snapshot,
        ))
    }

    pub fn persist(&self) -> Result<()> {
        let snapshot = self.lock_snapshot()?.clone();
        self.persist_locked(&snapshot)
    }

    fn lock_snapshot(&self) -> Result<std::sync::MutexGuard<'_, StatusSnapshot>> {
        self.snapshot
            .lock()
            .map_err(|_| anyhow!("Windows status snapshot lock poisoned"))
    }

    fn persist_locked(&self, snapshot: &StatusSnapshot) -> Result<()> {
        let document = build_status_document(
            self.profile_label.clone(),
            &self.root_dir,
            self.connection_target.clone(),
            snapshot,
        );
        write_status_document(&self.status_file, &document)
    }
}

pub fn spawn_remote_status_thread(
    running: Arc<AtomicBool>,
    publisher: Arc<WindowsStatusPublisher>,
    client: IronMeshClient,
    remote_status_poll_interval_ms: u64,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("ironmesh-windows-status".to_string())
        .spawn(move || {
            let poll_interval = Duration::from_millis(remote_status_poll_interval_ms.max(1_000));

            while running.load(Ordering::SeqCst) {
                match poll_remote_status(&client) {
                    Ok(update) => {
                        if let Err(error) = publisher.update_remote(&update) {
                            tracing::warn!(
                                "windows-status: failed to persist remote status: {error:#}"
                            );
                        }
                    }
                    Err(error) => {
                        if let Err(persist_error) = publisher.update_remote_error(&error) {
                            tracing::warn!(
                                "windows-status: failed to persist remote error: {persist_error:#}"
                            );
                        }
                    }
                }

                sleep_with_stop(&running, poll_interval);
            }
        })
        .context("failed to spawn Windows remote status thread")
}

pub struct WindowsTrayIconHandle {
    running: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl WindowsTrayIconHandle {
    pub fn spawn(
        running: Arc<AtomicBool>,
        sync_root: PathBuf,
        publisher: Arc<WindowsStatusPublisher>,
    ) -> Result<Self> {
        let shared = Arc::new(TraySharedState {
            running: running.clone(),
            sync_root,
            publisher,
        });

        {
            let mut slot = tray_shared_state()
                .lock()
                .map_err(|_| anyhow!("Windows tray shared state lock poisoned"))?;
            if slot.is_some() {
                return Err(anyhow!(
                    "Windows tray status is already running in this process"
                ));
            }
            *slot = Some(shared);
        }

        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = match thread::Builder::new()
            .name("ironmesh-windows-tray".to_string())
            .spawn(move || {
                let result = tray_thread_main(ready_tx);
                if let Err(error) = result {
                    tracing::warn!("windows-status: tray loop exited early: {error:#}");
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
                return Err(error).context("failed to spawn Windows tray thread");
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
                Err(anyhow!(error)).context("failed to receive Windows tray startup result")
            }
        }
    }

    pub fn shutdown(mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct TraySharedState {
    running: Arc<AtomicBool>,
    sync_root: PathBuf,
    publisher: Arc<WindowsStatusPublisher>,
}

fn tray_thread_main(ready_tx: mpsc::Sender<Result<()>>) -> Result<()> {
    let class_name = utf16_null("IronMeshWindowsTrayStatus");
    let instance = unsafe { GetModuleHandleW(null()) };
    if instance.is_null() {
        let error = anyhow!("failed to load current module handle for tray window");
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
        let error = anyhow!("failed to create hidden tray status window");
        let _ = ready_tx.send(Err(anyhow!("{error:#}")));
        return Err(error);
    }

    match update_tray_icon(hwnd, true) {
        Ok(true) => {}
        Ok(false) => {
            let error = anyhow!("failed to add Windows notification-area icon");
            let _ = ready_tx.send(Err(anyhow!("{error:#}")));
            return Err(error);
        }
        Err(error) => {
            let _ = ready_tx.send(Err(anyhow!("{error:#}")));
            return Err(error);
        }
    }
    unsafe {
        SetTimer(
            hwnd,
            STATUS_ICON_TIMER_ID,
            STATUS_ICON_POLL_INTERVAL_MS,
            None,
        );
    }
    let _ = ready_tx.send(Ok(()));

    let mut message: MSG = unsafe { zeroed() };
    loop {
        let code = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
        if code == -1 {
            return Err(anyhow!("Windows tray message loop failed"));
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
    wparam: WPARAM,
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
            if let Err(error) = update_tray_icon(hwnd, false) {
                tracing::warn!("windows-status: tray icon refresh failed: {error:#}");
            }
            0
        }
        WM_DESTROY => {
            let _ = remove_tray_icon(hwnd);
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
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
        .ok_or_else(|| anyhow!("Windows tray shared state disappeared during icon update"))?;
    let document = effective_document_for_tray(&shared)?;
    let icon = load_icon_for_state(document.overall.state.as_str());

    let mut data: NOTIFYICONDATAW = unsafe { zeroed() };
    data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = STATUS_TRAY_ICON_UID;
    data.uFlags = NIF_ICON | NIF_TIP;
    data.hIcon = icon;
    copy_utf16_truncated(&build_tooltip(&document), &mut data.szTip);

    let command = if add_icon { NIM_ADD } else { NIM_MODIFY };
    Ok(unsafe { Shell_NotifyIconW(command, &data) } != 0)
}

fn remove_tray_icon(hwnd: HWND) -> Result<()> {
    let mut data: NOTIFYICONDATAW = unsafe { zeroed() };
    data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = STATUS_TRAY_ICON_UID;
    let removed = unsafe { Shell_NotifyIconW(NIM_DELETE, &data) } != 0;
    if removed {
        Ok(())
    } else {
        Err(anyhow!("failed to remove Windows notification-area icon"))
    }
}

fn effective_document_for_tray(shared: &TraySharedState) -> Result<DesktopStatusDocument> {
    let mut document = shared.publisher.current_document()?;
    let active_hydrations = active_hydration_marker_count(&shared.sync_root)?;
    if active_hydrations > 0
        && !matches!(
            document.sync.state.as_str(),
            "error" | "stopped" | "starting"
        )
    {
        document.sync = StatusFacet::new(
            "syncing",
            "Hydrating files on demand",
            format!("{active_hydrations} active hydration request(s)"),
            "view-refresh-symbolic",
        );
        let snapshot = StatusSnapshot {
            connection: document.connection.clone(),
            sync: document.sync.clone(),
            replication: document.replication.clone(),
        };
        document.overall = desktop_status::overall_status_facet(&snapshot);
    }
    Ok(document)
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
