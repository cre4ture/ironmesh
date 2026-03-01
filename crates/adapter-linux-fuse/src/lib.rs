#![cfg(not(windows))]

pub mod mount_main;

use sync_core::{SyncOperation, SyncPlan, SyncPolicy, SyncSnapshot, plan_sync};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxFuseAdapter {
    pub mount_name: String,
}

impl LinuxFuseAdapter {
    pub fn new(mount_name: impl Into<String>) -> Self {
        Self {
            mount_name: mount_name.into(),
        }
    }

    pub fn plan_actions(&self, snapshot: &SyncSnapshot, policy: &SyncPolicy) -> FuseActionPlan {
        let sync_plan = plan_sync(snapshot, policy);
        map_sync_plan_to_fuse_actions(&sync_plan)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FuseActionPlan {
    pub actions: Vec<FuseAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuseAction {
    EnsureDirectory {
        path: String,
    },
    EnsurePlaceholder {
        path: String,
        remote_version: String,
    },
    HydrateOnRead {
        path: String,
        remote_version: String,
    },
    UploadOnFlush {
        path: String,
        local_version: Option<String>,
    },
    MarkConflict {
        path: String,
        local_version: Option<String>,
        remote_version: Option<String>,
    },
}

pub fn map_sync_plan_to_fuse_actions(sync_plan: &SyncPlan) -> FuseActionPlan {
    let mut actions = Vec::with_capacity(sync_plan.operations.len());

    for operation in &sync_plan.operations {
        let mapped = match operation {
            SyncOperation::CreateDirectory { path } => {
                FuseAction::EnsureDirectory { path: path.clone() }
            }
            SyncOperation::EnsurePlaceholder {
                path,
                remote_version,
            } => FuseAction::EnsurePlaceholder {
                path: path.clone(),
                remote_version: remote_version.clone(),
            },
            SyncOperation::Hydrate {
                path,
                remote_version,
            } => FuseAction::HydrateOnRead {
                path: path.clone(),
                remote_version: remote_version.clone(),
            },
            SyncOperation::Upload {
                path,
                local_version,
            } => FuseAction::UploadOnFlush {
                path: path.clone(),
                local_version: local_version.clone(),
            },
            SyncOperation::Conflict {
                path,
                local_version,
                remote_version,
            } => FuseAction::MarkConflict {
                path: path.clone(),
                local_version: local_version.clone(),
                remote_version: remote_version.clone(),
            },
        };
        actions.push(mapped);
    }

    FuseActionPlan { actions }
}

pub mod runtime {
    use super::FuseActionPlan;
    use crate::FuseAction;
    use anyhow::{Context, Result, anyhow};
    use fuser::consts::FOPEN_DIRECT_IO;
    use fuser::{
        FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData,
        ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
    };
    use libc::{EACCES, EBADF, EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY};
    use std::collections::{BTreeMap, HashMap};
    use std::ffi::OsStr;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::Receiver;
    use std::time::{Duration, SystemTime};

    const ROOT_INODE: u64 = 1;
    const TTL: Duration = Duration::from_secs(1);

    #[derive(Debug, Clone)]
    pub struct FuseMountConfig {
        pub mountpoint: PathBuf,
        pub fs_name: String,
        pub allow_other: bool,
    }

    impl FuseMountConfig {
        pub fn new(mountpoint: impl Into<PathBuf>, fs_name: impl Into<String>) -> Self {
            Self {
                mountpoint: mountpoint.into(),
                fs_name: fs_name.into(),
                allow_other: false,
            }
        }

        fn mount_options(&self) -> Vec<MountOption> {
            let mut options = vec![
                MountOption::FSName(self.fs_name.clone()),
                MountOption::NoExec,
                MountOption::DefaultPermissions,
            ];

            if self.allow_other {
                options.push(MountOption::AllowOther);
            }

            options
        }
    }

    pub trait Hydrator: Send + Sync + 'static {
        fn hydrate(&self, path: &str, remote_version: &str) -> Result<Vec<u8>>;
    }

    pub trait Uploader: Send + Sync + 'static {
        fn upload_reader(
            &self,
            path: &str,
            reader: &mut dyn std::io::Read,
            length: u64,
        ) -> Result<Option<String>>;
    }

    #[derive(Debug, Default, Clone)]
    pub struct DemoHydrator;

    impl Hydrator for DemoHydrator {
        fn hydrate(&self, path: &str, remote_version: &str) -> Result<Vec<u8>> {
            Ok(
                format!("ironmesh placeholder hydrated: path={path} version={remote_version}\n")
                    .into_bytes(),
            )
        }
    }

    #[derive(Debug, Default, Clone)]
    pub struct DemoUploader;

    impl Uploader for DemoUploader {
        fn upload_reader(
            &self,
            _path: &str,
            _reader: &mut dyn std::io::Read,
            _length: u64,
        ) -> Result<Option<String>> {
            Ok(Some("demo-upload".to_string()))
        }
    }

    #[derive(Debug, Clone)]
    struct FsNode {
        inode: u64,
        name: String,
        parent_inode: u64,
        kind: FileType,
        size: u64,
        modified_at: SystemTime,
        children: BTreeMap<String, u64>,
        data: Vec<u8>,
        placeholder_version: Option<String>,
    }

    impl FsNode {
        fn directory(inode: u64, name: String, parent_inode: u64) -> Self {
            Self {
                inode,
                name,
                parent_inode,
                kind: FileType::Directory,
                size: 0,
                modified_at: SystemTime::now(),
                children: BTreeMap::new(),
                data: Vec::new(),
                placeholder_version: None,
            }
        }

        fn placeholder_file(
            inode: u64,
            name: String,
            parent_inode: u64,
            remote_version: String,
        ) -> Self {
            Self {
                inode,
                name,
                parent_inode,
                kind: FileType::RegularFile,
                size: 0,
                modified_at: SystemTime::now(),
                children: BTreeMap::new(),
                data: Vec::new(),
                placeholder_version: Some(remote_version),
            }
        }

        fn regular_file(inode: u64, name: String, parent_inode: u64) -> Self {
            Self {
                inode,
                name,
                parent_inode,
                kind: FileType::RegularFile,
                size: 0,
                modified_at: SystemTime::now(),
                children: BTreeMap::new(),
                data: Vec::new(),
                placeholder_version: None,
            }
        }

        fn attr(&self, uid: u32, gid: u32) -> FileAttr {
            let (perm, nlink) = match self.kind {
                FileType::Directory => (0o755, 2),
                _ => (0o644, 1),
            };

            let blocks = if self.kind == FileType::Directory {
                1
            } else {
                self.size.div_ceil(512).max(1)
            };

            FileAttr {
                ino: self.inode,
                size: self.size,
                blocks,
                atime: self.modified_at,
                mtime: self.modified_at,
                ctime: self.modified_at,
                crtime: self.modified_at,
                kind: self.kind,
                perm,
                nlink,
                uid,
                gid,
                rdev: 0,
                blksize: 4096,
                flags: 0,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct OpenHandle {
        inode: u64,
        write_access: bool,
        dirty: bool,
    }

    pub struct IronmeshFuseFs {
        nodes: HashMap<u64, FsNode>,
        hydrator: Box<dyn Hydrator>,
        uploader: Box<dyn Uploader>,
        refresh_rx: Option<Receiver<FuseActionPlan>>,
        open_handles: HashMap<u64, OpenHandle>,
        next_handle: u64,
        uid: u32,
        gid: u32,
    }

    impl IronmeshFuseFs {
        pub fn from_action_plan(
            action_plan: &FuseActionPlan,
            hydrator: Box<dyn Hydrator>,
            uploader: Box<dyn Uploader>,
            refresh_rx: Option<Receiver<FuseActionPlan>>,
        ) -> Self {
            // Safe: libc getters have no preconditions.
            let uid = unsafe { libc::geteuid() };
            // Safe: libc getters have no preconditions.
            let gid = unsafe { libc::getegid() };

            let mut fs = Self {
                nodes: HashMap::new(),
                hydrator,
                uploader,
                refresh_rx,
                open_handles: HashMap::new(),
                next_handle: 1,
                uid,
                gid,
            };
            fs.nodes.insert(
                ROOT_INODE,
                FsNode::directory(ROOT_INODE, String::new(), ROOT_INODE),
            );

            for action in &action_plan.actions {
                match action {
                    FuseAction::EnsureDirectory { path } => {
                        fs.ensure_directory(path);
                    }
                    FuseAction::EnsurePlaceholder {
                        path,
                        remote_version,
                    }
                    | FuseAction::HydrateOnRead {
                        path,
                        remote_version,
                    } => {
                        fs.ensure_placeholder_file(path, remote_version);
                    }
                    FuseAction::UploadOnFlush { .. } | FuseAction::MarkConflict { .. } => {}
                }
            }

            fs
        }

        fn ensure_directory(&mut self, relative_path: &str) -> u64 {
            let mut current_inode = ROOT_INODE;

            for segment in relative_path
                .split('/')
                .filter(|segment| !segment.is_empty())
            {
                let existing = self
                    .nodes
                    .get(&current_inode)
                    .and_then(|node| node.children.get(segment).copied());

                if let Some(inode) = existing {
                    current_inode = inode;
                    continue;
                }

                let next_inode = self.next_inode();
                let directory = FsNode::directory(next_inode, segment.to_string(), current_inode);
                self.nodes.insert(next_inode, directory);
                if let Some(parent) = self.nodes.get_mut(&current_inode) {
                    parent.children.insert(segment.to_string(), next_inode);
                }
                current_inode = next_inode;
            }

            current_inode
        }

        fn ensure_placeholder_file(&mut self, relative_path: &str, remote_version: &str) {
            let mut segments: Vec<&str> = relative_path
                .split('/')
                .filter(|segment| !segment.is_empty())
                .collect();
            if segments.is_empty() {
                return;
            }

            let file_name = segments.pop().unwrap_or_default();
            let parent_path = segments.join("/");
            let parent_inode = self.ensure_directory(&parent_path);

            let existing = self
                .nodes
                .get(&parent_inode)
                .and_then(|node| node.children.get(file_name).copied());

            if let Some(inode) = existing {
                if let Some(file) = self.nodes.get_mut(&inode) {
                    file.placeholder_version = Some(remote_version.to_string());
                    file.data.clear();
                    file.size = 0;
                }
                return;
            }

            let inode = self.next_inode();
            let file = FsNode::placeholder_file(
                inode,
                file_name.to_string(),
                parent_inode,
                remote_version.to_string(),
            );

            self.nodes.insert(inode, file);
            if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                parent.children.insert(file_name.to_string(), inode);
            }
        }

        fn inode_has_active_writer(&self, inode: u64) -> bool {
            self.open_handles
                .values()
                .any(|handle| handle.inode == inode && handle.write_access)
        }

        fn ensure_placeholder_file_for_refresh(
            &mut self,
            relative_path: &str,
            remote_version: &str,
        ) {
            let mut segments: Vec<&str> = relative_path
                .split('/')
                .filter(|segment| !segment.is_empty())
                .collect();
            if segments.is_empty() {
                return;
            }

            let file_name = segments.pop().unwrap_or_default();
            let parent_path = segments.join("/");
            let parent_inode = self.ensure_directory(&parent_path);

            let existing = self
                .nodes
                .get(&parent_inode)
                .and_then(|node| node.children.get(file_name).copied());

            if let Some(inode) = existing {
                if self.inode_has_active_writer(inode) {
                    return;
                }

                let Some(file) = self.nodes.get_mut(&inode) else {
                    return;
                };
                if file.kind != FileType::RegularFile {
                    return;
                }

                let already_placeholder = file.placeholder_version.as_deref()
                    == Some(remote_version)
                    && file.data.is_empty()
                    && file.size == 0;
                if already_placeholder {
                    return;
                }

                file.placeholder_version = Some(remote_version.to_string());
                file.data.clear();
                file.size = 0;
                file.modified_at = SystemTime::now();
                return;
            }

            let inode = self.next_inode();
            let file = FsNode::placeholder_file(
                inode,
                file_name.to_string(),
                parent_inode,
                remote_version.to_string(),
            );
            self.nodes.insert(inode, file);
            if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                parent.children.insert(file_name.to_string(), inode);
            }
        }

        fn apply_remote_action_plan_additive(&mut self, action_plan: &FuseActionPlan) {
            for action in &action_plan.actions {
                match action {
                    FuseAction::EnsureDirectory { path } => {
                        self.ensure_directory(path);
                    }
                    FuseAction::EnsurePlaceholder {
                        path,
                        remote_version,
                    }
                    | FuseAction::HydrateOnRead {
                        path,
                        remote_version,
                    } => {
                        self.ensure_placeholder_file_for_refresh(path, remote_version);
                    }
                    FuseAction::UploadOnFlush { .. } | FuseAction::MarkConflict { .. } => {}
                }
            }
        }

        fn drain_remote_updates(&mut self) {
            let mut pending = Vec::new();
            if let Some(refresh_rx) = self.refresh_rx.as_ref() {
                while let Ok(action_plan) = refresh_rx.try_recv() {
                    pending.push(action_plan);
                }
            }

            for action_plan in pending {
                self.apply_remote_action_plan_additive(&action_plan);
            }
        }

        fn next_inode(&self) -> u64 {
            self.nodes.keys().max().copied().unwrap_or(ROOT_INODE) + 1
        }

        fn hydrate_if_needed(&mut self, inode: u64) -> Result<()> {
            let (path, version) = {
                let node = self
                    .nodes
                    .get(&inode)
                    .ok_or_else(|| anyhow!("inode not found"))?;
                if node.kind != FileType::RegularFile {
                    return Ok(());
                }
                let Some(version) = node.placeholder_version.clone() else {
                    return Ok(());
                };
                (self.resolve_full_path(inode), version)
            };

            let data = self.hydrator.hydrate(&path, &version)?;
            let file = self
                .nodes
                .get_mut(&inode)
                .ok_or_else(|| anyhow!("inode disappeared during hydration"))?;
            file.data = data;
            file.size = file.data.len() as u64;
            file.modified_at = SystemTime::now();
            file.placeholder_version = None;

            Ok(())
        }

        fn truncate_if_needed(&mut self, inode: u64, size: u64) -> Result<bool> {
            let node = self
                .nodes
                .get_mut(&inode)
                .ok_or_else(|| anyhow!("inode not found"))?;
            if node.kind != FileType::RegularFile {
                return Err(anyhow!("inode {inode} is not a regular file"));
            }

            let target_size = usize::try_from(size).context("file size overflow")?;
            let changed = node.data.len() != target_size;
            if changed {
                node.data.resize(target_size, 0);
                node.size = size;
                node.modified_at = SystemTime::now();
                node.placeholder_version = None;
            }
            Ok(changed)
        }

        fn alloc_open_handle(&mut self, inode: u64, write_access: bool) -> u64 {
            let fh = self.next_handle;
            self.next_handle = self.next_handle.saturating_add(1);
            self.open_handles.insert(
                fh,
                OpenHandle {
                    inode,
                    write_access,
                    dirty: false,
                },
            );
            fh
        }

        fn write_requested(flags: i32) -> bool {
            let write_flags =
                libc::O_WRONLY | libc::O_RDWR | libc::O_APPEND | libc::O_TRUNC | libc::O_CREAT;
            (flags & write_flags) != 0
        }

        fn upload_inode(&self, inode: u64) -> Result<()> {
            let node = self
                .nodes
                .get(&inode)
                .ok_or_else(|| anyhow!("inode not found"))?;
            if node.kind != FileType::RegularFile {
                return Err(anyhow!("inode {inode} is not a regular file"));
            }

            let path = self.resolve_full_path(inode);
            let mut reader = Cursor::new(node.data.clone());
            self.uploader
                .upload_reader(&path, &mut reader, node.size)
                .with_context(|| format!("failed to upload path {path}"))?;
            Ok(())
        }

        fn flush_handle(&mut self, ino: u64, fh: u64) -> Result<()> {
            let Some(handle) = self.open_handles.get(&fh).copied() else {
                return Err(anyhow!("unknown file handle"));
            };
            if handle.inode != ino {
                return Err(anyhow!("inode/file-handle mismatch"));
            }

            if handle.write_access && handle.dirty {
                self.upload_inode(ino)?;
                if let Some(handle) = self.open_handles.get_mut(&fh) {
                    handle.dirty = false;
                }
            }

            Ok(())
        }

        fn release_handle(&mut self, ino: u64, fh: u64) -> Result<()> {
            let Some(handle) = self.open_handles.remove(&fh) else {
                return Err(anyhow!("unknown file handle"));
            };
            if handle.inode != ino {
                return Err(anyhow!("inode/file-handle mismatch"));
            }

            if handle.write_access && handle.dirty {
                self.upload_inode(ino)?;
            }
            Ok(())
        }

        fn resolve_full_path(&self, inode: u64) -> String {
            if inode == ROOT_INODE {
                return String::new();
            }

            let mut segments = Vec::new();
            let mut current = inode;
            while current != ROOT_INODE {
                if let Some(node) = self.nodes.get(&current) {
                    segments.push(node.name.clone());
                    current = node.parent_inode;
                } else {
                    break;
                }
            }
            segments.reverse();
            segments.join("/")
        }
    }

    impl Filesystem for IronmeshFuseFs {
        fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
            self.drain_remote_updates();

            let Some(parent_node) = self.nodes.get(&parent) else {
                reply.error(ENOENT);
                return;
            };
            let Some(name) = name.to_str() else {
                reply.error(ENOENT);
                return;
            };
            let Some(child_inode) = parent_node.children.get(name).copied() else {
                reply.error(ENOENT);
                return;
            };
            let Some(child) = self.nodes.get(&child_inode) else {
                reply.error(ENOENT);
                return;
            };
            reply.entry(&TTL, &child.attr(self.uid, self.gid), 0);
        }

        fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
            self.drain_remote_updates();

            if let Err(_error) = self.hydrate_if_needed(ino) {
                reply.error(EIO);
                return;
            }

            let Some(node) = self.nodes.get(&ino) else {
                reply.error(ENOENT);
                return;
            };
            reply.attr(&TTL, &node.attr(self.uid, self.gid));
        }

        fn readdir(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            offset: i64,
            mut reply: ReplyDirectory,
        ) {
            self.drain_remote_updates();

            let Some(node) = self.nodes.get(&ino) else {
                reply.error(ENOENT);
                return;
            };

            if node.kind != FileType::Directory {
                reply.error(ENOENT);
                return;
            }

            let mut entries: Vec<(u64, FileType, String)> = Vec::new();
            entries.push((ino, FileType::Directory, ".".to_string()));
            entries.push((node.parent_inode, FileType::Directory, "..".to_string()));

            for (name, child_inode) in &node.children {
                if let Some(child) = self.nodes.get(child_inode) {
                    entries.push((*child_inode, child.kind, name.clone()));
                }
            }

            for (index, (entry_ino, kind, name)) in
                entries.into_iter().enumerate().skip(offset as usize)
            {
                let full = reply.add(entry_ino, (index + 1) as i64, kind, name);
                if full {
                    break;
                }
            }

            reply.ok();
        }

        fn mkdir(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            reply: ReplyEntry,
        ) {
            self.drain_remote_updates();

            let Some(parent_node) = self.nodes.get(&parent) else {
                reply.error(ENOENT);
                return;
            };
            if parent_node.kind != FileType::Directory {
                reply.error(ENOTDIR);
                return;
            }

            let Some(name) = name.to_str() else {
                reply.error(EINVAL);
                return;
            };
            if name.is_empty() || name.contains('/') {
                reply.error(EINVAL);
                return;
            }
            if parent_node.children.contains_key(name) {
                reply.error(EEXIST);
                return;
            }

            let inode = self.next_inode();
            self.nodes
                .insert(inode, FsNode::directory(inode, name.to_string(), parent));

            if let Some(parent_node) = self.nodes.get_mut(&parent) {
                parent_node.children.insert(name.to_string(), inode);
            }

            let Some(created) = self.nodes.get(&inode) else {
                reply.error(EIO);
                return;
            };
            reply.entry(&TTL, &created.attr(self.uid, self.gid), 0);
        }

        fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            self.drain_remote_updates();

            let Some(name) = name.to_str() else {
                reply.error(EINVAL);
                return;
            };

            let Some(parent_node) = self.nodes.get(&parent) else {
                reply.error(ENOENT);
                return;
            };
            if parent_node.kind != FileType::Directory {
                reply.error(ENOTDIR);
                return;
            }

            let Some(child_inode) = parent_node.children.get(name).copied() else {
                reply.error(ENOENT);
                return;
            };

            let Some(child_node) = self.nodes.get(&child_inode) else {
                reply.error(ENOENT);
                return;
            };
            if child_node.kind == FileType::Directory {
                reply.error(EISDIR);
                return;
            }

            if let Some(parent_node) = self.nodes.get_mut(&parent) {
                parent_node.children.remove(name);
            }
            self.nodes.remove(&child_inode);
            self.open_handles
                .retain(|_, handle| handle.inode != child_inode);
            reply.ok();
        }

        fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            self.drain_remote_updates();

            let Some(name) = name.to_str() else {
                reply.error(EINVAL);
                return;
            };
            if name == "." || name == ".." {
                reply.error(EINVAL);
                return;
            }

            let Some(parent_node) = self.nodes.get(&parent) else {
                reply.error(ENOENT);
                return;
            };
            if parent_node.kind != FileType::Directory {
                reply.error(ENOTDIR);
                return;
            }

            let Some(child_inode) = parent_node.children.get(name).copied() else {
                reply.error(ENOENT);
                return;
            };

            let Some(child_node) = self.nodes.get(&child_inode) else {
                reply.error(ENOENT);
                return;
            };
            if child_node.kind != FileType::Directory {
                reply.error(ENOTDIR);
                return;
            }
            if !child_node.children.is_empty() {
                reply.error(ENOTEMPTY);
                return;
            }

            if let Some(parent_node) = self.nodes.get_mut(&parent) {
                parent_node.children.remove(name);
            }
            self.nodes.remove(&child_inode);
            reply.ok();
        }

        fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
            self.drain_remote_updates();

            let Some(node) = self.nodes.get(&ino) else {
                reply.error(ENOENT);
                return;
            };

            if node.kind != FileType::RegularFile {
                reply.error(ENOENT);
                return;
            }

            let write_access = Self::write_requested(flags);
            if write_access && (flags & libc::O_TRUNC) != 0 {
                if let Err(_error) = self.truncate_if_needed(ino, 0) {
                    reply.error(EIO);
                    return;
                }
            } else if let Err(_error) = self.hydrate_if_needed(ino) {
                reply.error(EIO);
                return;
            }

            let fh = self.alloc_open_handle(ino, write_access);
            reply.opened(fh, FOPEN_DIRECT_IO);
        }

        fn create(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            _mode: u32,
            _umask: u32,
            flags: i32,
            reply: ReplyCreate,
        ) {
            self.drain_remote_updates();

            let Some(parent_node) = self.nodes.get(&parent) else {
                reply.error(ENOENT);
                return;
            };
            if parent_node.kind != FileType::Directory {
                reply.error(ENOENT);
                return;
            }

            let Some(name) = name.to_str() else {
                reply.error(EINVAL);
                return;
            };
            if name.is_empty() || name.contains('/') {
                reply.error(EINVAL);
                return;
            }
            if parent_node.children.contains_key(name) {
                reply.error(EEXIST);
                return;
            }

            let inode = self.next_inode();
            self.nodes
                .insert(inode, FsNode::regular_file(inode, name.to_string(), parent));

            if let Some(parent_node) = self.nodes.get_mut(&parent) {
                parent_node.children.insert(name.to_string(), inode);
            }

            let fh = self.alloc_open_handle(inode, Self::write_requested(flags));
            let Some(created) = self.nodes.get(&inode) else {
                reply.error(EIO);
                return;
            };
            reply.created(
                &TTL,
                &created.attr(self.uid, self.gid),
                0,
                fh,
                FOPEN_DIRECT_IO,
            );
        }

        fn read(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            offset: i64,
            size: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyData,
        ) {
            self.drain_remote_updates();

            if let Err(_error) = self.hydrate_if_needed(ino) {
                reply.error(EIO);
                return;
            }

            let Some(node) = self.nodes.get(&ino) else {
                reply.error(ENOENT);
                return;
            };

            if node.kind != FileType::RegularFile {
                reply.error(ENOENT);
                return;
            }

            let data = &node.data;
            let start = offset.max(0) as usize;
            if start >= data.len() {
                reply.data(&[]);
                return;
            }
            let end = (start + size as usize).min(data.len());
            reply.data(&data[start..end]);
        }

        fn write(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            fh: u64,
            offset: i64,
            data: &[u8],
            _write_flags: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyWrite,
        ) {
            self.drain_remote_updates();

            let Some(handle) = self.open_handles.get(&fh).copied() else {
                reply.error(EBADF);
                return;
            };
            if handle.inode != ino {
                reply.error(EBADF);
                return;
            }
            if !handle.write_access {
                reply.error(EACCES);
                return;
            }

            let Ok(start) = usize::try_from(offset) else {
                reply.error(EIO);
                return;
            };
            let Some(end) = start.checked_add(data.len()) else {
                reply.error(EIO);
                return;
            };

            let Some(file) = self.nodes.get_mut(&ino) else {
                reply.error(ENOENT);
                return;
            };
            if file.kind != FileType::RegularFile {
                reply.error(ENOENT);
                return;
            }

            if file.data.len() < start {
                file.data.resize(start, 0);
            }
            if file.data.len() < end {
                file.data.resize(end, 0);
            }
            file.data[start..end].copy_from_slice(data);
            file.size = file.data.len() as u64;
            file.modified_at = SystemTime::now();
            file.placeholder_version = None;

            if let Some(handle) = self.open_handles.get_mut(&fh) {
                handle.dirty = true;
            }

            let Ok(written) = u32::try_from(data.len()) else {
                reply.error(EIO);
                return;
            };
            reply.written(written);
        }

        fn setattr(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _mode: Option<u32>,
            _uid: Option<u32>,
            _gid: Option<u32>,
            size: Option<u64>,
            _atime: Option<TimeOrNow>,
            _mtime: Option<TimeOrNow>,
            _ctime: Option<SystemTime>,
            fh: Option<u64>,
            _crtime: Option<SystemTime>,
            _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>,
            _flags: Option<u32>,
            reply: ReplyAttr,
        ) {
            self.drain_remote_updates();

            if let Some(size) = size {
                if let Err(_error) = self.hydrate_if_needed(ino) {
                    reply.error(EIO);
                    return;
                }

                let changed = match self.truncate_if_needed(ino, size) {
                    Ok(changed) => changed,
                    Err(_error) => {
                        reply.error(EIO);
                        return;
                    }
                };

                if changed
                    && let Some(fh) = fh
                    && let Some(handle) = self.open_handles.get_mut(&fh)
                    && handle.write_access
                {
                    handle.dirty = true;
                }
            }

            let Some(node) = self.nodes.get(&ino) else {
                reply.error(ENOENT);
                return;
            };
            reply.attr(&TTL, &node.attr(self.uid, self.gid));
        }

        fn flush(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            fh: u64,
            _lock_owner: u64,
            reply: ReplyEmpty,
        ) {
            self.drain_remote_updates();

            match self.flush_handle(ino, fh) {
                Ok(()) => reply.ok(),
                Err(_error) => reply.error(EIO),
            }
        }

        fn release(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            fh: u64,
            _flags: i32,
            _lock_owner: Option<u64>,
            _flush: bool,
            reply: ReplyEmpty,
        ) {
            self.drain_remote_updates();

            match self.release_handle(ino, fh) {
                Ok(()) => reply.ok(),
                Err(_error) => reply.error(EIO),
            }
        }
    }

    pub fn mount_action_plan(
        config: &FuseMountConfig,
        action_plan: FuseActionPlan,
        hydrator: Box<dyn Hydrator>,
        uploader: Box<dyn Uploader>,
    ) -> Result<()> {
        if !Path::new(&config.mountpoint).exists() {
            return Err(anyhow!(
                "mountpoint does not exist: {}",
                config.mountpoint.display()
            ));
        }

        let fs = IronmeshFuseFs::from_action_plan(&action_plan, hydrator, uploader, None);
        fuser::mount2(fs, &config.mountpoint, &config.mount_options())?;
        Ok(())
    }

    pub fn mount_action_plan_until_shutdown(
        config: &FuseMountConfig,
        action_plan: FuseActionPlan,
        hydrator: Box<dyn Hydrator>,
        uploader: Box<dyn Uploader>,
    ) -> Result<()> {
        mount_action_plan_until_shutdown_with_updates(config, action_plan, hydrator, uploader, None)
    }

    pub fn mount_action_plan_until_shutdown_with_updates(
        config: &FuseMountConfig,
        action_plan: FuseActionPlan,
        hydrator: Box<dyn Hydrator>,
        uploader: Box<dyn Uploader>,
        refresh_rx: Option<Receiver<FuseActionPlan>>,
    ) -> Result<()> {
        if !Path::new(&config.mountpoint).exists() {
            return Err(anyhow!(
                "mountpoint does not exist: {}",
                config.mountpoint.display()
            ));
        }

        let fs = IronmeshFuseFs::from_action_plan(&action_plan, hydrator, uploader, refresh_rx);
        let session = fuser::spawn_mount2(fs, &config.mountpoint, &config.mount_options())
            .with_context(|| {
                format!(
                    "failed to mount FUSE filesystem at {}",
                    config.mountpoint.display()
                )
            })?;

        let (tx, rx) = std::sync::mpsc::channel::<()>();
        ctrlc::set_handler(move || {
            let _ = tx.send(());
        })
        .context("failed to install Ctrl+C handler")?;

        rx.recv()
            .context("failed waiting for Ctrl+C shutdown signal")?;

        drop(session);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync_core::{HydrationState, LocalEntry, NamespaceEntry, PinState};

    #[test]
    fn adapter_maps_remote_only_file_to_placeholder_action() {
        let adapter = LinuxFuseAdapter::new("ironmesh");
        let snapshot = SyncSnapshot {
            local: vec![],
            remote: vec![NamespaceEntry::file("docs/readme.md", "v1", "h1")],
        };

        let plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.actions,
            vec![FuseAction::EnsurePlaceholder {
                path: "docs/readme.md".to_string(),
                remote_version: "v1".to_string(),
            }],
        );
    }

    #[test]
    fn adapter_maps_local_only_file_to_upload_on_flush() {
        let adapter = LinuxFuseAdapter::new("ironmesh");
        let snapshot = SyncSnapshot {
            local: vec![LocalEntry::new(
                NamespaceEntry::file("notes/task.txt", "v-local", "h-local"),
                PinState::Pinned,
                HydrationState::Hydrated,
            )],
            remote: vec![],
        };

        let plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.actions,
            vec![FuseAction::UploadOnFlush {
                path: "notes/task.txt".to_string(),
                local_version: Some("v-local".to_string()),
            }],
        );
    }

    #[test]
    fn adapter_maps_divergence_to_conflict_action() {
        let adapter = LinuxFuseAdapter::new("ironmesh");
        let snapshot = SyncSnapshot {
            local: vec![LocalEntry::new(
                NamespaceEntry::file("report.csv", "v-local", "h1"),
                PinState::Pinned,
                HydrationState::Hydrated,
            )],
            remote: vec![NamespaceEntry::file("report.csv", "v-remote", "h2")],
        };

        let plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.actions,
            vec![FuseAction::MarkConflict {
                path: "report.csv".to_string(),
                local_version: Some("v-local".to_string()),
                remote_version: Some("v-remote".to_string()),
            }],
        );
    }
}
