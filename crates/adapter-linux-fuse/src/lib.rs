#![cfg(not(windows))]

pub mod client_rights_edge;
pub mod gnome;
pub mod mount_main;

use std::collections::HashMap;

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
        let remote_sizes_by_path = snapshot
            .remote
            .iter()
            .filter_map(|entry| entry.size_bytes.map(|size| (entry.path.clone(), size)))
            .collect::<HashMap<_, _>>();
        map_sync_plan_to_fuse_actions(&sync_plan, &remote_sizes_by_path)
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
        remote_content_hash: String,
        remote_size: Option<u64>,
    },
    HydrateOnRead {
        path: String,
        remote_version: String,
        remote_content_hash: String,
        remote_size: Option<u64>,
    },
    UploadOnFlush {
        path: String,
        local_version: Option<String>,
    },
    MarkConflict {
        path: String,
        local_version: Option<String>,
        remote_version: Option<String>,
        remote_content_hash: Option<String>,
        remote_size: Option<u64>,
    },
    RemovePath {
        path: String,
    },
}

pub fn map_sync_plan_to_fuse_actions(
    sync_plan: &SyncPlan,
    remote_sizes_by_path: &HashMap<String, u64>,
) -> FuseActionPlan {
    let mut actions = Vec::with_capacity(sync_plan.operations.len());

    for operation in &sync_plan.operations {
        let mapped = match operation {
            SyncOperation::CreateDirectory { path } => {
                FuseAction::EnsureDirectory { path: path.clone() }
            }
            SyncOperation::EnsurePlaceholder {
                path,
                remote_version,
                remote_content_hash,
            } => FuseAction::EnsurePlaceholder {
                path: path.clone(),
                remote_version: remote_version.clone(),
                remote_content_hash: remote_content_hash.clone(),
                remote_size: remote_sizes_by_path.get(path).copied(),
            },
            SyncOperation::Hydrate {
                path,
                remote_version,
                remote_content_hash,
            } => FuseAction::HydrateOnRead {
                path: path.clone(),
                remote_version: remote_version.clone(),
                remote_content_hash: remote_content_hash.clone(),
                remote_size: remote_sizes_by_path.get(path).copied(),
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
                remote_content_hash,
            } => FuseAction::MarkConflict {
                path: path.clone(),
                local_version: local_version.clone(),
                remote_version: remote_version.clone(),
                remote_content_hash: remote_content_hash.clone(),
                remote_size: remote_sizes_by_path.get(path).copied(),
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
        ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, ReplyXattr, Request,
        TimeOrNow,
    };
    use libc::{
        EACCES, EBADF, EEXIST, EINVAL, EIO, EISDIR, ENODATA, ENOENT, ENOTDIR, ENOTEMPTY, EPERM,
        ERANGE,
    };
    use nix::unistd::{Gid, Uid};
    use std::collections::{BTreeMap, HashMap};
    use std::ffi::OsStr;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::Receiver;
    use std::time::{Duration, Instant, SystemTime};

    const ROOT_INODE: u64 = 1;
    const TTL: Duration = Duration::from_secs(1);
    const CONFLICT_ROOT_NAME: &str = ".ironmesh-conflicts";
    const CONFLICT_REMOTE_ROOT: &str = ".ironmesh-conflicts/remote";
    const CONFLICT_REASON_DIVERGENT_VERSIONS: &str = "divergent_versions";
    const XATTR_STATE: &str = "user.ironmesh.state";
    const XATTR_LOCAL_VERSION: &str = "user.ironmesh.local_version";
    const XATTR_REMOTE_VERSION: &str = "user.ironmesh.remote_version";
    const XATTR_CONFLICT_REASON: &str = "user.ironmesh.conflict_reason";
    const XATTR_CONFLICT_COPY: &str = "user.ironmesh.conflict_copy";
    const XATTR_SOURCE_PATH: &str = "user.ironmesh.source_path";

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
        fn hydrate(
            &self,
            path: &str,
            remote_version: &str,
            remote_content_hash: &str,
        ) -> Result<Vec<u8>>;

        fn hydrate_range(
            &self,
            path: &str,
            remote_version: &str,
            remote_content_hash: &str,
            offset: u64,
            length: u64,
        ) -> Result<Vec<u8>> {
            if length == 0 {
                return Ok(Vec::new());
            }

            let payload = self.hydrate(path, remote_version, remote_content_hash)?;
            let start = offset.min(payload.len() as u64) as usize;
            let end = offset.saturating_add(length).min(payload.len() as u64) as usize;
            Ok(payload[start..end].to_vec())
        }
    }

    pub trait Uploader: Send + Sync + 'static {
        fn upload_reader(
            &self,
            path: &str,
            base_remote_version: Option<&str>,
            reader: &mut dyn std::io::Read,
            length: u64,
        ) -> Result<Option<String>>;

        fn rename_path(
            &self,
            from_path: &str,
            to_path: &str,
            overwrite: bool,
            base_remote_version: Option<&str>,
        ) -> Result<()>;

        fn delete_path(&self, path: &str, base_remote_version: Option<&str>) -> Result<()>;
    }

    #[derive(Debug, Default, Clone)]
    pub struct DemoHydrator;

    impl Hydrator for DemoHydrator {
        fn hydrate(
            &self,
            path: &str,
            remote_version: &str,
            _remote_content_hash: &str,
        ) -> Result<Vec<u8>> {
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
            _base_remote_version: Option<&str>,
            _reader: &mut dyn std::io::Read,
            _length: u64,
        ) -> Result<Option<String>> {
            Ok(Some("demo-upload".to_string()))
        }

        fn rename_path(
            &self,
            _from_path: &str,
            _to_path: &str,
            _overwrite: bool,
            _base_remote_version: Option<&str>,
        ) -> Result<()> {
            Ok(())
        }

        fn delete_path(&self, _path: &str, _base_remote_version: Option<&str>) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum NodeNamespace {
        User,
        ConflictInternal,
    }

    #[derive(Debug, Clone, Default)]
    struct NodeSyncMetadata {
        local_version: Option<String>,
        remote_version: Option<String>,
        conflict_reason: Option<String>,
        conflict_copy_path: Option<String>,
        source_path: Option<String>,
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
        placeholder_content_hash: Option<String>,
        read_only: bool,
        namespace: NodeNamespace,
        backing_path: Option<String>,
        sync_metadata: NodeSyncMetadata,
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
                placeholder_content_hash: None,
                read_only: false,
                namespace: NodeNamespace::User,
                backing_path: None,
                sync_metadata: NodeSyncMetadata::default(),
            }
        }

        fn placeholder_file(
            inode: u64,
            name: String,
            parent_inode: u64,
            remote_version: String,
            remote_content_hash: String,
            size: u64,
        ) -> Self {
            let sync_metadata = NodeSyncMetadata {
                remote_version: Some(remote_version.clone()),
                ..NodeSyncMetadata::default()
            };
            Self {
                inode,
                name,
                parent_inode,
                kind: FileType::RegularFile,
                size,
                modified_at: SystemTime::now(),
                children: BTreeMap::new(),
                data: Vec::new(),
                placeholder_version: Some(remote_version),
                placeholder_content_hash: Some(remote_content_hash),
                read_only: false,
                namespace: NodeNamespace::User,
                backing_path: None,
                sync_metadata,
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
                placeholder_content_hash: None,
                read_only: false,
                namespace: NodeNamespace::User,
                backing_path: None,
                sync_metadata: NodeSyncMetadata::default(),
            }
        }

        fn attr(&self, uid: u32, gid: u32) -> FileAttr {
            let (perm, nlink) = match self.kind {
                FileType::Directory => (if self.read_only { 0o555 } else { 0o755 }, 2),
                _ => (if self.read_only { 0o444 } else { 0o644 }, 1),
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

        fn content_path(&self, resolved_path: String) -> String {
            self.backing_path.clone().unwrap_or(resolved_path)
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct OpenHandle {
        inode: u64,
        write_access: bool,
        dirty: bool,
        upload_enqueued: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ReplayAction {
        EnsureDirectory {
            path: String,
        },
        UpsertFile {
            path: String,
            data: Vec<u8>,
        },
        DeletePath {
            path: String,
            directory: bool,
        },
        RenamePath {
            from_path: String,
            to_path: String,
            overwrite: bool,
        },
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
            let uid = Uid::effective().as_raw();
            let gid = Gid::effective().as_raw();

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
                        remote_content_hash,
                        remote_size,
                    }
                    | FuseAction::HydrateOnRead {
                        path,
                        remote_version,
                        remote_content_hash,
                        remote_size,
                    } => {
                        fs.clear_conflict_state_for_path(path);
                        fs.ensure_placeholder_file(
                            path,
                            remote_version,
                            remote_content_hash,
                            *remote_size,
                        );
                    }
                    FuseAction::MarkConflict {
                        path,
                        local_version,
                        remote_version,
                        remote_content_hash,
                        remote_size,
                    } => {
                        fs.mark_conflict_path(
                            path,
                            local_version.clone(),
                            remote_version.clone(),
                            remote_content_hash.clone(),
                            *remote_size,
                        );
                    }
                    FuseAction::UploadOnFlush { .. } | FuseAction::RemovePath { .. } => {}
                }
            }

            fs
        }

        fn is_reserved_root_child(name: &str) -> bool {
            name == CONFLICT_ROOT_NAME
        }

        fn conflict_copy_path(relative_path: &str) -> String {
            format!("{CONFLICT_REMOTE_ROOT}/{relative_path}")
        }

        fn ensure_directory_in_namespace(
            &mut self,
            relative_path: &str,
            namespace: NodeNamespace,
            read_only: bool,
        ) -> u64 {
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
                    if let Some(node) = self.nodes.get_mut(&inode)
                        && node.kind == FileType::Directory
                    {
                        node.namespace = namespace.clone();
                        node.read_only |= read_only;
                    }
                    current_inode = inode;
                    continue;
                }

                let next_inode = self.next_inode();
                let mut directory =
                    FsNode::directory(next_inode, segment.to_string(), current_inode);
                directory.namespace = namespace.clone();
                directory.read_only = read_only;
                self.nodes.insert(next_inode, directory);
                if let Some(parent) = self.nodes.get_mut(&current_inode) {
                    parent.children.insert(segment.to_string(), next_inode);
                }
                current_inode = next_inode;
            }

            current_inode
        }

        fn ensure_directory(&mut self, relative_path: &str) -> u64 {
            self.ensure_directory_in_namespace(relative_path, NodeNamespace::User, false)
        }

        fn ensure_internal_directory(&mut self, relative_path: &str) -> u64 {
            self.ensure_directory_in_namespace(relative_path, NodeNamespace::ConflictInternal, true)
        }

        fn lookup_inode_by_relative_path(&self, relative_path: &str) -> Option<u64> {
            let mut current_inode = ROOT_INODE;
            if relative_path.is_empty() {
                return Some(ROOT_INODE);
            }

            for segment in relative_path
                .split('/')
                .filter(|segment| !segment.is_empty())
            {
                current_inode = self
                    .nodes
                    .get(&current_inode)?
                    .children
                    .get(segment)
                    .copied()?;
            }

            Some(current_inode)
        }

        fn clear_conflict_metadata(&mut self, inode: u64) {
            if let Some(node) = self.nodes.get_mut(&inode) {
                node.sync_metadata.local_version = None;
                node.sync_metadata.conflict_reason = None;
                node.sync_metadata.conflict_copy_path = None;
            }
        }

        fn clear_conflict_metadata_subtree(&mut self, inode: u64) {
            let child_inodes = self
                .nodes
                .get(&inode)
                .map(|node| node.children.values().copied().collect::<Vec<_>>())
                .unwrap_or_default();
            self.clear_conflict_metadata(inode);
            for child_inode in child_inodes {
                self.clear_conflict_metadata_subtree(child_inode);
            }
        }

        fn prune_empty_conflict_ancestors(&mut self, mut inode: u64) {
            while inode != ROOT_INODE {
                let Some(node) = self.nodes.get(&inode).cloned() else {
                    break;
                };
                if node.namespace != NodeNamespace::ConflictInternal
                    || node.kind != FileType::Directory
                    || !node.children.is_empty()
                {
                    break;
                }

                let parent_inode = node.parent_inode;
                if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                    parent.children.remove(&node.name);
                }
                self.nodes.remove(&inode);
                inode = parent_inode;
            }
        }

        fn remove_internal_conflict_copy(&mut self, relative_path: &str) {
            let sidecar_path = Self::conflict_copy_path(relative_path);
            let Some(inode) = self.lookup_inode_by_relative_path(&sidecar_path) else {
                return;
            };
            if inode == ROOT_INODE {
                return;
            }

            let Some(node) = self.nodes.get(&inode).cloned() else {
                return;
            };
            let parent_inode = node.parent_inode;
            if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                parent.children.remove(&node.name);
            }
            self.remove_inode_recursive(inode);
            self.prune_empty_conflict_ancestors(parent_inode);
        }

        fn clear_conflict_state_for_path(&mut self, relative_path: &str) {
            if let Some(inode) = self.lookup_inode_by_relative_path(relative_path) {
                self.clear_conflict_metadata(inode);
            }
            self.remove_internal_conflict_copy(relative_path);
        }

        fn ensure_placeholder_file(
            &mut self,
            relative_path: &str,
            remote_version: &str,
            remote_content_hash: &str,
            remote_size: Option<u64>,
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
                if let Some(file) = self.nodes.get_mut(&inode) {
                    file.placeholder_version = Some(remote_version.to_string());
                    file.placeholder_content_hash = Some(remote_content_hash.to_string());
                    file.data.clear();
                    file.size = remote_size.unwrap_or(0);
                    file.sync_metadata.remote_version = Some(remote_version.to_string());
                }
                return;
            }

            let inode = self.next_inode();
            let file = FsNode::placeholder_file(
                inode,
                file_name.to_string(),
                parent_inode,
                remote_version.to_string(),
                remote_content_hash.to_string(),
                remote_size.unwrap_or(0),
            );

            self.nodes.insert(inode, file);
            if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                parent.children.insert(file_name.to_string(), inode);
            }
        }

        fn inode_has_open_handle(&self, inode: u64) -> bool {
            self.open_handles
                .values()
                .any(|handle| handle.inode == inode)
        }

        fn inode_has_unsynced_local_file_state(&self, inode: u64) -> bool {
            self.nodes.get(&inode).is_some_and(|node| {
                node.kind == FileType::RegularFile
                    && !node.read_only
                    && node.placeholder_version.is_none()
                    && node.sync_metadata.remote_version.is_none()
            })
        }

        fn local_file_matches_remote(
            file: &FsNode,
            remote_content_hash: &str,
            remote_size: Option<u64>,
        ) -> bool {
            if file.kind != FileType::RegularFile || file.placeholder_version.is_some() {
                return false;
            }
            if remote_size.is_some_and(|size| size != file.size) {
                return false;
            }

            blake3::hash(&file.data).to_hex().as_str() == remote_content_hash
        }

        fn ensure_placeholder_file_for_refresh(
            &mut self,
            relative_path: &str,
            remote_version: &str,
            remote_content_hash: &str,
            remote_size: Option<u64>,
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
                if self.inode_has_open_handle(inode) {
                    return;
                }
                if self.inode_has_unsynced_local_file_state(inode) {
                    if let Some(file) = self.nodes.get_mut(&inode)
                        && Self::local_file_matches_remote(file, remote_content_hash, remote_size)
                    {
                        file.sync_metadata.remote_version = Some(remote_version.to_string());
                    }
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
                    && file.placeholder_content_hash.as_deref() == Some(remote_content_hash)
                    && file.data.is_empty()
                    && file.size == remote_size.unwrap_or(0);
                if already_placeholder {
                    return;
                }

                file.placeholder_version = Some(remote_version.to_string());
                file.placeholder_content_hash = Some(remote_content_hash.to_string());
                file.data.clear();
                file.size = remote_size.unwrap_or(0);
                file.modified_at = SystemTime::now();
                file.sync_metadata.remote_version = Some(remote_version.to_string());
                return;
            }

            let inode = self.next_inode();
            let file = FsNode::placeholder_file(
                inode,
                file_name.to_string(),
                parent_inode,
                remote_version.to_string(),
                remote_content_hash.to_string(),
                remote_size.unwrap_or(0),
            );
            self.nodes.insert(inode, file);
            if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                parent.children.insert(file_name.to_string(), inode);
            }
        }

        fn mark_conflict_path(
            &mut self,
            relative_path: &str,
            local_version: Option<String>,
            remote_version: Option<String>,
            remote_content_hash: Option<String>,
            remote_size: Option<u64>,
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
            let conflict_copy_path = Self::conflict_copy_path(relative_path);

            let existing = self
                .nodes
                .get(&parent_inode)
                .and_then(|node| node.children.get(file_name).copied());

            if let Some(inode) = existing {
                if let Some(file) = self.nodes.get_mut(&inode) {
                    if file.kind != FileType::RegularFile {
                        return;
                    }
                    if let (Some(remote_version), Some(remote_content_hash)) =
                        (remote_version.as_ref(), remote_content_hash.as_ref())
                        && file.placeholder_version.is_none()
                        && file.data.is_empty()
                    {
                        file.placeholder_version = Some(remote_version.clone());
                        file.placeholder_content_hash = Some(remote_content_hash.clone());
                        file.size = remote_size.unwrap_or(0);
                    }
                    file.sync_metadata.local_version = local_version.clone();
                    file.sync_metadata.remote_version = remote_version.clone();
                    file.sync_metadata.conflict_reason =
                        Some(CONFLICT_REASON_DIVERGENT_VERSIONS.to_string());
                    file.sync_metadata.conflict_copy_path = Some(conflict_copy_path.clone());
                    file.modified_at = SystemTime::now();
                }
            } else {
                let inode = self.next_inode();
                let mut file = match (remote_version.as_ref(), remote_content_hash.as_ref()) {
                    (Some(remote_version), Some(remote_content_hash)) => FsNode::placeholder_file(
                        inode,
                        file_name.to_string(),
                        parent_inode,
                        remote_version.clone(),
                        remote_content_hash.clone(),
                        remote_size.unwrap_or(0),
                    ),
                    _ => FsNode::regular_file(inode, file_name.to_string(), parent_inode),
                };
                file.sync_metadata.local_version = local_version.clone();
                file.sync_metadata.remote_version = remote_version.clone();
                file.sync_metadata.conflict_reason =
                    Some(CONFLICT_REASON_DIVERGENT_VERSIONS.to_string());
                file.sync_metadata.conflict_copy_path = Some(conflict_copy_path.clone());
                self.nodes.insert(inode, file);
                if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                    parent.children.insert(file_name.to_string(), inode);
                }
            }

            let (Some(remote_version), Some(remote_content_hash)) =
                (remote_version, remote_content_hash)
            else {
                return;
            };

            let mut sidecar_segments: Vec<&str> = conflict_copy_path
                .split('/')
                .filter(|segment| !segment.is_empty())
                .collect();
            let sidecar_name = sidecar_segments.pop().unwrap_or_default();
            let sidecar_parent_path = sidecar_segments.join("/");
            let sidecar_parent = self.ensure_internal_directory(&sidecar_parent_path);
            let existing_sidecar = self
                .nodes
                .get(&sidecar_parent)
                .and_then(|node| node.children.get(sidecar_name).copied());

            if let Some(sidecar_inode) = existing_sidecar {
                if let Some(sidecar) = self.nodes.get_mut(&sidecar_inode) {
                    if sidecar.kind != FileType::RegularFile {
                        return;
                    }
                    sidecar.placeholder_version = Some(remote_version.clone());
                    sidecar.placeholder_content_hash = Some(remote_content_hash.clone());
                    sidecar.size = remote_size.unwrap_or(0);
                    sidecar.read_only = true;
                    sidecar.namespace = NodeNamespace::ConflictInternal;
                    sidecar.backing_path = Some(relative_path.to_string());
                    sidecar.sync_metadata.local_version = local_version;
                    sidecar.sync_metadata.remote_version = Some(remote_version);
                    sidecar.sync_metadata.conflict_reason =
                        Some(CONFLICT_REASON_DIVERGENT_VERSIONS.to_string());
                    sidecar.sync_metadata.conflict_copy_path = Some(conflict_copy_path.clone());
                    sidecar.sync_metadata.source_path = Some(relative_path.to_string());
                }
                return;
            }

            let sidecar_inode = self.next_inode();
            let mut sidecar = FsNode::placeholder_file(
                sidecar_inode,
                sidecar_name.to_string(),
                sidecar_parent,
                remote_version.clone(),
                remote_content_hash,
                remote_size.unwrap_or(0),
            );
            sidecar.read_only = true;
            sidecar.namespace = NodeNamespace::ConflictInternal;
            sidecar.backing_path = Some(relative_path.to_string());
            sidecar.sync_metadata.local_version = local_version;
            sidecar.sync_metadata.remote_version = Some(remote_version);
            sidecar.sync_metadata.conflict_reason =
                Some(CONFLICT_REASON_DIVERGENT_VERSIONS.to_string());
            sidecar.sync_metadata.conflict_copy_path = Some(conflict_copy_path.clone());
            sidecar.sync_metadata.source_path = Some(relative_path.to_string());
            self.nodes.insert(sidecar_inode, sidecar);
            if let Some(parent) = self.nodes.get_mut(&sidecar_parent) {
                parent
                    .children
                    .insert(sidecar_name.to_string(), sidecar_inode);
            }
        }

        fn remove_inode_recursive(&mut self, inode: u64) {
            let Some(node) = self.nodes.get(&inode).cloned() else {
                return;
            };

            for child_inode in node.children.values() {
                self.remove_inode_recursive(*child_inode);
            }

            self.open_handles.retain(|_, handle| handle.inode != inode);
            self.nodes.remove(&inode);
        }

        fn remove_path_for_refresh(&mut self, relative_path: &str) {
            let segments: Vec<&str> = relative_path
                .split('/')
                .filter(|segment| !segment.is_empty())
                .collect();
            if segments.is_empty() {
                return;
            }

            let mut parent_inode = ROOT_INODE;
            for segment in segments.iter().take(segments.len().saturating_sub(1)) {
                let Some(next_inode) = self
                    .nodes
                    .get(&parent_inode)
                    .and_then(|node| node.children.get(*segment).copied())
                else {
                    return;
                };
                parent_inode = next_inode;
            }

            let leaf_name = segments.last().copied().unwrap_or_default();
            let Some(target_inode) = self
                .nodes
                .get(&parent_inode)
                .and_then(|node| node.children.get(leaf_name).copied())
            else {
                return;
            };

            if self.inode_has_open_handle(target_inode) {
                return;
            }
            if self.inode_has_unsynced_local_file_state(target_inode) {
                return;
            }

            if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                parent.children.remove(leaf_name);
            }
            self.remove_inode_recursive(target_inode);
            self.remove_internal_conflict_copy(relative_path);
        }

        fn apply_remote_action_plan_refresh(&mut self, action_plan: &FuseActionPlan) {
            for action in &action_plan.actions {
                if let FuseAction::RemovePath { path } = action {
                    self.remove_path_for_refresh(path);
                }
            }

            for action in &action_plan.actions {
                match action {
                    FuseAction::EnsureDirectory { path } => {
                        self.clear_conflict_state_for_path(path);
                        self.ensure_directory(path);
                    }
                    FuseAction::EnsurePlaceholder {
                        path,
                        remote_version,
                        remote_content_hash,
                        remote_size,
                    }
                    | FuseAction::HydrateOnRead {
                        path,
                        remote_version,
                        remote_content_hash,
                        remote_size,
                    } => {
                        self.clear_conflict_state_for_path(path);
                        self.ensure_placeholder_file_for_refresh(
                            path,
                            remote_version,
                            remote_content_hash,
                            *remote_size,
                        );
                    }
                    FuseAction::MarkConflict {
                        path,
                        local_version,
                        remote_version,
                        remote_content_hash,
                        remote_size,
                    } => {
                        self.mark_conflict_path(
                            path,
                            local_version.clone(),
                            remote_version.clone(),
                            remote_content_hash.clone(),
                            *remote_size,
                        );
                    }
                    FuseAction::UploadOnFlush { .. } | FuseAction::RemovePath { .. } => {}
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
                self.apply_remote_action_plan_refresh(&action_plan);
            }
        }

        fn child_path(parent_path: &str, name: &str) -> String {
            if parent_path.is_empty() {
                name.to_string()
            } else {
                format!("{parent_path}/{name}")
            }
        }

        fn inode_has_dirty_state(&self, inode: u64) -> bool {
            self.open_handles.values().any(|handle| {
                handle.inode == inode
                    && handle.write_access
                    && (handle.dirty || handle.upload_enqueued)
            })
        }

        fn xattr_entries_for_inode(&self, inode: u64) -> Result<Vec<(String, Vec<u8>)>> {
            let node = self
                .nodes
                .get(&inode)
                .ok_or_else(|| anyhow!("inode not found: {inode}"))?;

            let mut entries = Vec::new();
            let mut state = Vec::new();
            if node.placeholder_version.is_some() {
                state.push("placeholder");
            }
            if self.inode_has_dirty_state(inode) {
                state.push("dirty");
            }
            if node.sync_metadata.conflict_reason.is_some() {
                state.push("conflict");
            }
            if node.namespace == NodeNamespace::ConflictInternal
                && node.kind == FileType::RegularFile
            {
                state.push("conflict-copy");
            }
            if node.read_only {
                state.push("read-only");
            }
            if state.is_empty() {
                state.push("clean");
            }
            entries.push((XATTR_STATE.to_string(), state.join(",").into_bytes()));

            if let Some(local_version) = node.sync_metadata.local_version.as_deref() {
                entries.push((
                    XATTR_LOCAL_VERSION.to_string(),
                    local_version.as_bytes().to_vec(),
                ));
            }
            if let Some(remote_version) = node.sync_metadata.remote_version.as_deref() {
                entries.push((
                    XATTR_REMOTE_VERSION.to_string(),
                    remote_version.as_bytes().to_vec(),
                ));
            }
            if let Some(conflict_reason) = node.sync_metadata.conflict_reason.as_deref() {
                entries.push((
                    XATTR_CONFLICT_REASON.to_string(),
                    conflict_reason.as_bytes().to_vec(),
                ));
            }
            if let Some(conflict_copy_path) = node.sync_metadata.conflict_copy_path.as_deref() {
                entries.push((
                    XATTR_CONFLICT_COPY.to_string(),
                    conflict_copy_path.as_bytes().to_vec(),
                ));
            }
            if let Some(source_path) = node.sync_metadata.source_path.as_deref() {
                entries.push((
                    XATTR_SOURCE_PATH.to_string(),
                    source_path.as_bytes().to_vec(),
                ));
            }

            Ok(entries)
        }

        fn xattr_value_for_inode(&self, inode: u64, name: &str) -> Result<Option<Vec<u8>>> {
            Ok(self
                .xattr_entries_for_inode(inode)?
                .into_iter()
                .find_map(|(entry_name, value)| (entry_name == name).then_some(value)))
        }

        fn xattr_name_list_for_inode(&self, inode: u64) -> Result<Vec<u8>> {
            let mut payload = Vec::new();
            for (name, _) in self.xattr_entries_for_inode(inode)? {
                payload.extend_from_slice(name.as_bytes());
                payload.push(0);
            }
            Ok(payload)
        }

        fn reply_xattr_payload(payload: &[u8], size: u32, reply: ReplyXattr) {
            if size == 0 {
                reply.size(payload.len() as u32);
                return;
            }

            if payload.len() > size as usize {
                reply.error(ERANGE);
                return;
            }

            reply.data(payload);
        }

        fn parent_allows_mutation(&self, parent: u64, name: &str) -> bool {
            let Some(parent_node) = self.nodes.get(&parent) else {
                return false;
            };
            !(parent_node.read_only || (parent == ROOT_INODE && Self::is_reserved_root_child(name)))
        }

        fn collect_subtree_nodes(
            &self,
            inode: u64,
            directories: &mut Vec<u64>,
            files: &mut Vec<u64>,
        ) -> Result<()> {
            let node = self
                .nodes
                .get(&inode)
                .ok_or_else(|| anyhow!("inode not found: {inode}"))?;

            match node.kind {
                FileType::Directory => {
                    directories.push(inode);
                    for child_inode in node.children.values() {
                        self.collect_subtree_nodes(*child_inode, directories, files)?;
                    }
                }
                FileType::RegularFile => files.push(inode),
                _ => return Err(anyhow!("unsupported inode kind for rename: {}", node.inode)),
            }

            Ok(())
        }

        fn ensure_remote_directory_marker(&self, path: &str) -> Result<()> {
            let marker = format!("{}/", path.trim_end_matches('/'));
            let mut reader = Cursor::new(Vec::new());
            self.uploader.upload_reader(&marker, None, &mut reader, 0)?;
            Ok(())
        }

        fn path_depth(path: &str) -> usize {
            path.split('/')
                .filter(|segment| !segment.is_empty())
                .count()
        }

        fn remote_rename_file(
            &self,
            from_path: &str,
            to_path: &str,
            base_remote_version: Option<&str>,
        ) -> Result<()> {
            let started = Instant::now();
            tracing::info!(
                from_path,
                to_path,
                base_remote_version = base_remote_version.unwrap_or("<none>"),
                "ironmesh fuse remote rename file start"
            );
            self.uploader
                .rename_path(from_path, to_path, false, base_remote_version)
                .with_context(|| {
                    format!("failed to rename remote file {from_path} -> {to_path}")
                })?;
            tracing::info!(
                from_path,
                to_path,
                elapsed_ms = started.elapsed().as_millis(),
                "ironmesh fuse remote rename file finished"
            );
            Ok(())
        }

        fn remote_rename_directory_subtree(
            &self,
            directory_inode: u64,
            from_root: &str,
            to_root: &str,
        ) -> Result<()> {
            let started = Instant::now();
            let mut directories = Vec::new();
            let mut files = Vec::new();
            self.collect_subtree_nodes(directory_inode, &mut directories, &mut files)?;
            tracing::info!(
                from_root,
                to_root,
                file_count = files.len(),
                directory_count = directories.len(),
                "ironmesh fuse remote rename directory subtree start"
            );

            let file_phase_started = Instant::now();
            let file_count = files.len();
            for inode in files {
                let old_path = self.resolve_full_path(inode);
                let relative = old_path
                    .strip_prefix(from_root)
                    .and_then(|value| value.strip_prefix('/'))
                    .ok_or_else(|| anyhow!("file path escaped rename root: {old_path}"))?;
                let new_path = format!("{to_root}/{relative}");
                let remote_version = self
                    .nodes
                    .get(&inode)
                    .and_then(|node| node.sync_metadata.remote_version.as_deref());
                tracing::info!(
                    from_path = old_path.as_str(),
                    to_path = new_path.as_str(),
                    base_remote_version = remote_version.unwrap_or("<none>"),
                    file_count,
                    "ironmesh fuse remote rename directory file step"
                );
                self.remote_rename_file(&old_path, &new_path, remote_version)?;
            }
            tracing::info!(
                from_root,
                to_root,
                file_count,
                elapsed_ms = file_phase_started.elapsed().as_millis(),
                "ironmesh fuse remote rename directory file phase finished"
            );

            let mut directory_paths: Vec<String> = directories
                .into_iter()
                .map(|inode| self.resolve_full_path(inode))
                .collect();

            directory_paths.sort_by_key(|path| Self::path_depth(path));
            let marker_create_started = Instant::now();
            let directory_count = directory_paths.len();
            for old_path in &directory_paths {
                let relative = old_path
                    .strip_prefix(from_root)
                    .and_then(|value| {
                        if value.is_empty() {
                            Some("")
                        } else {
                            value.strip_prefix('/')
                        }
                    })
                    .ok_or_else(|| anyhow!("directory path escaped rename root: {old_path}"))?;
                let new_path = if relative.is_empty() {
                    to_root.to_string()
                } else {
                    format!("{to_root}/{relative}")
                };
                tracing::info!(
                    from_path = old_path.as_str(),
                    to_path = new_path.as_str(),
                    directory_count,
                    "ironmesh fuse remote rename directory marker create step"
                );
                self.ensure_remote_directory_marker(&new_path)?;
            }
            tracing::info!(
                from_root,
                to_root,
                directory_count,
                elapsed_ms = marker_create_started.elapsed().as_millis(),
                "ironmesh fuse remote rename directory marker create phase finished"
            );

            directory_paths.sort_by_key(|path| std::cmp::Reverse(Self::path_depth(path)));
            let marker_delete_started = Instant::now();
            for old_path in &directory_paths {
                let old_marker = format!("{}/", old_path.trim_end_matches('/'));
                tracing::info!(
                    old_marker = old_marker.as_str(),
                    directory_count,
                    "ironmesh fuse remote rename directory marker delete step"
                );
                self.uploader
                    .delete_path(&old_marker, None)
                    .with_context(|| format!("failed to delete stale marker {old_marker}"))?;
            }
            tracing::info!(
                from_root,
                to_root,
                directory_count,
                elapsed_ms = marker_delete_started.elapsed().as_millis(),
                total_elapsed_ms = started.elapsed().as_millis(),
                "ironmesh fuse remote rename directory subtree finished"
            );

            Ok(())
        }

        fn apply_local_rename(
            &mut self,
            old_parent: u64,
            old_name: &str,
            new_parent: u64,
            new_name: &str,
            inode: u64,
        ) -> Result<()> {
            if let Some(parent) = self.nodes.get_mut(&old_parent) {
                parent.children.remove(old_name);
            } else {
                return Err(anyhow!("old parent inode missing during rename"));
            }

            if let Some(parent) = self.nodes.get_mut(&new_parent) {
                parent.children.insert(new_name.to_string(), inode);
            } else {
                return Err(anyhow!("new parent inode missing during rename"));
            }

            if let Some(node) = self.nodes.get_mut(&inode) {
                node.parent_inode = new_parent;
                node.name = new_name.to_string();
                node.modified_at = SystemTime::now();
            } else {
                return Err(anyhow!("inode missing during rename update"));
            }

            Ok(())
        }

        fn next_inode(&self) -> u64 {
            self.nodes.keys().max().copied().unwrap_or(ROOT_INODE) + 1
        }

        fn hydrate_if_needed(&mut self, inode: u64) -> Result<()> {
            let (path, version, content_hash) = {
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
                let content_hash = node
                    .placeholder_content_hash
                    .clone()
                    .ok_or_else(|| anyhow!("placeholder content hash missing"))?;
                (
                    node.content_path(self.resolve_full_path(inode)),
                    version,
                    content_hash,
                )
            };

            let data = self
                .hydrator
                .hydrate(&path, &version, &content_hash)
                .with_context(|| {
                    format!(
                        "failed to hydrate placeholder path={path} version={version} content_hash={content_hash}"
                    )
                })?;
            let file = self
                .nodes
                .get_mut(&inode)
                .ok_or_else(|| anyhow!("inode disappeared during hydration"))?;
            file.data = data;
            file.size = file.data.len() as u64;
            file.modified_at = SystemTime::now();
            file.placeholder_version = None;
            file.placeholder_content_hash = None;

            Ok(())
        }

        fn read_file_data(&mut self, inode: u64, offset: i64, size: u32) -> Result<Vec<u8>> {
            let (path, version, content_hash) = {
                let node = self
                    .nodes
                    .get(&inode)
                    .ok_or_else(|| anyhow!("inode not found"))?;
                if node.kind != FileType::RegularFile {
                    return Err(anyhow!("inode {inode} is not a regular file"));
                }

                (
                    node.content_path(self.resolve_full_path(inode)),
                    node.placeholder_version.clone(),
                    node.placeholder_content_hash.clone(),
                )
            };

            if size == 0 {
                return Ok(Vec::new());
            }

            if let Some(version) = version {
                let content_hash =
                    content_hash.ok_or_else(|| anyhow!("placeholder content hash missing"))?;
                let start = offset.max(0) as u64;
                return self
                    .hydrator
                    .hydrate_range(&path, &version, &content_hash, start, size as u64)
                    .with_context(|| {
                        format!(
                            "failed to hydrate placeholder range path={path} version={version} content_hash={content_hash} offset={start} size={size}"
                        )
                    });
            }

            let node = self
                .nodes
                .get(&inode)
                .ok_or_else(|| anyhow!("inode disappeared during read"))?;
            let start = offset.max(0) as usize;
            if start >= node.data.len() {
                return Ok(Vec::new());
            }
            let end = (start + size as usize).min(node.data.len());
            Ok(node.data[start..end].to_vec())
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
                node.placeholder_content_hash = None;
                node.sync_metadata.local_version = None;
            }
            Ok(changed)
        }

        fn alloc_open_handle(
            &mut self,
            inode: u64,
            write_access: bool,
            upload_enqueued: bool,
        ) -> u64 {
            let fh = self.next_handle;
            self.next_handle = self.next_handle.saturating_add(1);
            self.open_handles.insert(
                fh,
                OpenHandle {
                    inode,
                    write_access,
                    dirty: false,
                    upload_enqueued,
                },
            );
            fh
        }

        fn write_requested(flags: i32) -> bool {
            let write_flags =
                libc::O_WRONLY | libc::O_RDWR | libc::O_APPEND | libc::O_TRUNC | libc::O_CREAT;
            (flags & write_flags) != 0
        }

        fn should_hydrate_on_open(flags: i32) -> bool {
            Self::write_requested(flags) && (flags & libc::O_TRUNC) == 0
        }

        fn should_hydrate_for_size_change(node: &FsNode, size: u64) -> bool {
            node.kind == FileType::RegularFile
                && node.placeholder_version.is_some()
                && node.size != size
        }

        fn upload_inode(&mut self, inode: u64) -> Result<bool> {
            let (path, base_remote_version, size, payload) = {
                let node = self
                    .nodes
                    .get(&inode)
                    .ok_or_else(|| anyhow!("inode not found"))?;
                if node.kind != FileType::RegularFile {
                    return Err(anyhow!("inode {inode} is not a regular file"));
                }
                if node.read_only {
                    return Err(anyhow!("inode {inode} is read-only"));
                }

                (
                    self.resolve_full_path(inode),
                    node.sync_metadata.remote_version.clone(),
                    node.size,
                    node.data.clone(),
                )
            };

            let mut reader = Cursor::new(payload);
            let remote_version = self
                .uploader
                .upload_reader(&path, base_remote_version.as_deref(), &mut reader, size)
                .with_context(|| format!("failed to upload path {path}"))?;
            let synced = remote_version.is_some();

            if !synced && let Some(node) = self.nodes.get_mut(&inode) {
                // Once a mutation is only queued, the old remote version is no longer a reliable
                // parent for subsequent local writes on this inode.
                node.sync_metadata.remote_version = None;
            }

            Ok(synced)
        }

        fn flush_handle(&mut self, ino: u64, fh: u64) -> Result<()> {
            let Some(handle) = self.open_handles.get(&fh).copied() else {
                return Err(anyhow!("unknown file handle"));
            };
            if handle.inode != ino {
                return Err(anyhow!("inode/file-handle mismatch"));
            }

            if handle.write_access && handle.dirty && !handle.upload_enqueued {
                let synced = self.upload_inode(ino)?;
                if let Some(handle) = self.open_handles.get_mut(&fh) {
                    if synced {
                        handle.dirty = false;
                    } else {
                        handle.upload_enqueued = true;
                    }
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

            if handle.write_access && handle.dirty && !handle.upload_enqueued {
                self.upload_inode(ino)?;
            }
            Ok(())
        }

        fn delete_remote_path_for_inode(&self, inode: u64) -> Result<()> {
            let node = self
                .nodes
                .get(&inode)
                .ok_or_else(|| anyhow!("inode not found"))?;
            let path = self.resolve_full_path(inode);
            match node.kind {
                FileType::RegularFile => self
                    .uploader
                    .delete_path(&path, node.sync_metadata.remote_version.as_deref())
                    .with_context(|| format!("failed to delete remote file {path}")),
                FileType::Directory => {
                    let marker_path = format!("{}/", path.trim_end_matches('/'));
                    self.uploader
                        .delete_path(&marker_path, None)
                        .with_context(|| {
                            format!("failed to delete remote directory marker {marker_path}")
                        })
                }
                _ => Err(anyhow!("unsupported inode type for remote delete")),
            }
        }

        fn rename_entry(
            &mut self,
            parent: u64,
            name: &str,
            newparent: u64,
            newname: &str,
            flags: u32,
        ) -> Result<()> {
            if flags != 0 {
                return Err(anyhow!("rename flags not supported"));
            }

            let Some(old_parent_node) = self.nodes.get(&parent) else {
                return Err(anyhow!("source parent inode missing"));
            };
            if old_parent_node.kind != FileType::Directory {
                return Err(anyhow!("source parent inode is not a directory"));
            }
            if old_parent_node.read_only
                || (parent == ROOT_INODE && Self::is_reserved_root_child(name))
            {
                return Err(anyhow!("source parent is read-only"));
            }

            let Some(new_parent_node) = self.nodes.get(&newparent) else {
                return Err(anyhow!("destination parent inode missing"));
            };
            if new_parent_node.kind != FileType::Directory {
                return Err(anyhow!("destination parent inode is not a directory"));
            }
            if new_parent_node.read_only
                || (newparent == ROOT_INODE && Self::is_reserved_root_child(newname))
            {
                return Err(anyhow!("destination parent is read-only"));
            }

            let Some(inode) = old_parent_node.children.get(name).copied() else {
                return Err(anyhow!("rename source not found"));
            };

            if parent == newparent && name == newname {
                return Ok(());
            }

            let Some(source_node) = self.nodes.get(&inode).cloned() else {
                return Err(anyhow!("source inode missing"));
            };
            if source_node.read_only {
                return Err(anyhow!("source inode is read-only"));
            }

            let dest_inode = new_parent_node.children.get(newname).copied();
            if let Some(dest_inode) = dest_inode {
                if dest_inode == inode {
                    return Ok(());
                }

                let Some(dest_node) = self.nodes.get(&dest_inode).cloned() else {
                    return Err(anyhow!("destination inode missing"));
                };
                if dest_node.read_only {
                    return Err(anyhow!("destination inode is read-only"));
                }

                match (source_node.kind, dest_node.kind) {
                    (FileType::RegularFile, FileType::RegularFile) => {}
                    (FileType::Directory, FileType::Directory) => {
                        if !dest_node.children.is_empty() {
                            return Err(anyhow!("destination directory is not empty"));
                        }
                    }
                    (FileType::RegularFile, FileType::Directory) => {
                        return Err(anyhow!("cannot replace a directory with a file"));
                    }
                    (FileType::Directory, FileType::RegularFile) => {
                        return Err(anyhow!("cannot replace a file with a directory"));
                    }
                    _ => return Err(anyhow!("unsupported inode type for rename")),
                }
            }

            let old_parent_path = self.resolve_full_path(parent);
            let new_parent_path = self.resolve_full_path(newparent);
            let old_full_path = Self::child_path(&old_parent_path, name);
            let new_full_path = Self::child_path(&new_parent_path, newname);

            if let Some(dest_inode) = dest_inode {
                self.remove_internal_conflict_copy(&new_full_path);
                self.delete_remote_path_for_inode(dest_inode)?;
            }

            let remote_result = match source_node.kind {
                FileType::RegularFile => self.remote_rename_file(
                    &old_full_path,
                    &new_full_path,
                    source_node.sync_metadata.remote_version.as_deref(),
                ),
                FileType::Directory => {
                    self.remote_rename_directory_subtree(inode, &old_full_path, &new_full_path)
                }
                _ => Err(anyhow!("unsupported inode type for rename")),
            };
            remote_result?;

            if let Some(dest_inode) = dest_inode {
                if let Some(parent_node) = self.nodes.get_mut(&newparent) {
                    parent_node.children.remove(newname);
                }
                self.remove_inode_recursive(dest_inode);
            }

            self.apply_local_rename(parent, name, newparent, newname, inode)?;
            self.clear_conflict_metadata_subtree(inode);
            self.remove_internal_conflict_copy(&old_full_path);
            Ok(())
        }

        fn would_create_directory_cycle(
            &self,
            directory_inode: u64,
            candidate_parent_inode: u64,
        ) -> Result<bool> {
            let mut current = candidate_parent_inode;
            while current != ROOT_INODE {
                if current == directory_inode {
                    return Ok(true);
                }
                let ancestor = self
                    .nodes
                    .get(&current)
                    .ok_or_else(|| anyhow!("ancestor inode missing during rename"))?;
                current = ancestor.parent_inode;
            }

            Ok(false)
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

        fn split_relative_path(relative_path: &str) -> Result<(String, String)> {
            let mut segments: Vec<&str> = relative_path
                .split('/')
                .filter(|segment| !segment.is_empty())
                .collect();
            if segments.is_empty() {
                return Err(anyhow!("relative path is empty"));
            }
            let name = segments.pop().unwrap_or_default().to_string();
            Ok((segments.join("/"), name))
        }

        fn upsert_file_local_only(&mut self, relative_path: &str, data: &[u8]) -> Result<()> {
            let (parent_path, name) = Self::split_relative_path(relative_path)?;
            let parent_inode = self.ensure_directory(&parent_path);
            let existing = self
                .nodes
                .get(&parent_inode)
                .and_then(|node| node.children.get(name.as_str()).copied());

            if let Some(inode) = existing {
                let existing_kind = self
                    .nodes
                    .get(&inode)
                    .map(|node| node.kind)
                    .ok_or_else(|| anyhow!("inode missing during replay upsert"))?;
                if existing_kind == FileType::Directory {
                    if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                        parent.children.remove(name.as_str());
                    }
                    self.remove_inode_recursive(inode);
                } else if let Some(node) = self.nodes.get_mut(&inode) {
                    node.data = data.to_vec();
                    node.size = node.data.len() as u64;
                    node.placeholder_version = None;
                    node.placeholder_content_hash = None;
                    node.modified_at = SystemTime::now();
                    node.sync_metadata.local_version = None;
                    return Ok(());
                }
            }

            let inode = self.next_inode();
            let mut file = FsNode::regular_file(inode, name.clone(), parent_inode);
            file.data = data.to_vec();
            file.size = file.data.len() as u64;
            self.nodes.insert(inode, file);
            if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                parent.children.insert(name, inode);
            }
            Ok(())
        }

        fn delete_path_local_only(&mut self, relative_path: &str, _directory: bool) -> Result<()> {
            let Some(inode) = self.lookup_inode_by_relative_path(relative_path) else {
                self.remove_internal_conflict_copy(relative_path);
                return Ok(());
            };
            if inode == ROOT_INODE {
                return Err(anyhow!("cannot delete root inode"));
            }

            let parent_inode = self
                .nodes
                .get(&inode)
                .map(|node| node.parent_inode)
                .ok_or_else(|| anyhow!("inode missing during replay delete"))?;
            let name = self
                .nodes
                .get(&inode)
                .map(|node| node.name.clone())
                .ok_or_else(|| anyhow!("inode missing during replay delete"))?;
            if let Some(parent) = self.nodes.get_mut(&parent_inode) {
                parent.children.remove(name.as_str());
            }
            self.remove_inode_recursive(inode);
            self.remove_internal_conflict_copy(relative_path);
            Ok(())
        }

        fn rename_path_local_only(
            &mut self,
            from_path: &str,
            to_path: &str,
            overwrite: bool,
        ) -> Result<()> {
            let Some(inode) = self.lookup_inode_by_relative_path(from_path) else {
                return Ok(());
            };
            let old_parent = self
                .nodes
                .get(&inode)
                .map(|node| node.parent_inode)
                .ok_or_else(|| anyhow!("source inode missing during replay rename"))?;
            let old_name = self
                .nodes
                .get(&inode)
                .map(|node| node.name.clone())
                .ok_or_else(|| anyhow!("source inode missing during replay rename"))?;
            let (new_parent_path, new_name) = Self::split_relative_path(to_path)?;
            let new_parent = self.ensure_directory(&new_parent_path);

            if let Some(dest_inode) = self.lookup_inode_by_relative_path(to_path) {
                if dest_inode == inode {
                    return Ok(());
                }
                if !overwrite {
                    return Err(anyhow!("replay rename target exists: {to_path}"));
                }
                let dest_parent = self
                    .nodes
                    .get(&dest_inode)
                    .map(|node| node.parent_inode)
                    .ok_or_else(|| anyhow!("target inode missing during replay rename"))?;
                let dest_name = self
                    .nodes
                    .get(&dest_inode)
                    .map(|node| node.name.clone())
                    .ok_or_else(|| anyhow!("target inode missing during replay rename"))?;
                if let Some(parent) = self.nodes.get_mut(&dest_parent) {
                    parent.children.remove(dest_name.as_str());
                }
                self.remove_inode_recursive(dest_inode);
            }

            self.apply_local_rename(old_parent, &old_name, new_parent, &new_name, inode)?;
            self.clear_conflict_metadata_subtree(inode);
            self.remove_internal_conflict_copy(from_path);
            Ok(())
        }

        pub fn apply_replay_actions(&mut self, actions: &[ReplayAction]) -> Result<()> {
            for action in actions {
                match action {
                    ReplayAction::EnsureDirectory { path } => {
                        self.ensure_directory(path);
                    }
                    ReplayAction::UpsertFile { path, data } => {
                        self.upsert_file_local_only(path, data)?;
                    }
                    ReplayAction::DeletePath { path, directory } => {
                        self.delete_path_local_only(path, *directory)?;
                    }
                    ReplayAction::RenamePath {
                        from_path,
                        to_path,
                        overwrite,
                    } => {
                        self.rename_path_local_only(from_path, to_path, *overwrite)?;
                    }
                }
            }
            Ok(())
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

        fn mknod(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            mode: u32,
            _umask: u32,
            _rdev: u32,
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
            if !self.parent_allows_mutation(parent, name) {
                reply.error(EACCES);
                return;
            }
            if parent_node.children.contains_key(name) {
                reply.error(EEXIST);
                return;
            }

            if (mode & libc::S_IFMT) != libc::S_IFREG {
                reply.error(EPERM);
                return;
            }

            let inode = self.next_inode();
            self.nodes
                .insert(inode, FsNode::regular_file(inode, name.to_string(), parent));

            if let Some(parent_node) = self.nodes.get_mut(&parent) {
                parent_node.children.insert(name.to_string(), inode);
            }

            if let Err(_error) = self.upload_inode(inode) {
                if let Some(parent_node) = self.nodes.get_mut(&parent) {
                    parent_node.children.remove(name);
                }
                self.remove_inode_recursive(inode);
                reply.error(EIO);
                return;
            }

            let Some(created) = self.nodes.get(&inode) else {
                reply.error(EIO);
                return;
            };
            reply.entry(&TTL, &created.attr(self.uid, self.gid), 0);
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
            if !self.parent_allows_mutation(parent, name) {
                reply.error(EACCES);
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

            let directory_marker_path = format!("{}/", self.resolve_full_path(inode));
            let mut marker_reader = Cursor::new(Vec::new());
            if self
                .uploader
                .upload_reader(&directory_marker_path, None, &mut marker_reader, 0)
                .is_err()
            {
                if let Some(parent_node) = self.nodes.get_mut(&parent) {
                    parent_node.children.remove(name);
                }
                self.nodes.remove(&inode);
                reply.error(EIO);
                return;
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
            if child_node.read_only {
                reply.error(EPERM);
                return;
            }
            if child_node.kind == FileType::Directory {
                reply.error(EISDIR);
                return;
            }

            let child_path = self.resolve_full_path(child_inode);
            if self
                .uploader
                .delete_path(
                    &child_path,
                    child_node.sync_metadata.remote_version.as_deref(),
                )
                .is_err()
            {
                reply.error(EIO);
                return;
            }

            if let Some(parent_node) = self.nodes.get_mut(&parent) {
                parent_node.children.remove(name);
            }
            self.nodes.remove(&child_inode);
            self.open_handles
                .retain(|_, handle| handle.inode != child_inode);
            self.remove_internal_conflict_copy(&child_path);
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
            if child_node.read_only {
                reply.error(EPERM);
                return;
            }
            if child_node.kind != FileType::Directory {
                reply.error(ENOTDIR);
                return;
            }
            if !child_node.children.is_empty() {
                reply.error(ENOTEMPTY);
                return;
            }

            let directory_marker_path = format!(
                "{}/",
                self.resolve_full_path(child_inode).trim_end_matches('/')
            );
            let child_path = self.resolve_full_path(child_inode);
            if self
                .uploader
                .delete_path(&directory_marker_path, None)
                .is_err()
            {
                reply.error(EIO);
                return;
            }

            if let Some(parent_node) = self.nodes.get_mut(&parent) {
                parent_node.children.remove(name);
            }
            self.nodes.remove(&child_inode);
            self.remove_internal_conflict_copy(&child_path);
            reply.ok();
        }

        fn rename(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            newparent: u64,
            newname: &OsStr,
            flags: u32,
            reply: ReplyEmpty,
        ) {
            self.drain_remote_updates();

            let Some(old_name) = name.to_str() else {
                reply.error(EINVAL);
                return;
            };
            let Some(new_name) = newname.to_str() else {
                reply.error(EINVAL);
                return;
            };
            if old_name.is_empty()
                || new_name.is_empty()
                || old_name.contains('/')
                || new_name.contains('/')
            {
                reply.error(EINVAL);
                return;
            }

            let Some(old_parent_node) = self.nodes.get(&parent) else {
                reply.error(ENOENT);
                return;
            };
            if old_parent_node.kind != FileType::Directory {
                reply.error(ENOTDIR);
                return;
            }

            let Some(new_parent_node) = self.nodes.get(&newparent) else {
                reply.error(ENOENT);
                return;
            };
            if new_parent_node.kind != FileType::Directory {
                reply.error(ENOTDIR);
                return;
            }
            if old_parent_node.read_only
                || new_parent_node.read_only
                || (parent == ROOT_INODE && Self::is_reserved_root_child(old_name))
                || (newparent == ROOT_INODE && Self::is_reserved_root_child(new_name))
            {
                reply.error(EPERM);
                return;
            }

            let Some(inode) = old_parent_node.children.get(old_name).copied() else {
                reply.error(ENOENT);
                return;
            };

            if parent == newparent && old_name == new_name {
                reply.ok();
                return;
            }

            let Some(node) = self.nodes.get(&inode) else {
                reply.error(ENOENT);
                return;
            };
            if node.read_only {
                reply.error(EPERM);
                return;
            }

            let old_parent_path = self.resolve_full_path(parent);
            let new_parent_path = self.resolve_full_path(newparent);
            let old_full_path = Self::child_path(&old_parent_path, old_name);
            let new_full_path = Self::child_path(&new_parent_path, new_name);
            let started = Instant::now();
            tracing::info!(
                from_path = old_full_path.as_str(),
                to_path = new_full_path.as_str(),
                inode,
                kind = ?node.kind,
                flags,
                destination_exists = new_parent_node.children.contains_key(new_name),
                "ironmesh fuse rename start"
            );

            if let Some(existing_inode) = new_parent_node.children.get(new_name).copied() {
                if existing_inode == inode {
                    tracing::info!(
                        from_path = old_full_path.as_str(),
                        to_path = new_full_path.as_str(),
                        elapsed_ms = started.elapsed().as_millis(),
                        "ironmesh fuse rename short-circuited because destination already matches source"
                    );
                    reply.ok();
                    return;
                }

                let Some(existing_node) = self.nodes.get(&existing_inode) else {
                    reply.error(ENOENT);
                    return;
                };
                if existing_node.read_only {
                    reply.error(EPERM);
                    return;
                }

                match (node.kind, existing_node.kind) {
                    (FileType::RegularFile, FileType::RegularFile) => {}
                    (FileType::Directory, FileType::Directory) => {
                        if !existing_node.children.is_empty() {
                            reply.error(ENOTEMPTY);
                            return;
                        }
                    }
                    (FileType::RegularFile, FileType::Directory) => {
                        reply.error(EISDIR);
                        return;
                    }
                    (FileType::Directory, FileType::RegularFile) => {
                        reply.error(ENOTDIR);
                        return;
                    }
                    _ => {
                        reply.error(EIO);
                        return;
                    }
                }
            }

            if node.kind == FileType::Directory {
                match self.would_create_directory_cycle(inode, newparent) {
                    Ok(true) => {
                        reply.error(EINVAL);
                        return;
                    }
                    Ok(false) => {}
                    Err(_) => {
                        reply.error(EIO);
                        return;
                    }
                }
            }

            if let Err(error) = self.rename_entry(parent, old_name, newparent, new_name, flags) {
                tracing::warn!(
                    from_path = old_full_path.as_str(),
                    to_path = new_full_path.as_str(),
                    elapsed_ms = started.elapsed().as_millis(),
                    error = %error,
                    "ironmesh fuse rename failed"
                );
                reply.error(EIO);
                return;
            }

            tracing::info!(
                from_path = old_full_path.as_str(),
                to_path = new_full_path.as_str(),
                elapsed_ms = started.elapsed().as_millis(),
                "ironmesh fuse rename finished"
            );
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
            let mut upload_enqueued = false;
            if node.read_only && write_access {
                reply.error(EACCES);
                return;
            }
            if write_access && (flags & libc::O_TRUNC) != 0 {
                if let Err(_error) = self.truncate_if_needed(ino, 0) {
                    reply.error(EIO);
                    return;
                }
                match self.upload_inode(ino) {
                    Ok(synced) => upload_enqueued = !synced,
                    Err(_error) => {
                        reply.error(EIO);
                        return;
                    }
                }
            } else if Self::should_hydrate_on_open(flags)
                && let Err(_error) = self.hydrate_if_needed(ino)
            {
                reply.error(EIO);
                return;
            }

            let fh = self.alloc_open_handle(ino, write_access, upload_enqueued);
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
            if !self.parent_allows_mutation(parent, name) {
                reply.error(EACCES);
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

            let write_access = Self::write_requested(flags);
            let fh = self.alloc_open_handle(inode, write_access, false);
            match self.upload_inode(inode) {
                Ok(synced) => {
                    if !synced && let Some(handle) = self.open_handles.get_mut(&fh) {
                        handle.upload_enqueued = true;
                    }
                }
                Err(_error) => {
                    if let Some(parent_node) = self.nodes.get_mut(&parent) {
                        parent_node.children.remove(name);
                    }
                    self.remove_inode_recursive(inode);
                    reply.error(EIO);
                    return;
                }
            }
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
            let path = self.resolve_full_path(ino);

            match self.read_file_data(ino, offset, size) {
                Ok(data) => reply.data(&data),
                Err(error) => {
                    tracing::warn!(
                        inode = ino,
                        path = if path.is_empty() { "/" } else { path.as_str() },
                        offset,
                        size,
                        error = %error,
                        "ironmesh fuse read failed"
                    );
                    reply.error(EIO);
                }
            }
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
            if file.read_only {
                reply.error(EACCES);
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
            file.placeholder_content_hash = None;
            file.sync_metadata.local_version = None;

            if let Some(handle) = self.open_handles.get_mut(&fh) {
                handle.dirty = true;
                handle.upload_enqueued = false;
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
                let Some(node) = self.nodes.get(&ino) else {
                    reply.error(ENOENT);
                    return;
                };
                if node.read_only {
                    reply.error(EACCES);
                    return;
                }

                if Self::should_hydrate_for_size_change(node, size)
                    && let Err(_error) = self.hydrate_if_needed(ino)
                {
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
                    && size == 0
                    && let Err(_error) = self.upload_inode(ino)
                {
                    reply.error(EIO);
                    return;
                }

                if changed
                    && let Some(fh) = fh
                    && let Some(handle) = self.open_handles.get_mut(&fh)
                    && handle.write_access
                {
                    handle.dirty = true;
                    handle.upload_enqueued = false;
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

        fn setxattr(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _name: &OsStr,
            _value: &[u8],
            _flags: i32,
            _position: u32,
            reply: ReplyEmpty,
        ) {
            reply.error(EPERM);
        }

        fn getxattr(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            name: &OsStr,
            size: u32,
            reply: ReplyXattr,
        ) {
            self.drain_remote_updates();

            let Some(name) = name.to_str() else {
                reply.error(EINVAL);
                return;
            };

            match self.xattr_value_for_inode(ino, name) {
                Ok(Some(payload)) => Self::reply_xattr_payload(&payload, size, reply),
                Ok(None) => reply.error(ENODATA),
                Err(_error) => reply.error(ENOENT),
            }
        }

        fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
            self.drain_remote_updates();

            match self.xattr_name_list_for_inode(ino) {
                Ok(payload) => Self::reply_xattr_payload(&payload, size, reply),
                Err(_error) => reply.error(ENOENT),
            }
        }

        fn removexattr(&mut self, _req: &Request<'_>, _ino: u64, _name: &OsStr, reply: ReplyEmpty) {
            reply.error(EPERM);
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

    pub fn mount_fs_until_shutdown(config: &FuseMountConfig, fs: IronmeshFuseFs) -> Result<()> {
        if !Path::new(&config.mountpoint).exists() {
            return Err(anyhow!(
                "mountpoint does not exist: {}",
                config.mountpoint.display()
            ));
        }

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
        mount_fs_until_shutdown(config, fs)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Read;
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Clone, Default)]
        struct RecordingHydrator {
            full_calls: Arc<Mutex<Vec<String>>>,
            range_calls: Arc<Mutex<Vec<(String, u64, u64)>>>,
        }

        impl Hydrator for RecordingHydrator {
            fn hydrate(
                &self,
                path: &str,
                remote_version: &str,
                remote_content_hash: &str,
            ) -> Result<Vec<u8>> {
                self.full_calls
                    .lock()
                    .expect("full hydrate call log lock poisoned")
                    .push(format!("{path}:{remote_version}:{remote_content_hash}"));
                Ok(format!("full:{path}:{remote_version}:{remote_content_hash}").into_bytes())
            }

            fn hydrate_range(
                &self,
                path: &str,
                remote_version: &str,
                remote_content_hash: &str,
                offset: u64,
                length: u64,
            ) -> Result<Vec<u8>> {
                self.range_calls
                    .lock()
                    .expect("range hydrate call log lock poisoned")
                    .push((
                        format!("{path}:{remote_version}:{remote_content_hash}"),
                        offset,
                        length,
                    ));
                Ok(
                    format!(
                        "range:{path}:{remote_version}:{remote_content_hash}:{offset}:{length}"
                    )
                    .into_bytes(),
                )
            }
        }

        #[derive(Debug, Clone, PartialEq, Eq)]
        enum RecordingUploadOp {
            Upload {
                path: String,
                length: u64,
                bytes: Vec<u8>,
            },
            Rename {
                from: String,
                to: String,
                overwrite: bool,
            },
            Delete {
                path: String,
            },
        }

        #[derive(Debug, Clone, Default)]
        struct RecordingUploader {
            ops: Arc<Mutex<Vec<RecordingUploadOp>>>,
        }

        impl Uploader for RecordingUploader {
            fn upload_reader(
                &self,
                path: &str,
                _base_remote_version: Option<&str>,
                reader: &mut dyn Read,
                length: u64,
            ) -> Result<Option<String>> {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes)?;
                self.ops.lock().expect("upload op log lock poisoned").push(
                    RecordingUploadOp::Upload {
                        path: path.to_string(),
                        length,
                        bytes,
                    },
                );
                Ok(Some("recorded".to_string()))
            }

            fn rename_path(
                &self,
                from_path: &str,
                to_path: &str,
                overwrite: bool,
                _base_remote_version: Option<&str>,
            ) -> Result<()> {
                self.ops.lock().expect("upload op log lock poisoned").push(
                    RecordingUploadOp::Rename {
                        from: from_path.to_string(),
                        to: to_path.to_string(),
                        overwrite,
                    },
                );
                Ok(())
            }

            fn delete_path(&self, path: &str, _base_remote_version: Option<&str>) -> Result<()> {
                self.ops.lock().expect("upload op log lock poisoned").push(
                    RecordingUploadOp::Delete {
                        path: path.to_string(),
                    },
                );
                Ok(())
            }
        }

        #[test]
        fn placeholder_files_keep_remote_size_metadata() {
            let plan = FuseActionPlan {
                actions: vec![FuseAction::EnsurePlaceholder {
                    path: "docs/report.txt".to_string(),
                    remote_version: "v1".to_string(),
                    remote_content_hash: "h1".to_string(),
                    remote_size: Some(4096),
                }],
            };

            let fs = IronmeshFuseFs::from_action_plan(
                &plan,
                Box::new(DemoHydrator),
                Box::new(DemoUploader),
                None,
            );

            let report = fs
                .nodes
                .values()
                .find(|node| node.name == "report.txt")
                .expect("placeholder file missing");
            assert_eq!(report.size, 4096);
            assert_eq!(report.placeholder_version.as_deref(), Some("v1"));
            assert_eq!(report.placeholder_content_hash.as_deref(), Some("h1"));
        }

        #[test]
        fn placeholder_reads_use_ranged_hydration_and_preserve_placeholder_state() {
            let plan = FuseActionPlan {
                actions: vec![FuseAction::EnsurePlaceholder {
                    path: "docs/photo.jpg".to_string(),
                    remote_version: "v1".to_string(),
                    remote_content_hash: "h-photo".to_string(),
                    remote_size: Some(4096),
                }],
            };
            let hydrator = RecordingHydrator::default();
            let uploader = RecordingUploader::default();
            let mut fs = IronmeshFuseFs::from_action_plan(
                &plan,
                Box::new(hydrator.clone()),
                Box::new(uploader),
                None,
            );
            let photo_inode = fs
                .nodes
                .values()
                .find(|node| node.name == "photo.jpg")
                .expect("placeholder file missing")
                .inode;

            let bytes = fs
                .read_file_data(photo_inode, 9, 12)
                .expect("range read should work");
            assert_eq!(bytes, b"range:docs/photo.jpg:v1:h-photo:9:12");

            assert_eq!(
                hydrator
                    .range_calls
                    .lock()
                    .expect("range hydrate call log lock poisoned")
                    .as_slice(),
                &[(String::from("docs/photo.jpg:v1:h-photo"), 9, 12)]
            );
            assert!(
                hydrator
                    .full_calls
                    .lock()
                    .expect("full hydrate call log lock poisoned")
                    .is_empty()
            );
            assert_eq!(
                fs.nodes
                    .get(&photo_inode)
                    .and_then(|node| node.placeholder_version.as_deref()),
                Some("v1")
            );
            assert_eq!(
                fs.nodes
                    .get(&photo_inode)
                    .and_then(|node| node.placeholder_content_hash.as_deref()),
                Some("h-photo")
            );
            assert_eq!(fs.nodes.get(&photo_inode).map(|node| node.size), Some(4096));
        }

        #[test]
        fn dirty_zero_byte_handles_flush_empty_uploads() {
            let hydrator = RecordingHydrator::default();
            let uploader = RecordingUploader::default();
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan::default(),
                Box::new(hydrator),
                Box::new(uploader.clone()),
                None,
            );

            let inode = fs.next_inode();
            fs.nodes.insert(
                inode,
                FsNode::regular_file(inode, "empty.txt".to_string(), ROOT_INODE),
            );
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("empty.txt".to_string(), inode);

            let fh = fs.alloc_open_handle(inode, true, false);
            fs.open_handles
                .get_mut(&fh)
                .expect("handle should exist")
                .dirty = true;
            fs.flush_handle(inode, fh).expect("flush should succeed");

            assert_eq!(
                uploader
                    .ops
                    .lock()
                    .expect("upload op log lock poisoned")
                    .as_slice(),
                &[RecordingUploadOp::Upload {
                    path: "empty.txt".to_string(),
                    length: 0,
                    bytes: Vec::new(),
                }]
            );
        }

        #[test]
        fn conflict_actions_surface_xattrs_and_conflict_sidecars() {
            let hydrator = RecordingHydrator::default();
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan {
                    actions: vec![FuseAction::MarkConflict {
                        path: "albums/report.csv".to_string(),
                        local_version: Some("v-local".to_string()),
                        remote_version: Some("v-remote".to_string()),
                        remote_content_hash: Some("h-remote".to_string()),
                        remote_size: Some(2048),
                    }],
                },
                Box::new(hydrator.clone()),
                Box::new(RecordingUploader::default()),
                None,
            );

            let user_inode = fs
                .lookup_inode_by_relative_path("albums/report.csv")
                .expect("conflicted user file should exist");
            let sidecar_inode = fs
                .lookup_inode_by_relative_path(".ironmesh-conflicts/remote/albums/report.csv")
                .expect("conflict sidecar should exist");

            assert_eq!(
                fs.xattr_value_for_inode(user_inode, XATTR_STATE)
                    .expect("xattr lookup should work"),
                Some(b"placeholder,conflict".to_vec())
            );
            assert_eq!(
                fs.xattr_value_for_inode(user_inode, XATTR_CONFLICT_COPY)
                    .expect("xattr lookup should work"),
                Some(b".ironmesh-conflicts/remote/albums/report.csv".to_vec())
            );
            assert_eq!(
                fs.xattr_value_for_inode(sidecar_inode, XATTR_STATE)
                    .expect("xattr lookup should work"),
                Some(b"placeholder,conflict,conflict-copy,read-only".to_vec())
            );
            assert_eq!(
                fs.xattr_value_for_inode(sidecar_inode, XATTR_SOURCE_PATH)
                    .expect("xattr lookup should work"),
                Some(b"albums/report.csv".to_vec())
            );

            let sidecar_bytes = fs
                .read_file_data(sidecar_inode, 4, 7)
                .expect("sidecar range read should work");
            assert_eq!(
                sidecar_bytes,
                b"range:albums/report.csv:v-remote:h-remote:4:7"
            );
            assert_eq!(
                hydrator
                    .range_calls
                    .lock()
                    .expect("range hydrate call log lock poisoned")
                    .as_slice(),
                &[(String::from("albums/report.csv:v-remote:h-remote"), 4, 7)]
            );
        }

        #[test]
        fn dirty_state_xattr_tracks_open_write_handles() {
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan::default(),
                Box::new(RecordingHydrator::default()),
                Box::new(RecordingUploader::default()),
                None,
            );

            let inode = fs.next_inode();
            let mut file = FsNode::regular_file(inode, "dirty.txt".to_string(), ROOT_INODE);
            file.data = b"draft".to_vec();
            file.size = file.data.len() as u64;
            fs.nodes.insert(inode, file);
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("dirty.txt".to_string(), inode);

            let fh = fs.alloc_open_handle(inode, true, false);
            fs.open_handles
                .get_mut(&fh)
                .expect("handle should exist")
                .dirty = true;

            assert_eq!(
                fs.xattr_value_for_inode(inode, XATTR_STATE)
                    .expect("xattr lookup should work"),
                Some(b"dirty".to_vec())
            );
        }

        #[test]
        fn dirty_state_xattr_treats_enqueued_open_writes_as_dirty() {
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan::default(),
                Box::new(RecordingHydrator::default()),
                Box::new(RecordingUploader::default()),
                None,
            );

            let inode = fs.next_inode();
            fs.nodes.insert(
                inode,
                FsNode::regular_file(inode, "queued.txt".to_string(), ROOT_INODE),
            );
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("queued.txt".to_string(), inode);

            let fh = fs.alloc_open_handle(inode, true, true);
            assert_eq!(
                fs.xattr_value_for_inode(inode, XATTR_STATE)
                    .expect("xattr lookup should work"),
                Some(b"dirty".to_vec())
            );

            fs.open_handles.remove(&fh);
            assert_eq!(
                fs.xattr_value_for_inode(inode, XATTR_STATE)
                    .expect("xattr lookup should work"),
                Some(b"clean".to_vec())
            );
        }

        #[test]
        fn refresh_replaces_conflict_state_with_plain_placeholder() {
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan {
                    actions: vec![FuseAction::MarkConflict {
                        path: "albums/report.csv".to_string(),
                        local_version: Some("v-local".to_string()),
                        remote_version: Some("v-remote".to_string()),
                        remote_content_hash: Some("h-remote".to_string()),
                        remote_size: Some(2048),
                    }],
                },
                Box::new(RecordingHydrator::default()),
                Box::new(RecordingUploader::default()),
                None,
            );

            fs.apply_remote_action_plan_refresh(&FuseActionPlan {
                actions: vec![FuseAction::EnsurePlaceholder {
                    path: "albums/report.csv".to_string(),
                    remote_version: "v-remote-2".to_string(),
                    remote_content_hash: "h-remote-2".to_string(),
                    remote_size: Some(1024),
                }],
            });

            let user_inode = fs
                .lookup_inode_by_relative_path("albums/report.csv")
                .expect("refreshed file should exist");
            assert_eq!(
                fs.xattr_value_for_inode(user_inode, XATTR_STATE)
                    .expect("xattr lookup should work"),
                Some(b"placeholder".to_vec())
            );
            assert_eq!(
                fs.xattr_value_for_inode(user_inode, XATTR_CONFLICT_COPY)
                    .expect("xattr lookup should work"),
                None
            );
            assert!(
                fs.lookup_inode_by_relative_path(".ironmesh-conflicts/remote/albums/report.csv")
                    .is_none()
            );
        }

        #[test]
        fn refresh_does_not_clobber_unsynced_local_file_with_placeholder() {
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan::default(),
                Box::new(RecordingHydrator::default()),
                Box::new(RecordingUploader::default()),
                None,
            );

            let docs_inode = fs.ensure_directory("docs");
            let file_inode = fs.next_inode();
            let mut file = FsNode::regular_file(file_inode, "report.txt".to_string(), docs_inode);
            file.data = b"offline-local".to_vec();
            file.size = file.data.len() as u64;
            file.sync_metadata.remote_version = None;
            fs.nodes.insert(file_inode, file);
            fs.nodes
                .get_mut(&docs_inode)
                .expect("docs directory missing")
                .children
                .insert("report.txt".to_string(), file_inode);

            fs.apply_remote_action_plan_refresh(&FuseActionPlan {
                actions: vec![FuseAction::EnsurePlaceholder {
                    path: "docs/report.txt".to_string(),
                    remote_version: "v-remote".to_string(),
                    remote_content_hash: "h-remote".to_string(),
                    remote_size: Some(2048),
                }],
            });

            let file = fs.nodes.get(&file_inode).expect("local file should remain");
            assert_eq!(file.data, b"offline-local".to_vec());
            assert_eq!(file.placeholder_version, None);
            assert_eq!(file.sync_metadata.remote_version, None);
            assert_eq!(file.size, b"offline-local".len() as u64);
        }

        #[test]
        fn refresh_rebinds_remote_version_when_local_bytes_match_remote_content() {
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan::default(),
                Box::new(RecordingHydrator::default()),
                Box::new(RecordingUploader::default()),
                None,
            );

            let docs_inode = fs.ensure_directory("docs");
            let file_inode = fs.next_inode();
            let payload = b"synced".to_vec();
            let mut file = FsNode::regular_file(file_inode, "report.txt".to_string(), docs_inode);
            file.data = payload.clone();
            file.size = payload.len() as u64;
            file.sync_metadata.remote_version = None;
            fs.nodes.insert(file_inode, file);
            fs.nodes
                .get_mut(&docs_inode)
                .expect("docs directory missing")
                .children
                .insert("report.txt".to_string(), file_inode);

            fs.apply_remote_action_plan_refresh(&FuseActionPlan {
                actions: vec![FuseAction::EnsurePlaceholder {
                    path: "docs/report.txt".to_string(),
                    remote_version: "v-remote".to_string(),
                    remote_content_hash: blake3::hash(&payload).to_hex().to_string(),
                    remote_size: Some(payload.len() as u64),
                }],
            });

            let file = fs.nodes.get(&file_inode).expect("local file should remain");
            assert_eq!(file.data, payload);
            assert_eq!(file.placeholder_version, None);
            assert_eq!(
                file.sync_metadata.remote_version.as_deref(),
                Some("v-remote")
            );
        }

        #[test]
        fn rename_overwrites_replaceable_file_targets() {
            let hydrator = RecordingHydrator::default();
            let uploader = RecordingUploader::default();
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan::default(),
                Box::new(hydrator),
                Box::new(uploader.clone()),
                None,
            );

            let source_inode = fs.next_inode();
            let mut source = FsNode::regular_file(source_inode, "from.txt".to_string(), ROOT_INODE);
            source.data = b"source".to_vec();
            source.size = source.data.len() as u64;
            fs.nodes.insert(source_inode, source);
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("from.txt".to_string(), source_inode);

            let target_inode = fs.next_inode();
            let mut target = FsNode::regular_file(target_inode, "to.txt".to_string(), ROOT_INODE);
            target.data = b"target".to_vec();
            target.size = target.data.len() as u64;
            fs.nodes.insert(target_inode, target);
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("to.txt".to_string(), target_inode);

            fs.rename_entry(ROOT_INODE, "from.txt", ROOT_INODE, "to.txt", 0)
                .expect("rename should overwrite replaceable target");

            assert_eq!(
                fs.nodes
                    .get(&ROOT_INODE)
                    .expect("root inode missing")
                    .children
                    .get("to.txt")
                    .copied(),
                Some(source_inode)
            );
            assert!(!fs.nodes.contains_key(&target_inode));
            assert_eq!(
                fs.nodes.get(&source_inode).map(|node| node.name.as_str()),
                Some("to.txt")
            );
            assert_eq!(
                uploader
                    .ops
                    .lock()
                    .expect("upload op log lock poisoned")
                    .as_slice(),
                &[
                    RecordingUploadOp::Delete {
                        path: "to.txt".to_string(),
                    },
                    RecordingUploadOp::Rename {
                        from: "from.txt".to_string(),
                        to: "to.txt".to_string(),
                        overwrite: false,
                    },
                ]
            );
        }

        #[test]
        fn rename_overwrites_replaceable_empty_directory_targets() {
            let hydrator = RecordingHydrator::default();
            let uploader = RecordingUploader::default();
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan::default(),
                Box::new(hydrator),
                Box::new(uploader.clone()),
                None,
            );

            let source_dir_inode = fs.next_inode();
            fs.nodes.insert(
                source_dir_inode,
                FsNode::directory(source_dir_inode, "from".to_string(), ROOT_INODE),
            );
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("from".to_string(), source_dir_inode);

            let child_inode = fs.next_inode();
            let mut child =
                FsNode::regular_file(child_inode, "child.txt".to_string(), source_dir_inode);
            child.data = b"payload".to_vec();
            child.size = child.data.len() as u64;
            fs.nodes.insert(child_inode, child);
            fs.nodes
                .get_mut(&source_dir_inode)
                .expect("source directory missing")
                .children
                .insert("child.txt".to_string(), child_inode);

            let target_dir_inode = fs.next_inode();
            fs.nodes.insert(
                target_dir_inode,
                FsNode::directory(target_dir_inode, "to".to_string(), ROOT_INODE),
            );
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("to".to_string(), target_dir_inode);

            fs.rename_entry(ROOT_INODE, "from", ROOT_INODE, "to", 0)
                .expect("rename should overwrite replaceable directory target");

            assert_eq!(
                fs.nodes
                    .get(&ROOT_INODE)
                    .expect("root inode missing")
                    .children
                    .get("to")
                    .copied(),
                Some(source_dir_inode)
            );
            assert!(!fs.nodes.contains_key(&target_dir_inode));
            assert_eq!(
                fs.nodes
                    .get(&source_dir_inode)
                    .map(|node| node.name.as_str()),
                Some("to")
            );
            assert_eq!(
                fs.nodes.get(&child_inode).map(|node| node.parent_inode),
                Some(source_dir_inode)
            );
            assert_eq!(
                uploader
                    .ops
                    .lock()
                    .expect("upload op log lock poisoned")
                    .as_slice(),
                &[
                    RecordingUploadOp::Delete {
                        path: "to/".to_string(),
                    },
                    RecordingUploadOp::Rename {
                        from: "from/child.txt".to_string(),
                        to: "to/child.txt".to_string(),
                        overwrite: false,
                    },
                    RecordingUploadOp::Upload {
                        path: "to/".to_string(),
                        length: 0,
                        bytes: Vec::new(),
                    },
                    RecordingUploadOp::Delete {
                        path: "from/".to_string(),
                    },
                ]
            );
        }

        #[test]
        fn rename_rejects_non_empty_directory_targets() {
            let hydrator = RecordingHydrator::default();
            let uploader = RecordingUploader::default();
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan::default(),
                Box::new(hydrator),
                Box::new(uploader.clone()),
                None,
            );

            let source_dir_inode = fs.next_inode();
            fs.nodes.insert(
                source_dir_inode,
                FsNode::directory(source_dir_inode, "from".to_string(), ROOT_INODE),
            );
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("from".to_string(), source_dir_inode);

            let target_dir_inode = fs.next_inode();
            fs.nodes.insert(
                target_dir_inode,
                FsNode::directory(target_dir_inode, "to".to_string(), ROOT_INODE),
            );
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("to".to_string(), target_dir_inode);

            let target_child_inode = fs.next_inode();
            let target_child = FsNode::regular_file(
                target_child_inode,
                "nested.txt".to_string(),
                target_dir_inode,
            );
            fs.nodes.insert(target_child_inode, target_child);
            fs.nodes
                .get_mut(&target_dir_inode)
                .expect("target directory missing")
                .children
                .insert("nested.txt".to_string(), target_child_inode);

            let error = fs
                .rename_entry(ROOT_INODE, "from", ROOT_INODE, "to", 0)
                .expect_err("rename should reject non-empty directory targets");

            assert!(
                error
                    .to_string()
                    .contains("destination directory is not empty"),
                "unexpected rename error: {error:#}"
            );
            assert_eq!(
                fs.nodes
                    .get(&ROOT_INODE)
                    .expect("root inode missing")
                    .children
                    .get("from")
                    .copied(),
                Some(source_dir_inode)
            );
            assert_eq!(
                fs.nodes
                    .get(&ROOT_INODE)
                    .expect("root inode missing")
                    .children
                    .get("to")
                    .copied(),
                Some(target_dir_inode)
            );
            assert_eq!(
                uploader
                    .ops
                    .lock()
                    .expect("upload op log lock poisoned")
                    .len(),
                0
            );
        }

        #[test]
        fn rename_cycle_detection_blocks_descendant_targets() {
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan::default(),
                Box::new(RecordingHydrator::default()),
                Box::new(RecordingUploader::default()),
                None,
            );

            let source_dir_inode = fs.next_inode();
            fs.nodes.insert(
                source_dir_inode,
                FsNode::directory(source_dir_inode, "from".to_string(), ROOT_INODE),
            );
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("from".to_string(), source_dir_inode);

            let nested_dir_inode = fs.next_inode();
            fs.nodes.insert(
                nested_dir_inode,
                FsNode::directory(nested_dir_inode, "nested".to_string(), source_dir_inode),
            );
            fs.nodes
                .get_mut(&source_dir_inode)
                .expect("source directory missing")
                .children
                .insert("nested".to_string(), nested_dir_inode);

            let sibling_dir_inode = fs.next_inode();
            fs.nodes.insert(
                sibling_dir_inode,
                FsNode::directory(sibling_dir_inode, "other".to_string(), ROOT_INODE),
            );
            fs.nodes
                .get_mut(&ROOT_INODE)
                .expect("root inode missing")
                .children
                .insert("other".to_string(), sibling_dir_inode);

            assert!(
                fs.would_create_directory_cycle(source_dir_inode, nested_dir_inode)
                    .expect("cycle detection should succeed")
            );
            assert!(
                !fs.would_create_directory_cycle(source_dir_inode, sibling_dir_inode)
                    .expect("cycle detection should succeed")
            );
        }

        #[test]
        fn replay_actions_restore_pending_file_over_placeholder() {
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan {
                    actions: vec![FuseAction::EnsurePlaceholder {
                        path: "docs/report.txt".to_string(),
                        remote_version: "v1".to_string(),
                        remote_content_hash: "h1".to_string(),
                        remote_size: Some(1024),
                    }],
                },
                Box::new(RecordingHydrator::default()),
                Box::new(RecordingUploader::default()),
                None,
            );

            fs.apply_replay_actions(&[ReplayAction::UpsertFile {
                path: "docs/report.txt".to_string(),
                data: b"offline-local".to_vec(),
            }])
            .expect("replay should succeed");

            let inode = fs
                .lookup_inode_by_relative_path("docs/report.txt")
                .expect("file should exist after replay");
            let node = fs.nodes.get(&inode).expect("inode should exist");
            assert_eq!(node.data, b"offline-local".to_vec());
            assert_eq!(node.placeholder_version, None);
            assert_eq!(node.size, b"offline-local".len() as u64);
        }

        #[test]
        fn replay_actions_restore_queued_rename_and_delete() {
            let mut fs = IronmeshFuseFs::from_action_plan(
                &FuseActionPlan::default(),
                Box::new(RecordingHydrator::default()),
                Box::new(RecordingUploader::default()),
                None,
            );

            fs.apply_replay_actions(&[
                ReplayAction::UpsertFile {
                    path: "drafts/local.txt".to_string(),
                    data: b"payload".to_vec(),
                },
                ReplayAction::RenamePath {
                    from_path: "drafts/local.txt".to_string(),
                    to_path: "drafts/final.txt".to_string(),
                    overwrite: true,
                },
                ReplayAction::DeletePath {
                    path: "drafts/final.txt".to_string(),
                    directory: false,
                },
            ])
            .expect("replay should succeed");

            assert!(
                fs.lookup_inode_by_relative_path("drafts/local.txt")
                    .is_none(),
                "old path should be gone after replay rename"
            );
            assert!(
                fs.lookup_inode_by_relative_path("drafts/final.txt")
                    .is_none(),
                "delete replay should remove renamed file"
            );
        }

        #[test]
        fn open_only_hydrates_for_write_without_truncate() {
            assert!(!IronmeshFuseFs::should_hydrate_on_open(libc::O_RDONLY));
            assert!(!IronmeshFuseFs::should_hydrate_on_open(
                libc::O_WRONLY | libc::O_TRUNC
            ));
            assert!(IronmeshFuseFs::should_hydrate_on_open(libc::O_WRONLY));
            assert!(IronmeshFuseFs::should_hydrate_on_open(libc::O_RDWR));
        }

        #[test]
        fn no_op_size_updates_do_not_force_placeholder_hydration() {
            let placeholder = FsNode::placeholder_file(
                2,
                "report.txt".to_string(),
                ROOT_INODE,
                "v1".to_string(),
                "h1".to_string(),
                2048,
            );
            let hydrated = FsNode::regular_file(3, "hydrated.txt".to_string(), ROOT_INODE);

            assert!(!IronmeshFuseFs::should_hydrate_for_size_change(
                &placeholder,
                2048,
            ));
            assert!(IronmeshFuseFs::should_hydrate_for_size_change(
                &placeholder,
                1024,
            ));
            assert!(!IronmeshFuseFs::should_hydrate_for_size_change(
                &hydrated, 0,
            ));
        }
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
            remote: vec![NamespaceEntry::file_sized(
                "docs/readme.md",
                "v1",
                "h1",
                Some(123),
            )],
        };

        let plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.actions,
            vec![FuseAction::EnsurePlaceholder {
                path: "docs/readme.md".to_string(),
                remote_version: "v1".to_string(),
                remote_content_hash: "h1".to_string(),
                remote_size: Some(123),
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
                remote_content_hash: Some("h2".to_string()),
                remote_size: None,
            }],
        );
    }
}
