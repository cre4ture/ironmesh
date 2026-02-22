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

#[cfg(feature = "fuse-runtime")]
pub mod runtime {
    use super::FuseActionPlan;
    use crate::FuseAction;
    use anyhow::{Result, anyhow};
    use fuser::{
        FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory,
        ReplyEntry, ReplyOpen, Request,
    };
    use libc::{EIO, ENOENT, ENOSYS};
    use std::collections::{BTreeMap, HashMap};
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};
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
                MountOption::RO,
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

        fn attr(&self) -> FileAttr {
            let (perm, nlink) = match self.kind {
                FileType::Directory => (0o755, 2),
                _ => (0o444, 1),
            };

            FileAttr {
                ino: self.inode,
                size: self.size,
                blocks: 1,
                atime: self.modified_at,
                mtime: self.modified_at,
                ctime: self.modified_at,
                crtime: self.modified_at,
                kind: self.kind,
                perm,
                nlink,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: 4096,
                flags: 0,
            }
        }
    }

    pub struct IronmeshFuseFs {
        nodes: HashMap<u64, FsNode>,
        hydrator: Box<dyn Hydrator>,
    }

    impl IronmeshFuseFs {
        pub fn from_action_plan(action_plan: &FuseActionPlan, hydrator: Box<dyn Hydrator>) -> Self {
            let mut fs = Self {
                nodes: HashMap::new(),
                hydrator,
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
            reply.entry(&TTL, &child.attr(), 0);
        }

        fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
            let Some(node) = self.nodes.get(&ino) else {
                reply.error(ENOENT);
                return;
            };
            reply.attr(&TTL, &node.attr());
        }

        fn readdir(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            offset: i64,
            mut reply: ReplyDirectory,
        ) {
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

        fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
            let Some(node) = self.nodes.get(&ino) else {
                reply.error(ENOENT);
                return;
            };

            if node.kind != FileType::RegularFile {
                reply.error(ENOENT);
                return;
            }

            let write_flags = libc::O_WRONLY | libc::O_RDWR | libc::O_APPEND | libc::O_TRUNC;
            if (flags & write_flags) != 0 {
                reply.error(ENOSYS);
                return;
            }

            reply.opened(0, 0);
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
    }

    pub fn mount_action_plan(
        config: &FuseMountConfig,
        action_plan: FuseActionPlan,
        hydrator: Box<dyn Hydrator>,
    ) -> Result<()> {
        if !Path::new(&config.mountpoint).exists() {
            return Err(anyhow!(
                "mountpoint does not exist: {}",
                config.mountpoint.display()
            ));
        }

        let fs = IronmeshFuseFs::from_action_plan(&action_plan, hydrator);
        fuser::mount2(fs, &config.mountpoint, &config.mount_options())?;
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
