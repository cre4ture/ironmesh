use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinState {
    Unpinned,
    Pinned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HydrationState {
    Placeholder,
    Hydrated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceEntry {
    pub path: String,
    pub kind: EntryKind,
    pub version: Option<String>,
    pub content_hash: Option<String>,
}

impl NamespaceEntry {
    pub fn file(
        path: impl Into<String>,
        version: impl Into<String>,
        hash: impl Into<String>,
    ) -> Self {
        Self {
            path: normalize_path(path),
            kind: EntryKind::File,
            version: Some(version.into()),
            content_hash: Some(hash.into()),
        }
    }

    pub fn directory(path: impl Into<String>) -> Self {
        Self {
            path: normalize_path(path),
            kind: EntryKind::Directory,
            version: None,
            content_hash: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalEntry {
    pub namespace: NamespaceEntry,
    pub pin_state: PinState,
    pub hydration_state: HydrationState,
}

impl LocalEntry {
    pub fn new(
        namespace: NamespaceEntry,
        pin_state: PinState,
        hydration_state: HydrationState,
    ) -> Self {
        Self {
            namespace,
            pin_state,
            hydration_state,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SyncSnapshot {
    pub local: Vec<LocalEntry>,
    pub remote: Vec<NamespaceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOperation {
    EnsurePlaceholder {
        path: String,
        remote_version: String,
    },
    Hydrate {
        path: String,
        remote_version: String,
    },
    Upload {
        path: String,
        local_version: Option<String>,
    },
    Conflict {
        path: String,
        local_version: Option<String>,
        remote_version: Option<String>,
    },
    CreateDirectory {
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncPlan {
    pub operations: Vec<SyncOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPolicy {
    pub create_local_placeholders_for_remote_only: bool,
    pub treat_missing_remote_as_upload: bool,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        Self {
            create_local_placeholders_for_remote_only: true,
            treat_missing_remote_as_upload: true,
        }
    }
}

pub fn plan_sync(snapshot: &SyncSnapshot, policy: &SyncPolicy) -> SyncPlan {
    let local_map: BTreeMap<&str, &LocalEntry> = snapshot
        .local
        .iter()
        .map(|entry| (entry.namespace.path.as_str(), entry))
        .collect();
    let remote_map: BTreeMap<&str, &NamespaceEntry> = snapshot
        .remote
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();

    let mut all_paths: BTreeSet<&str> = BTreeSet::new();
    all_paths.extend(local_map.keys().copied());
    all_paths.extend(remote_map.keys().copied());

    let mut operations = Vec::new();

    for path in all_paths {
        let local = local_map.get(path).copied();
        let remote = remote_map.get(path).copied();

        match (local, remote) {
            (Some(local_entry), Some(remote_entry)) => {
                if local_entry.namespace.kind == EntryKind::Directory
                    || remote_entry.kind == EntryKind::Directory
                {
                    continue;
                }

                let same_version = local_entry.namespace.version == remote_entry.version
                    && local_entry.namespace.content_hash == remote_entry.content_hash;

                if same_version {
                    if local_entry.pin_state == PinState::Pinned
                        && local_entry.hydration_state == HydrationState::Placeholder
                    {
                        operations.push(SyncOperation::Hydrate {
                            path: path.to_string(),
                            remote_version: remote_entry.version.clone().unwrap_or_default(),
                        });
                    }
                    continue;
                }

                let local_has_data = local_entry.hydration_state == HydrationState::Hydrated;
                let local_has_version = local_entry.namespace.version.is_some();
                let remote_has_version = remote_entry.version.is_some();

                if local_has_data && local_has_version && remote_has_version {
                    operations.push(SyncOperation::Conflict {
                        path: path.to_string(),
                        local_version: local_entry.namespace.version.clone(),
                        remote_version: remote_entry.version.clone(),
                    });
                    continue;
                }

                operations.push(SyncOperation::Hydrate {
                    path: path.to_string(),
                    remote_version: remote_entry.version.clone().unwrap_or_default(),
                });
            }
            (Some(local_entry), None) => {
                if local_entry.namespace.kind == EntryKind::Directory {
                    continue;
                }
                if policy.treat_missing_remote_as_upload {
                    operations.push(SyncOperation::Upload {
                        path: path.to_string(),
                        local_version: local_entry.namespace.version.clone(),
                    });
                }
            }
            (None, Some(remote_entry)) => {
                if remote_entry.kind == EntryKind::Directory {
                    operations.push(SyncOperation::CreateDirectory {
                        path: path.to_string(),
                    });
                    continue;
                }

                if policy.create_local_placeholders_for_remote_only {
                    operations.push(SyncOperation::EnsurePlaceholder {
                        path: path.to_string(),
                        remote_version: remote_entry.version.clone().unwrap_or_default(),
                    });
                }
            }
            (None, None) => {}
        }
    }

    SyncPlan { operations }
}

fn normalize_path(path: impl Into<String>) -> String {
    let raw = path.into();
    raw.trim().trim_start_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_only_file_creates_placeholder() {
        let snapshot = SyncSnapshot {
            local: vec![],
            remote: vec![NamespaceEntry::file("docs/readme.txt", "v1", "h1")],
        };

        let plan = plan_sync(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.operations,
            vec![SyncOperation::EnsurePlaceholder {
                path: "docs/readme.txt".to_string(),
                remote_version: "v1".to_string(),
            }],
        );
    }

    #[test]
    fn local_only_file_uploads_when_policy_enabled() {
        let snapshot = SyncSnapshot {
            local: vec![LocalEntry::new(
                NamespaceEntry::file("notes/todo.md", "v-local", "h-local"),
                PinState::Pinned,
                HydrationState::Hydrated,
            )],
            remote: vec![],
        };

        let plan = plan_sync(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.operations,
            vec![SyncOperation::Upload {
                path: "notes/todo.md".to_string(),
                local_version: Some("v-local".to_string()),
            }],
        );
    }

    #[test]
    fn divergent_versions_raise_conflict() {
        let snapshot = SyncSnapshot {
            local: vec![LocalEntry::new(
                NamespaceEntry::file("report.csv", "v1-local", "h1"),
                PinState::Pinned,
                HydrationState::Hydrated,
            )],
            remote: vec![NamespaceEntry::file("report.csv", "v2-remote", "h2")],
        };

        let plan = plan_sync(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.operations,
            vec![SyncOperation::Conflict {
                path: "report.csv".to_string(),
                local_version: Some("v1-local".to_string()),
                remote_version: Some("v2-remote".to_string()),
            }],
        );
    }

    #[test]
    fn pinned_placeholder_hydrates_when_versions_match() {
        let snapshot = SyncSnapshot {
            local: vec![LocalEntry::new(
                NamespaceEntry::file("media/song.mp3", "v1", "h1"),
                PinState::Pinned,
                HydrationState::Placeholder,
            )],
            remote: vec![NamespaceEntry::file("media/song.mp3", "v1", "h1")],
        };

        let plan = plan_sync(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.operations,
            vec![SyncOperation::Hydrate {
                path: "media/song.mp3".to_string(),
                remote_version: "v1".to_string(),
            }],
        );
    }

    #[test]
    fn remote_directory_creates_local_directory() {
        let snapshot = SyncSnapshot {
            local: vec![],
            remote: vec![NamespaceEntry::directory("nested/dir")],
        };

        let plan = plan_sync(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.operations,
            vec![SyncOperation::CreateDirectory {
                path: "nested/dir".to_string(),
            }],
        );
    }
}
