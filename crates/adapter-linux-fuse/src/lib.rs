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
            SyncOperation::CreateDirectory { path } => FuseAction::EnsureDirectory {
                path: path.clone(),
            },
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