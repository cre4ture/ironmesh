use std::collections::HashMap;

use sync_core::{SyncOperation, SyncPlan, SyncPolicy, SyncSnapshot, plan_sync};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCfapiAdapter {
    pub sync_root_name: String,
}

impl WindowsCfapiAdapter {
    pub fn new(sync_root_name: impl Into<String>) -> Self {
        Self {
            sync_root_name: sync_root_name.into(),
        }
    }

    pub fn plan_actions(&self, snapshot: &SyncSnapshot, policy: &SyncPolicy) -> CfapiActionPlan {
        let sync_plan = plan_sync(snapshot, policy);
        let remote_sizes_by_path = snapshot
            .remote
            .iter()
            .filter_map(|entry| entry.size_bytes.map(|size| (entry.path.clone(), size)))
            .collect::<HashMap<_, _>>();
        map_sync_plan_to_cfapi_actions(&sync_plan, &remote_sizes_by_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CfapiActionPlan {
    pub actions: Vec<CfapiAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfapiAction {
    EnsureDirectory {
        path: String,
    },
    EnsurePlaceholder {
        path: String,
        remote_version: String,
        remote_size: Option<u64>,
    },
    HydrateOnDemand {
        path: String,
        remote_version: String,
        remote_size: Option<u64>,
    },
    QueueUploadOnClose {
        path: String,
        local_version: Option<String>,
    },
    MarkConflict {
        path: String,
        local_version: Option<String>,
        remote_version: Option<String>,
        remote_size: Option<u64>,
    },
}

pub fn map_sync_plan_to_cfapi_actions(
    sync_plan: &SyncPlan,
    remote_sizes_by_path: &HashMap<String, u64>,
) -> CfapiActionPlan {
    let mut actions = Vec::with_capacity(sync_plan.operations.len());

    for operation in &sync_plan.operations {
        let mapped = match operation {
            SyncOperation::CreateDirectory { path } => {
                CfapiAction::EnsureDirectory { path: path.clone() }
            }
            SyncOperation::EnsurePlaceholder {
                path,
                remote_version,
                ..
            } => CfapiAction::EnsurePlaceholder {
                path: path.clone(),
                remote_version: remote_version.clone(),
                remote_size: remote_sizes_by_path.get(path).copied(),
            },
            SyncOperation::Hydrate {
                path,
                remote_version,
                ..
            } => CfapiAction::HydrateOnDemand {
                path: path.clone(),
                remote_version: remote_version.clone(),
                remote_size: remote_sizes_by_path.get(path).copied(),
            },
            SyncOperation::Upload {
                path,
                local_version,
            } => CfapiAction::QueueUploadOnClose {
                path: path.clone(),
                local_version: local_version.clone(),
            },
            SyncOperation::Conflict {
                path,
                local_version,
                remote_version,
                ..
            } => CfapiAction::MarkConflict {
                path: path.clone(),
                local_version: local_version.clone(),
                remote_version: remote_version.clone(),
                remote_size: remote_sizes_by_path.get(path).copied(),
            },
        };

        actions.push(mapped);
    }

    CfapiActionPlan { actions }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync_core::{HydrationState, LocalEntry, NamespaceEntry, PinState};

    #[test]
    fn adapter_maps_remote_only_file_to_placeholder_action() {
        let adapter = WindowsCfapiAdapter::new("Ironmesh");
        let snapshot = SyncSnapshot {
            local: vec![],
            remote: vec![NamespaceEntry::file("docs/readme.md", "v1", "h1")],
        };

        let plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.actions,
            vec![CfapiAction::EnsurePlaceholder {
                path: "docs/readme.md".to_string(),
                remote_version: "v1".to_string(),
                remote_size: None,
            }],
        );
    }

    #[test]
    fn adapter_maps_local_only_file_to_upload_on_close() {
        let adapter = WindowsCfapiAdapter::new("Ironmesh");
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
            vec![CfapiAction::QueueUploadOnClose {
                path: "notes/task.txt".to_string(),
                local_version: Some("v-local".to_string()),
            }],
        );
    }

    #[test]
    fn adapter_maps_divergence_to_conflict_action() {
        let adapter = WindowsCfapiAdapter::new("Ironmesh");
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
            vec![CfapiAction::MarkConflict {
                path: "report.csv".to_string(),
                local_version: Some("v-local".to_string()),
                remote_version: Some("v-remote".to_string()),
                remote_size: None,
            }],
        );
    }

    #[test]
    fn adapter_carries_remote_size_for_file_actions() {
        let adapter = WindowsCfapiAdapter::new("Ironmesh");
        let snapshot = SyncSnapshot {
            local: vec![],
            remote: vec![NamespaceEntry::file_sized(
                "docs/readme.md",
                "v1",
                "h1",
                Some(42),
            )],
        };

        let plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.actions,
            vec![CfapiAction::EnsurePlaceholder {
                path: "docs/readme.md".to_string(),
                remote_version: "v1".to_string(),
                remote_size: Some(42),
            }],
        );
    }

    #[test]
    fn adapter_maps_remote_directory_to_ensure_directory() {
        let adapter = WindowsCfapiAdapter::new("Ironmesh");
        let snapshot = SyncSnapshot {
            local: vec![],
            remote: vec![NamespaceEntry::directory("nested/dir")],
        };

        let plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

        assert_eq!(
            plan.actions,
            vec![CfapiAction::EnsureDirectory {
                path: "nested/dir".to_string(),
            }],
        );
    }
}
