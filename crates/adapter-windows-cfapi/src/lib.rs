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
        map_sync_plan_to_cfapi_actions(&sync_plan)
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
    },
    HydrateOnDemand {
        path: String,
        remote_version: String,
    },
    QueueUploadOnClose {
        path: String,
        local_version: Option<String>,
    },
    MarkConflict {
        path: String,
        local_version: Option<String>,
        remote_version: Option<String>,
    },
}

pub fn map_sync_plan_to_cfapi_actions(sync_plan: &SyncPlan) -> CfapiActionPlan {
    let mut actions = Vec::with_capacity(sync_plan.operations.len());

    for operation in &sync_plan.operations {
        let mapped = match operation {
            SyncOperation::CreateDirectory { path } => {
                CfapiAction::EnsureDirectory { path: path.clone() }
            }
            SyncOperation::EnsurePlaceholder {
                path,
                remote_version,
            } => CfapiAction::EnsurePlaceholder {
                path: path.clone(),
                remote_version: remote_version.clone(),
            },
            SyncOperation::Hydrate {
                path,
                remote_version,
            } => CfapiAction::HydrateOnDemand {
                path: path.clone(),
                remote_version: remote_version.clone(),
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
            } => CfapiAction::MarkConflict {
                path: path.clone(),
                local_version: local_version.clone(),
                remote_version: remote_version.clone(),
            },
        };

        actions.push(mapped);
    }

    CfapiActionPlan { actions }
}

pub mod runtime;

pub mod live;

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
