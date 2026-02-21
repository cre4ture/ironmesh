use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use common::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Online,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub node_id: NodeId,
    pub public_url: String,
    pub labels: HashMap<String, String>,
    pub capacity_bytes: u64,
    pub free_bytes: u64,
    pub last_heartbeat_unix: u64,
    pub status: NodeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPolicy {
    pub replication_factor: usize,
    pub min_distinct_labels: HashMap<String, usize>,
}

impl Default for ReplicationPolicy {
    fn default() -> Self {
        let mut min_distinct_labels = HashMap::new();
        min_distinct_labels.insert("dc".to_string(), 1);
        min_distinct_labels.insert("rack".to_string(), 1);

        Self {
            replication_factor: 3,
            min_distinct_labels,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PlacementDecision {
    pub key: String,
    pub selected_nodes: Vec<NodeId>,
    pub replication_factor: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplicationPlanItem {
    pub key: String,
    pub desired_nodes: Vec<NodeId>,
    pub current_nodes: Vec<NodeId>,
    pub missing_nodes: Vec<NodeId>,
    pub extra_nodes: Vec<NodeId>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReplicationPlan {
    pub generated_at_unix: u64,
    pub under_replicated: usize,
    pub over_replicated: usize,
    pub items: Vec<ReplicationPlanItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterSummary {
    pub local_node_id: NodeId,
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub offline_nodes: usize,
    pub policy: ReplicationPolicy,
}

pub struct ClusterService {
    local_node: NodeId,
    heartbeat_timeout_secs: u64,
    policy: ReplicationPolicy,
    nodes: HashMap<NodeId, NodeDescriptor>,
    replicas_by_key: HashMap<String, HashSet<NodeId>>,
}

impl ClusterService {
    pub fn new(local_node: NodeId, policy: ReplicationPolicy, heartbeat_timeout_secs: u64) -> Self {
        Self {
            local_node,
            heartbeat_timeout_secs,
            policy,
            nodes: HashMap::new(),
            replicas_by_key: HashMap::new(),
        }
    }

    pub fn register_node(&mut self, mut descriptor: NodeDescriptor) {
        descriptor.last_heartbeat_unix = unix_ts();
        descriptor.status = NodeStatus::Online;
        self.nodes.insert(descriptor.node_id, descriptor);
    }

    pub fn remove_node(&mut self, node_id: NodeId) -> bool {
        if self.nodes.remove(&node_id).is_none() {
            return false;
        }

        self.replicas_by_key.retain(|_, replicas| {
            replicas.remove(&node_id);
            !replicas.is_empty()
        });

        true
    }

    pub fn touch_heartbeat(
        &mut self,
        node_id: NodeId,
        free_bytes: Option<u64>,
        capacity_bytes: Option<u64>,
        labels: Option<HashMap<String, String>>,
    ) -> bool {
        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.last_heartbeat_unix = unix_ts();
            node.status = NodeStatus::Online;
            if let Some(free) = free_bytes {
                node.free_bytes = free;
            }
            if let Some(capacity) = capacity_bytes {
                node.capacity_bytes = capacity;
            }
            if let Some(labels) = labels {
                node.labels = labels;
            }
            true
        } else {
            false
        }
    }

    pub fn list_nodes(&self) -> Vec<NodeDescriptor> {
        let mut nodes: Vec<_> = self.nodes.values().cloned().collect();
        nodes.sort_by_key(|node| node.node_id);
        nodes
    }

    pub fn summary(&self) -> ClusterSummary {
        let online_nodes = self
            .nodes
            .values()
            .filter(|node| node.status == NodeStatus::Online)
            .count();

        ClusterSummary {
            local_node_id: self.local_node,
            total_nodes: self.nodes.len(),
            online_nodes,
            offline_nodes: self.nodes.len().saturating_sub(online_nodes),
            policy: self.policy.clone(),
        }
    }

    pub fn metadata_commit_quorum_size(&self) -> usize {
        let total = self.nodes.len();
        if total == 0 {
            return 0;
        }
        (total / 2) + 1
    }

    pub fn has_metadata_commit_quorum(&self) -> bool {
        let required = self.metadata_commit_quorum_size();
        if required == 0 {
            return false;
        }

        let online = self
            .nodes
            .values()
            .filter(|node| node.status == NodeStatus::Online)
            .count();

        online >= required
    }

    pub fn update_health_and_detect_offline_transition(&mut self) -> bool {
        let now = unix_ts();
        let mut changed_to_offline = false;

        for node in self.nodes.values_mut() {
            if node.node_id == self.local_node {
                node.status = NodeStatus::Online;
                continue;
            }

            let stale = now.saturating_sub(node.last_heartbeat_unix) > self.heartbeat_timeout_secs;
            if stale && node.status != NodeStatus::Offline {
                node.status = NodeStatus::Offline;
                changed_to_offline = true;
            }
        }

        changed_to_offline
    }

    pub fn note_replica(&mut self, key: impl Into<String>, node_id: NodeId) {
        self.replicas_by_key
            .entry(key.into())
            .or_default()
            .insert(node_id);
    }

    pub fn import_replicas_by_key(&mut self, replicas: HashMap<String, Vec<NodeId>>) {
        self.replicas_by_key = replicas
            .into_iter()
            .map(|(key, nodes)| (key, nodes.into_iter().collect::<HashSet<_>>()))
            .collect();
    }

    pub fn export_replicas_by_key(&self) -> HashMap<String, Vec<NodeId>> {
        self.replicas_by_key
            .iter()
            .map(|(key, nodes)| {
                let mut ordered: Vec<NodeId> = nodes.iter().copied().collect();
                ordered.sort();
                (key.clone(), ordered)
            })
            .collect()
    }

    pub fn remove_replica(&mut self, key: &str, node_id: NodeId) {
        if let Some(nodes) = self.replicas_by_key.get_mut(key) {
            nodes.remove(&node_id);
            if nodes.is_empty() {
                self.replicas_by_key.remove(key);
            }
        }
    }

    pub fn placement_for_key(&self, key: &str) -> PlacementDecision {
        let selected_nodes = select_nodes_by_rendezvous(key, &self.nodes, &self.policy);
        PlacementDecision {
            key: key.to_string(),
            selected_nodes,
            replication_factor: self.policy.replication_factor,
        }
    }

    pub fn replication_plan(&self, keys: &[String]) -> ReplicationPlan {
        let mut items = Vec::new();

        for key in keys {
            let desired_nodes = select_nodes_by_rendezvous(key, &self.nodes, &self.policy);
            let desired_set: HashSet<_> = desired_nodes.iter().copied().collect();
            let target_replica_count = desired_nodes.len();

            let current_set = self.replicas_by_key.get(key).cloned().unwrap_or_default();
            let mut current_nodes: Vec<_> = current_set.iter().copied().collect();
            current_nodes.sort();

            let needed_replicas = target_replica_count.saturating_sub(current_set.len());
            let missing_nodes: Vec<_> = desired_nodes
                .iter()
                .copied()
                .filter(|node_id| !current_set.contains(node_id))
                .take(needed_replicas)
                .collect();

            let extra_nodes = if current_set.len() > target_replica_count {
                let mut extra_nodes: Vec<_> =
                    current_set.difference(&desired_set).copied().collect();
                extra_nodes.sort_by_key(|node_id| {
                    self.nodes
                        .get(node_id)
                        .map(|node| node.free_bytes)
                        .unwrap_or(0)
                });
                extra_nodes
            } else {
                Vec::new()
            };

            if !missing_nodes.is_empty() || !extra_nodes.is_empty() {
                items.push(ReplicationPlanItem {
                    key: key.clone(),
                    desired_nodes,
                    current_nodes,
                    missing_nodes,
                    extra_nodes,
                });
            }
        }

        let under_replicated = items
            .iter()
            .filter(|item| !item.missing_nodes.is_empty())
            .count();
        let over_replicated = items
            .iter()
            .filter(|item| !item.extra_nodes.is_empty())
            .count();

        ReplicationPlan {
            generated_at_unix: unix_ts(),
            under_replicated,
            over_replicated,
            items,
        }
    }
}

fn select_nodes_by_rendezvous(
    key: &str,
    nodes: &HashMap<NodeId, NodeDescriptor>,
    policy: &ReplicationPolicy,
) -> Vec<NodeId> {
    let mut ranked: Vec<(NodeId, u64)> = nodes
        .values()
        .filter(|node| node.status == NodeStatus::Online)
        .map(|node| {
            let score = rendezvous_score(key, node.node_id);
            (node.node_id, score)
        })
        .collect();

    ranked.sort_by_key(|entry| std::cmp::Reverse(entry.1));

    let mut selected = Vec::<NodeId>::new();
    let mut seen_label_values: HashMap<String, HashSet<String>> = HashMap::new();

    for (node_id, _) in &ranked {
        if selected.len() >= policy.replication_factor {
            break;
        }

        let node = match nodes.get(node_id) {
            Some(node) => node,
            None => continue,
        };

        let helps_constraint = policy
            .min_distinct_labels
            .iter()
            .any(|(label_key, min_needed)| {
                let current_count = seen_label_values
                    .get(label_key)
                    .map(HashSet::len)
                    .unwrap_or(0);

                if current_count >= *min_needed {
                    return false;
                }

                let value = node
                    .labels
                    .get(label_key)
                    .cloned()
                    .unwrap_or_else(|| "_unknown".to_string());
                !seen_label_values
                    .get(label_key)
                    .map(|values| values.contains(&value))
                    .unwrap_or(false)
            });

        if helps_constraint || selected.len() < policy.min_distinct_labels.len() {
            selected.push(*node_id);
            for label_key in policy.min_distinct_labels.keys() {
                let value = node
                    .labels
                    .get(label_key)
                    .cloned()
                    .unwrap_or_else(|| "_unknown".to_string());
                seen_label_values
                    .entry(label_key.clone())
                    .or_default()
                    .insert(value);
            }
        }
    }

    if selected.len() < policy.replication_factor {
        for (node_id, _) in ranked {
            if selected.len() >= policy.replication_factor {
                break;
            }
            if !selected.contains(&node_id) {
                selected.push(node_id);
            }
        }
    }

    selected
}

fn rendezvous_score(key: &str, node_id: NodeId) -> u64 {
    let seed = format!("{key}:{node_id}");
    let hash = blake3::hash(seed.as_bytes());
    let bytes = hash.as_bytes();

    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_node(id: NodeId, dc: &str, rack: &str, free_bytes: u64) -> NodeDescriptor {
        let mut labels = HashMap::new();
        labels.insert("dc".to_string(), dc.to_string());
        labels.insert("rack".to_string(), rack.to_string());

        NodeDescriptor {
            node_id: id,
            public_url: format!("http://{id}"),
            labels,
            capacity_bytes: 1_000,
            free_bytes,
            last_heartbeat_unix: unix_ts(),
            status: NodeStatus::Online,
        }
    }

    #[test]
    fn placement_is_deterministic_for_same_key_and_topology() {
        let local = NodeId::new_v4();
        let mut svc = ClusterService::new(local, ReplicationPolicy::default(), 60);

        let node_a = NodeId::new_v4();
        let node_b = NodeId::new_v4();
        let node_c = NodeId::new_v4();

        svc.register_node(mk_node(node_a, "dc-a", "rack-1", 900));
        svc.register_node(mk_node(node_b, "dc-a", "rack-2", 800));
        svc.register_node(mk_node(node_c, "dc-b", "rack-7", 700));

        let p1 = svc.placement_for_key("alpha");
        let p2 = svc.placement_for_key("alpha");
        assert_eq!(p1.selected_nodes, p2.selected_nodes);
    }

    #[test]
    fn replication_plan_detects_missing_and_extra() {
        let local = NodeId::new_v4();
        let policy = ReplicationPolicy {
            replication_factor: 2,
            ..ReplicationPolicy::default()
        };

        let mut svc = ClusterService::new(local, policy, 60);
        let node_a = NodeId::new_v4();
        let node_b = NodeId::new_v4();
        let node_c = NodeId::new_v4();

        svc.register_node(mk_node(node_a, "dc-a", "rack-1", 900));
        svc.register_node(mk_node(node_b, "dc-b", "rack-2", 800));
        svc.register_node(mk_node(node_c, "dc-c", "rack-3", 100));

        svc.note_replica("k", node_a);
        svc.note_replica("k", node_c);

        let placement = svc.placement_for_key("k");
        let expected_count = placement
            .selected_nodes
            .iter()
            .filter(|node_id| [node_a, node_c].contains(node_id))
            .count();

        let plan = svc.replication_plan(&["k".to_string()]);

        if expected_count == placement.selected_nodes.len() && expected_count == 2 {
            assert!(plan.items.is_empty());
        } else {
            assert_eq!(plan.items.len(), 1);
            let item = &plan.items[0];
            assert!(item.missing_nodes.len() <= 2);
            assert!(item.extra_nodes.len() <= 2);
            assert!(plan.under_replicated + plan.over_replicated >= 1);
        }
    }

    #[test]
    fn metadata_commit_quorum_uses_majority_rule() {
        let local = NodeId::new_v4();
        let mut svc = ClusterService::new(local, ReplicationPolicy::default(), 60);

        let node_a = NodeId::new_v4();
        let node_b = NodeId::new_v4();
        let node_c = NodeId::new_v4();

        svc.register_node(mk_node(node_a, "dc-a", "rack-1", 900));
        svc.register_node(mk_node(node_b, "dc-b", "rack-2", 800));
        svc.register_node(mk_node(node_c, "dc-c", "rack-3", 700));

        assert_eq!(svc.metadata_commit_quorum_size(), 2);
        assert!(svc.has_metadata_commit_quorum());

        if let Some(node) = svc.nodes.get_mut(&node_b) {
            node.status = NodeStatus::Offline;
        }

        assert!(svc.has_metadata_commit_quorum());

        if let Some(node) = svc.nodes.get_mut(&node_c) {
            node.status = NodeStatus::Offline;
        }

        assert!(!svc.has_metadata_commit_quorum());
    }

    #[test]
    fn metadata_commit_quorum_size_is_one_for_single_node() {
        let local = NodeId::new_v4();
        let mut svc = ClusterService::new(local, ReplicationPolicy::default(), 60);
        svc.register_node(mk_node(local, "dc-a", "rack-1", 500));

        assert_eq!(svc.metadata_commit_quorum_size(), 1);
        assert!(svc.has_metadata_commit_quorum());
    }

    #[test]
    fn remove_replica_clears_subject_membership() {
        let local = NodeId::new_v4();
        let mut svc = ClusterService::new(local, ReplicationPolicy::default(), 60);

        let node_a = NodeId::new_v4();
        svc.note_replica("subject-a", node_a);

        let before = svc.replication_plan(&["subject-a".to_string()]);
        assert_eq!(before.items.len(), 1);

        svc.remove_replica("subject-a", node_a);

        let after = svc.replication_plan(&["subject-a".to_string()]);
        assert!(after.items.is_empty());
    }

    #[test]
    fn import_export_replicas_roundtrip() {
        let local = NodeId::new_v4();
        let mut svc = ClusterService::new(local, ReplicationPolicy::default(), 60);

        let node_a = NodeId::new_v4();
        let node_b = NodeId::new_v4();

        let mut replicas = HashMap::new();
        replicas.insert("subject-a".to_string(), vec![node_b, node_a]);

        svc.import_replicas_by_key(replicas);
        let exported = svc.export_replicas_by_key();

        assert_eq!(exported.get("subject-a").map(Vec::len), Some(2));
        let nodes = exported.get("subject-a").unwrap();
        assert!(nodes.contains(&node_a));
        assert!(nodes.contains(&node_b));
    }

    #[test]
    fn update_health_keeps_local_node_online() {
        let local = NodeId::new_v4();
        let mut svc = ClusterService::new(local, ReplicationPolicy::default(), 0);
        svc.register_node(mk_node(local, "dc-a", "rack-1", 900));

        let transitioned = svc.update_health_and_detect_offline_transition();
        assert!(!transitioned);

        let local_node = svc
            .list_nodes()
            .into_iter()
            .find(|node| node.node_id == local)
            .expect("local node should exist");
        assert_eq!(local_node.status, NodeStatus::Online);
    }

    #[test]
    fn replication_plan_never_has_empty_desired_nodes_for_local_subject() {
        let local = NodeId::new_v4();
        let mut svc = ClusterService::new(
            local,
            ReplicationPolicy {
                replication_factor: 3,
                ..ReplicationPolicy::default()
            },
            0,
        );

        let remote_a = NodeId::new_v4();
        let remote_b = NodeId::new_v4();
        svc.register_node(mk_node(local, "dc-a", "rack-1", 900));
        svc.register_node(mk_node(remote_a, "dc-b", "rack-2", 800));
        svc.register_node(mk_node(remote_b, "dc-c", "rack-3", 700));
        svc.note_replica("hello", local);

        svc.update_health_and_detect_offline_transition();
        let plan = svc.replication_plan(&["hello".to_string()]);

        if let Some(item) = plan.items.iter().find(|item| item.key == "hello") {
            assert!(
                !item.desired_nodes.is_empty(),
                "desired nodes must include at least the local online node"
            );
        }
    }

    #[test]
    fn replication_plan_limits_backfill_when_current_replica_not_in_desired_set() {
        let local = NodeId::new_v4();
        let mut svc = ClusterService::new(
            local,
            ReplicationPolicy {
                replication_factor: 3,
                ..ReplicationPolicy::default()
            },
            0,
        );

        let node_a = NodeId::new_v4();
        let node_b = NodeId::new_v4();
        let node_c = NodeId::new_v4();
        let node_d = NodeId::new_v4();

        svc.register_node(mk_node(node_a, "dc-a", "rack-1", 900));
        svc.register_node(mk_node(node_b, "dc-b", "rack-2", 800));
        svc.register_node(mk_node(node_c, "dc-c", "rack-3", 700));
        svc.register_node(mk_node(node_d, "dc-d", "rack-4", 600));

        let mut selected_key = None;
        for idx in 0..10_000 {
            let candidate = format!("hello@ver-{idx}");
            let placement = svc.placement_for_key(&candidate);
            if placement.selected_nodes.len() == 3 && !placement.selected_nodes.contains(&node_a) {
                selected_key = Some(candidate);
                break;
            }
        }

        let key = selected_key.expect("failed to find key where desired set excludes node_a");
        svc.note_replica(&key, node_a);

        let plan = svc.replication_plan(std::slice::from_ref(&key));
        let item = plan
            .items
            .iter()
            .find(|item| item.key == key)
            .expect("expected replication plan item for key");

        assert_eq!(item.current_nodes, vec![node_a]);
        assert_eq!(item.missing_nodes.len(), 2);
        assert!(item.extra_nodes.is_empty());
    }

    #[test]
    fn remove_node_cleans_membership_and_replica_references() {
        let local = NodeId::new_v4();
        let mut svc = ClusterService::new(local, ReplicationPolicy::default(), 60);

        let node_a = NodeId::new_v4();
        let node_b = NodeId::new_v4();
        svc.register_node(mk_node(node_a, "dc-a", "rack-1", 900));
        svc.register_node(mk_node(node_b, "dc-b", "rack-2", 800));

        svc.note_replica("subject-a", node_a);
        svc.note_replica("subject-a", node_b);
        svc.note_replica("subject-b", node_a);

        assert!(svc.remove_node(node_a));
        assert!(!svc.nodes.contains_key(&node_a));

        let exported = svc.export_replicas_by_key();
        assert_eq!(exported.get("subject-a").map(Vec::len), Some(1));
        assert_eq!(exported.get("subject-b"), None);
        assert!(
            exported
                .get("subject-a")
                .map(|nodes| nodes.contains(&node_b))
                .unwrap_or(false)
        );
    }
}
