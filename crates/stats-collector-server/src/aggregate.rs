//! K-anonymous fleet aggregation (doc Sections 4.3 and 5.3).
//!
//! Raw per-subject rows are condensed into publishable fleet statistics: distinct-subject counts
//! grouped by `hardware_profile_id`, by `country_code`, and by the cross of both. Any group with
//! fewer than the configured k-anonymity minimum distinct subjects is suppressed entirely, so a
//! rare hardware profile — or a rare profile in a low-population country — cannot be used to single
//! out one installation.
//!
//! A subject may have sent many batches over time; each subject is counted once, using its most
//! recent record (the caller passes rows most-recent-first).

use std::collections::HashMap;
use std::collections::HashSet;

use serde::Serialize;
use serde_json::Value;

use crate::storage::StoredRecord;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProfileCount {
    pub hardware_profile_id: String,
    pub subject_count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CountryCount {
    pub country_code: String,
    pub subject_count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CountryProfileCount {
    pub country_code: String,
    pub hardware_profile_id: String,
    pub subject_count: u64,
}

/// Publishable, k-anonymity-safe fleet summary.
#[derive(Debug, Clone, Serialize)]
pub struct FleetSummary {
    pub k_anonymity_min: u32,
    pub total_subjects: u64,
    pub by_hardware_profile: Vec<ProfileCount>,
    pub by_country: Vec<CountryCount>,
    pub by_country_and_profile: Vec<CountryProfileCount>,
}

/// One subject's current attributes, after deduping its historical rows.
struct SubjectAttributes {
    hardware_profile_id: Option<String>,
    country_code: Option<String>,
}

fn extract_hardware_profile_id(raw_payload_json: &str) -> Option<String> {
    serde_json::from_str::<Value>(raw_payload_json)
        .ok()
        .and_then(|value| {
            value
                .get("hardware_profile_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|value| !value.is_empty())
}

/// Builds the k-anonymous summary from raw rows (passed most-recent-first).
pub fn summarize(records: &[StoredRecord], k_anonymity_min: u32) -> FleetSummary {
    // Dedupe to one current record per subject: the first row seen per subject wins, since the
    // caller orders rows most-recent-first.
    let mut current: HashMap<&str, SubjectAttributes> = HashMap::new();
    for record in records {
        current
            .entry(record.telemetry_subject_id.as_str())
            .or_insert_with(|| SubjectAttributes {
                hardware_profile_id: extract_hardware_profile_id(&record.raw_payload_json),
                country_code: record.country_code.clone(),
            });
    }

    let total_subjects = current.len() as u64;

    // Distinct subjects per grouping key. Using sets keyed on subject id makes "distinct subject"
    // explicit and robust even though we already deduped above.
    let mut by_profile: HashMap<String, HashSet<&str>> = HashMap::new();
    let mut by_country: HashMap<String, HashSet<&str>> = HashMap::new();
    let mut by_country_profile: HashMap<(String, String), HashSet<&str>> = HashMap::new();

    for (subject, attrs) in &current {
        if let Some(profile) = &attrs.hardware_profile_id {
            by_profile
                .entry(profile.clone())
                .or_default()
                .insert(subject);
        }
        if let Some(country) = &attrs.country_code {
            by_country
                .entry(country.clone())
                .or_default()
                .insert(subject);
        }
        if let (Some(country), Some(profile)) = (&attrs.country_code, &attrs.hardware_profile_id) {
            by_country_profile
                .entry((country.clone(), profile.clone()))
                .or_default()
                .insert(subject);
        }
    }

    let threshold = u64::from(k_anonymity_min);

    let mut by_hardware_profile: Vec<ProfileCount> = by_profile
        .into_iter()
        .map(|(hardware_profile_id, subjects)| ProfileCount {
            hardware_profile_id,
            subject_count: subjects.len() as u64,
        })
        .filter(|entry| entry.subject_count >= threshold)
        .collect();
    by_hardware_profile.sort_by(|a, b| a.hardware_profile_id.cmp(&b.hardware_profile_id));

    let mut by_country_out: Vec<CountryCount> = by_country
        .into_iter()
        .map(|(country_code, subjects)| CountryCount {
            country_code,
            subject_count: subjects.len() as u64,
        })
        .filter(|entry| entry.subject_count >= threshold)
        .collect();
    by_country_out.sort_by(|a, b| a.country_code.cmp(&b.country_code));

    let mut by_country_and_profile: Vec<CountryProfileCount> = by_country_profile
        .into_iter()
        .map(
            |((country_code, hardware_profile_id), subjects)| CountryProfileCount {
                country_code,
                hardware_profile_id,
                subject_count: subjects.len() as u64,
            },
        )
        .filter(|entry| entry.subject_count >= threshold)
        .collect();
    by_country_and_profile.sort_by(|a, b| {
        a.country_code
            .cmp(&b.country_code)
            .then_with(|| a.hardware_profile_id.cmp(&b.hardware_profile_id))
    });

    FleetSummary {
        k_anonymity_min,
        total_subjects,
        by_hardware_profile,
        by_country: by_country_out,
        by_country_and_profile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: i64, subject: &str, profile: &str, country: Option<&str>) -> StoredRecord {
        StoredRecord {
            id,
            received_at_unix: id,
            telemetry_subject_id: subject.to_string(),
            schema_version: 1,
            country_code: country.map(str::to_string),
            raw_payload_json: format!("{{\"hardware_profile_id\":\"{profile}\"}}"),
        }
    }

    #[test]
    fn suppresses_groups_below_the_k_anonymity_threshold() {
        // 5 subjects on profile "common", 2 on profile "rare".
        let mut records = Vec::new();
        for i in 0..5 {
            records.push(record(i, &format!("s-common-{i}"), "common", Some("DE")));
        }
        for i in 0..2 {
            records.push(record(100 + i, &format!("s-rare-{i}"), "rare", Some("DE")));
        }

        let summary = summarize(&records, 5);
        assert_eq!(summary.total_subjects, 7);

        // "common" has 5 distinct subjects (>= 5) and is visible; "rare" has 2 and is suppressed.
        assert_eq!(summary.by_hardware_profile.len(), 1);
        assert_eq!(summary.by_hardware_profile[0].hardware_profile_id, "common");
        assert_eq!(summary.by_hardware_profile[0].subject_count, 5);

        // DE overall has 7 subjects (>= 5) and is visible.
        assert_eq!(summary.by_country.len(), 1);
        assert_eq!(summary.by_country[0].country_code, "DE");
        assert_eq!(summary.by_country[0].subject_count, 7);

        // Only (DE, common) meets the threshold in the cross-tab; (DE, rare) is suppressed.
        assert_eq!(summary.by_country_and_profile.len(), 1);
        assert_eq!(summary.by_country_and_profile[0].country_code, "DE");
        assert_eq!(
            summary.by_country_and_profile[0].hardware_profile_id,
            "common"
        );
    }

    #[test]
    fn counts_each_subject_once_across_repeated_batches() {
        // Same subject sent three batches; must count as one distinct subject.
        let records = vec![
            record(3, "s1", "p", Some("DE")),
            record(2, "s1", "p", Some("DE")),
            record(1, "s1", "p", Some("DE")),
        ];
        let summary = summarize(&records, 1);
        assert_eq!(summary.total_subjects, 1);
        assert_eq!(summary.by_hardware_profile[0].subject_count, 1);
    }

    #[test]
    fn rows_without_country_are_excluded_from_country_views_only() {
        let mut records = Vec::new();
        for i in 0..5 {
            records.push(record(i, &format!("s-{i}"), "p", None));
        }
        let summary = summarize(&records, 5);
        // Profile view still sees all 5, but there is no country to group by.
        assert_eq!(summary.by_hardware_profile.len(), 1);
        assert!(summary.by_country.is_empty());
        assert!(summary.by_country_and_profile.is_empty());
    }
}
