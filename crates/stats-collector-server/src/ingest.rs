//! Payload validation for `POST /v1/ingest/hardware-reliability`.
//!
//! Deserialization here is deliberately tolerant, per
//! `docs/server-node-hardware-reliability-telemetry-strategy.md` Section 7: the request body is
//! accepted as an arbitrary `serde_json::Value` (rather than a strict typed struct with
//! `deny_unknown_fields`), and only the two fields this slice actually needs to make an
//! accept/reject decision (`schema_version`, `telemetry_subject_id`) are pulled out and checked.
//! Everything else — including fields not yet known about, or fields whose nested shape drifts
//! between node versions — is stored as-is in `raw_payload_json` without being rejected.
//!
//! Note on `country_code`: even though a client-supplied `country_code` field may be present in
//! the raw JSON body, it is never read or trusted here. Per Section 4.2, country code must be
//! derived server-side from the request's source IP, which this slice does not implement yet
//! (see `crate::storage`) — so the dedicated `country_code` column is always written as `NULL`,
//! regardless of what a payload claims.

use serde_json::Value;

/// Only `schema_version` this service currently understands.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// The subset of a payload this slice actually validates and acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPayload {
    pub schema_version: u32,
    pub telemetry_subject_id: String,
}

/// Why a payload was rejected as implausible. Maps 1:1 to a 400 response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadValidationError {
    NotAnObject,
    MissingSchemaVersion,
    UnsupportedSchemaVersion(u64),
    MissingTelemetrySubjectId,
}

impl PayloadValidationError {
    pub fn message(&self) -> String {
        match self {
            PayloadValidationError::NotAnObject => "payload must be a JSON object".to_string(),
            PayloadValidationError::MissingSchemaVersion => {
                "payload is missing a numeric \"schema_version\" field".to_string()
            }
            PayloadValidationError::UnsupportedSchemaVersion(version) => {
                format!(
                    "unsupported schema_version {version}; this service only understands {SUPPORTED_SCHEMA_VERSION}"
                )
            }
            PayloadValidationError::MissingTelemetrySubjectId => {
                "payload is missing a non-empty \"telemetry_subject_id\" field".to_string()
            }
        }
    }
}

/// Performs basic plausibility validation on an ingested payload: "this looks like a real
/// payload, not garbage" rather than full schema validation.
pub fn validate_payload(value: &Value) -> Result<ValidatedPayload, PayloadValidationError> {
    let object = value
        .as_object()
        .ok_or(PayloadValidationError::NotAnObject)?;

    let schema_version = object
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or(PayloadValidationError::MissingSchemaVersion)?;
    if schema_version != u64::from(SUPPORTED_SCHEMA_VERSION) {
        return Err(PayloadValidationError::UnsupportedSchemaVersion(
            schema_version,
        ));
    }

    let telemetry_subject_id = object
        .get("telemetry_subject_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(PayloadValidationError::MissingTelemetrySubjectId)?
        .to_string();

    Ok(ValidatedPayload {
        schema_version: schema_version as u32,
        telemetry_subject_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_minimal_valid_payload() {
        let payload = json!({
            "schema_version": 1,
            "telemetry_subject_id": "abc123",
        });
        let validated = validate_payload(&payload).expect("payload should validate");
        assert_eq!(validated.schema_version, 1);
        assert_eq!(validated.telemetry_subject_id, "abc123");
    }

    #[test]
    fn tolerates_unknown_extra_fields() {
        let payload = json!({
            "schema_version": 1,
            "telemetry_subject_id": "abc123",
            "some_future_field": {"nested": true},
            "another_new_thing": [1, 2, 3],
        });
        assert!(validate_payload(&payload).is_ok());
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let payload = json!({
            "schema_version": 99,
            "telemetry_subject_id": "abc123",
        });
        assert_eq!(
            validate_payload(&payload),
            Err(PayloadValidationError::UnsupportedSchemaVersion(99))
        );
    }

    #[test]
    fn rejects_missing_schema_version() {
        let payload = json!({ "telemetry_subject_id": "abc123" });
        assert_eq!(
            validate_payload(&payload),
            Err(PayloadValidationError::MissingSchemaVersion)
        );
    }

    #[test]
    fn rejects_missing_telemetry_subject_id() {
        let payload = json!({ "schema_version": 1 });
        assert_eq!(
            validate_payload(&payload),
            Err(PayloadValidationError::MissingTelemetrySubjectId)
        );
    }

    #[test]
    fn rejects_empty_telemetry_subject_id() {
        let payload = json!({ "schema_version": 1, "telemetry_subject_id": "   " });
        assert_eq!(
            validate_payload(&payload),
            Err(PayloadValidationError::MissingTelemetrySubjectId)
        );
    }

    #[test]
    fn rejects_non_object_payload() {
        let payload = json!([1, 2, 3]);
        assert_eq!(
            validate_payload(&payload),
            Err(PayloadValidationError::NotAnObject)
        );
    }
}
