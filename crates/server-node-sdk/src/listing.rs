use super::*;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KeyListingPrefixMode {
    ExactStartsWith,
    PathBoundary,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KeyListingEntryKind {
    Object,
    CommonPrefix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyListingEntry {
    pub path: String,
    pub kind: KeyListingEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyListingPage {
    pub entries: Vec<KeyListingEntry>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct KeyListingCursor {
    scope: String,
    prefix_mode: KeyListingPrefixMode,
    prefix: String,
    delimiter: Option<String>,
    collapse_after: Option<usize>,
    last_path: String,
    last_kind: KeyListingEntryKind,
}

pub(crate) fn paginate_sorted_keys(
    sorted_keys: &[String],
    scope: &str,
    prefix_mode: KeyListingPrefixMode,
    prefix: &str,
    delimiter: Option<&str>,
    collapse_after: Option<usize>,
    cursor: Option<&str>,
    resume_after: Option<&str>,
    max_keys: usize,
) -> Result<KeyListingPage, String> {
    let delimiter = delimiter
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let max_keys = max_keys.max(1);
    let cursor_resume = match cursor {
        Some(token) => Some(decode_cursor(
            token,
            scope,
            prefix_mode,
            prefix,
            delimiter.as_deref(),
            collapse_after,
        )?),
        None => None,
    };
    let resume_after = if cursor_resume.is_none() {
        resume_after.map(ToString::to_string)
    } else {
        None
    };

    let mut entries = Vec::with_capacity(max_keys.min(sorted_keys.len()));
    let mut last_emitted_entry = None::<(String, KeyListingEntryKind)>;
    let mut has_more = false;

    for key in sorted_keys {
        let Some(remainder) = key_remainder_for_prefix(key, prefix, prefix_mode) else {
            continue;
        };
        let entry = entry_for_key(key, prefix, remainder, delimiter.as_deref(), collapse_after);
        if cursor_resume.as_ref().is_some_and(|resume| {
            entry.path.as_str() < resume.last_path.as_str()
                || (entry.path == resume.last_path
                    && entry_kind_rank(entry.kind) <= entry_kind_rank(resume.last_kind))
        }) {
            continue;
        }
        if resume_after
            .as_deref()
            .is_some_and(|after| entry.path.as_str() <= after)
        {
            continue;
        }
        if last_emitted_entry
            .as_ref()
            .is_some_and(|(previous_path, previous_kind)| {
                previous_path == &entry.path && *previous_kind == entry.kind
            })
        {
            continue;
        }
        if entries.len() >= max_keys {
            has_more = true;
            break;
        }
        last_emitted_entry = Some((entry.path.clone(), entry.kind));
        entries.push(entry);
    }

    let next_cursor = if has_more {
        entries.last().map(|entry| {
            encode_cursor(&KeyListingCursor {
                scope: scope.to_string(),
                prefix_mode,
                prefix: prefix.to_string(),
                delimiter,
                collapse_after,
                last_path: entry.path.clone(),
                last_kind: entry.kind,
            })
        })
    } else {
        None
    };

    Ok(KeyListingPage {
        entries,
        next_cursor,
        has_more,
    })
}

pub(crate) fn count_sorted_keys(
    sorted_keys: &[String],
    prefix_mode: KeyListingPrefixMode,
    prefix: &str,
    delimiter: Option<&str>,
    collapse_after: Option<usize>,
) -> usize {
    let delimiter = delimiter.map(str::trim).filter(|value| !value.is_empty());
    let mut count = 0usize;
    let mut last_emitted_entry = None::<(String, KeyListingEntryKind)>;

    for key in sorted_keys {
        let Some(remainder) = key_remainder_for_prefix(key, prefix, prefix_mode) else {
            continue;
        };
        let entry = entry_for_key(key, prefix, remainder, delimiter, collapse_after);
        if last_emitted_entry
            .as_ref()
            .is_some_and(|(previous_path, previous_kind)| {
                previous_path == &entry.path && *previous_kind == entry.kind
            })
        {
            continue;
        }
        last_emitted_entry = Some((entry.path.clone(), entry.kind));
        count += 1;
    }

    count
}

fn entry_for_key(
    key: &str,
    prefix: &str,
    remainder: &str,
    delimiter: Option<&str>,
    collapse_after: Option<usize>,
) -> KeyListingEntry {
    let Some(delimiter) = delimiter else {
        return KeyListingEntry {
            path: key.to_string(),
            kind: KeyListingEntryKind::Object,
        };
    };
    let Some(collapse_after) = collapse_after else {
        return KeyListingEntry {
            path: key.to_string(),
            kind: KeyListingEntryKind::Object,
        };
    };
    if collapse_after == 0 {
        return KeyListingEntry {
            path: key.to_string(),
            kind: KeyListingEntryKind::Object,
        };
    }

    let segments = split_remainder_segments(remainder, delimiter);
    if segments.len() <= collapse_after {
        return KeyListingEntry {
            path: key.to_string(),
            kind: KeyListingEntryKind::Object,
        };
    }

    let collapsed = segments[..collapse_after].concat();
    let path = if prefix.is_empty() {
        collapsed
    } else if prefix.ends_with(delimiter) {
        format!("{prefix}{collapsed}")
    } else {
        format!("{prefix}{delimiter}{collapsed}")
    };
    KeyListingEntry {
        path,
        kind: KeyListingEntryKind::CommonPrefix,
    }
}

fn split_remainder_segments<'a>(remainder: &'a str, delimiter: &str) -> Vec<&'a str> {
    let mut segments = Vec::new();
    let mut rest = remainder;

    while !rest.is_empty() {
        if let Some(index) = rest.find(delimiter) {
            let end = index + delimiter.len();
            segments.push(&rest[..end]);
            rest = &rest[end..];
        } else {
            segments.push(rest);
            break;
        }
    }

    segments
}

fn key_remainder_for_prefix<'a>(
    key: &'a str,
    prefix: &str,
    prefix_mode: KeyListingPrefixMode,
) -> Option<&'a str> {
    match prefix_mode {
        KeyListingPrefixMode::ExactStartsWith => {
            if prefix.is_empty() {
                Some(key)
            } else {
                key.strip_prefix(prefix)
            }
        }
        KeyListingPrefixMode::PathBoundary => store_index_remainder_for_prefix(key, prefix),
    }
}

fn encode_cursor(cursor: &KeyListingCursor) -> String {
    let bytes = serde_json::to_vec(cursor).expect("key listing cursor should serialize");
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

fn entry_kind_rank(kind: KeyListingEntryKind) -> u8 {
    match kind {
        KeyListingEntryKind::Object => 0,
        KeyListingEntryKind::CommonPrefix => 1,
    }
}

fn decode_cursor(
    token: &str,
    expected_scope: &str,
    expected_prefix_mode: KeyListingPrefixMode,
    expected_prefix: &str,
    expected_delimiter: Option<&str>,
    expected_collapse_after: Option<usize>,
) -> Result<KeyListingCursor, String> {
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| "the continuation token could not be decoded".to_string())?;
    let cursor = serde_json::from_slice::<KeyListingCursor>(&decoded)
        .map_err(|_| "the continuation token payload was invalid".to_string())?;

    if cursor.scope != expected_scope
        || cursor.prefix_mode != expected_prefix_mode
        || cursor.prefix != expected_prefix
        || cursor.delimiter.as_deref() != expected_delimiter
        || cursor.collapse_after != expected_collapse_after
    {
        return Err(
            "the continuation token does not match the requested listing parameters".to_string(),
        );
    }

    Ok(cursor)
}
