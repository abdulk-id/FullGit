//! Reading fields out of an operation's JSON payload. Errors are rejection
//! reasons, for [`crate::Model::apply`].

use git2::Oid;
use serde_json::Value;

/// Reads a required string field from `payload`.
pub fn required_string<'a>(payload: &'a Value, key: &str) -> Result<&'a str, String> {
    optional_string(payload, key)?.ok_or_else(|| format!("missing {key}"))
}

/// A string field that may be absent, but not of another type.
pub fn optional_string<'a>(payload: &'a Value, key: &str) -> Result<Option<&'a str>, String> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{key} is not a string")),
    }
}

/// Reads a required object-id field (40 hex characters) from `payload`.
pub fn required_oid(payload: &Value, key: &str) -> Result<Oid, String> {
    parse_oid(required_string(payload, key)?)
}

/// Parses a full 40-character git object id.
pub fn parse_oid(s: &str) -> Result<Oid, String> {
    if s.len() != 40 {
        return Err(format!("{s} is not a full object id"));
    }
    Oid::from_str(s).map_err(|e| format!("{s}: {e}"))
}
