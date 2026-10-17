//! Reading fields out of an operation's JSON payload. Errors are rejection
//! reasons, for [`crate::Model::apply`].

use git2::Oid;
use serde_json::Value;

pub fn str<'a>(payload: &'a Value, key: &str) -> Result<&'a str, String> {
    opt_str(payload, key)?.ok_or_else(|| format!("missing {key}"))
}

/// A string field that may be absent, but not of another type.
pub fn opt_str<'a>(payload: &'a Value, key: &str) -> Result<Option<&'a str>, String> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{key} is not a string")),
    }
}

pub fn oid(payload: &Value, key: &str) -> Result<Oid, String> {
    parse_oid(str(payload, key)?)
}

pub fn parse_oid(s: &str) -> Result<Oid, String> {
    if s.len() != 40 {
        return Err(format!("{s} is not a full object id"));
    }
    Oid::from_str(s).map_err(|e| format!("{s}: {e}"))
}
