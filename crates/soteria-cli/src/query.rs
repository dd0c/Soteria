//! Filters shared by the history commands (`events`, `alerts`).

use chrono::{DateTime, SecondsFormat, Utc};
use soteria_core::{ExitStatus, Severity};

use crate::cli::TimeRange;
use crate::output::Failure;

/// Parse `--since`/`--until`: an RFC 3339 time, or an age such as "2h"
/// meaning that long ago. Returned in the database's timestamp format so it
/// compares correctly as text.
pub fn time_bound(value: Option<&str>, flag: &str) -> Result<Option<String>, Failure> {
    let Some(v) = value else {
        return Ok(None);
    };
    let t = if let Ok(t) = DateTime::parse_from_rfc3339(v) {
        t.with_timezone(&Utc)
    } else if let Ok(age) = humantime::parse_duration(v) {
        let age = chrono::Duration::from_std(age).map_err(|_| {
            Failure::new(ExitStatus::Usage, format!("{flag}: '{v}' is too long ago"))
        })?;
        Utc::now() - age
    } else {
        return Err(Failure::new(
            ExitStatus::Usage,
            format!("{flag}: '{v}' is neither an RFC 3339 time nor an age such as 30m or 2h"),
        ));
    };
    Ok(Some(t.to_rfc3339_opts(SecondsFormat::Millis, true)))
}

pub fn range(r: &TimeRange) -> Result<(Option<String>, Option<String>), Failure> {
    Ok((
        time_bound(r.since.as_deref(), "--since")?,
        time_bound(r.until.as_deref(), "--until")?,
    ))
}

/// `--severity X` means X and above. Returned as ",high,critical," for use
/// with `instr(?, ',' || severity || ',')`.
pub fn min_severity(value: Option<&str>) -> Result<Option<String>, Failure> {
    let Some(v) = value else {
        return Ok(None);
    };
    let min: Severity = v.parse().map_err(|e: soteria_core::ParseEnumError| {
        Failure::new(ExitStatus::Usage, e.to_string())
    })?;
    let list: Vec<&str> = Severity::ALL
        .into_iter()
        .filter(|s| *s >= min)
        .map(|s| s.as_str())
        .collect();
    Ok(Some(format!(",{},", list.join(","))))
}

pub fn internal(e: rusqlite::Error) -> Failure {
    Failure::new(ExitStatus::Internal, e.to_string())
}

pub fn path_text(b: Option<Vec<u8>>) -> Option<String> {
    b.map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Parse a JSON column, keeping malformed text visible rather than failing.
pub fn json_column(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::Value::String(text.to_owned()))
}
