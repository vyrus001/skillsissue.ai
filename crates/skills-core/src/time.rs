use chrono::{DateTime, SecondsFormat, Utc};

use crate::{CoreError, Result};

/// Return the current instant in canonical UTC RFC3339 form with millisecond precision.
pub fn utc_now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parse an RFC3339 timestamp and require an explicit zero UTC offset.
pub fn parse_utc_rfc3339(value: &str) -> Result<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| CoreError::InvalidTimestamp(value.to_owned()))?;
    if parsed.offset().local_minus_utc() != 0 {
        return Err(CoreError::InvalidTimestamp(value.to_owned()));
    }
    Ok(parsed.with_timezone(&Utc))
}

pub fn is_valid_utc_rfc3339(value: &str) -> bool {
    parse_utc_rfc3339(value).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_utc_rfc3339() {
        let now = utc_now_rfc3339();
        assert!(now.ends_with('Z'));
        assert!(is_valid_utc_rfc3339(&now));
    }

    #[test]
    fn rejects_non_utc_offsets_and_invalid_values() {
        assert!(is_valid_utc_rfc3339("2026-07-13T20:00:00Z"));
        assert!(is_valid_utc_rfc3339("2026-07-13T20:00:00+00:00"));
        assert!(!is_valid_utc_rfc3339("2026-07-13T13:00:00-07:00"));
        assert!(!is_valid_utc_rfc3339("yesterday"));
    }
}
