//! UTC timestamps without chrono. Howard Hinnant's civil-from-days algorithm.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Unix time as UTC with the same microsecond precision as the recorder.
fn unix_to_utc_iso(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // days since 1970-01-01 -> civil date
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    let micros = elapsed.subsec_micros();
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{micros:06}Z")
}

pub fn now_utc_iso() -> String {
    unix_to_utc_iso(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        assert_eq!(
            unix_to_utc_iso(Duration::ZERO),
            "1970-01-01T00:00:00.000000Z"
        );
    }

    #[test]
    fn known_date() {
        // 2026-11-27T00:00:00Z = 1795737600
        assert_eq!(
            unix_to_utc_iso(Duration::from_secs(1_795_737_600)),
            "2026-11-27T00:00:00.000000Z"
        );
    }

    #[test]
    fn retains_order_within_one_second() {
        let first = unix_to_utc_iso(Duration::new(1_795_737_600, 5_000));
        let second = unix_to_utc_iso(Duration::new(1_795_737_600, 123_456_789));
        assert_eq!(first, "2026-11-27T00:00:00.000005Z");
        assert_eq!(second, "2026-11-27T00:00:00.123456Z");
        assert!(first < second);
    }
}
