//! Strict offline RFC3339 parser for PayPal webhook transmission timestamps.
//! Explicit offsets, Gregorian date validity, and 1..9 fractional digits are
//! required; output is Unix nanoseconds for exact replay-window boundaries.

const NANOS_PER_SECOND: i128 = 1_000_000_000;

fn digits(bytes: &[u8], begin: usize, len: usize) -> Option<i64> {
    let mut value = 0_i64;
    for &b in bytes.get(begin..begin.checked_add(len)?)? {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value * 10 + i64::from(b - b'0');
    }
    Some(value)
}

pub(crate) fn parse_rfc3339_unix_nanos(value: &str) -> Option<i128> {
    let b = value.as_bytes();
    if b.len() < 20
        || b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || b.get(10) != Some(&b'T')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    let year = digits(b, 0, 4)?;
    let month = digits(b, 5, 2)?;
    let day = digits(b, 8, 2)?;
    let hour = digits(b, 11, 2)?;
    let minute = digits(b, 14, 2)?;
    let second = digits(b, 17, 2)?;
    if year == 0 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > max_day {
        return None;
    }

    let mut at = 19;
    let mut fractional_nanos = 0_i128;
    if b.get(at) == Some(&b'.') {
        at += 1;
        let first_digit = at;
        while b.get(at).is_some_and(u8::is_ascii_digit) {
            if at - first_digit >= 9 {
                return None;
            }
            fractional_nanos = fractional_nanos * 10 + i128::from(b[at] - b'0');
            at += 1;
        }
        let count = at - first_digit;
        if count == 0 {
            return None;
        }
        for _ in count..9 {
            fractional_nanos *= 10;
        }
    }

    let zone = *b.get(at)?;
    let offset_seconds = match zone {
        b'Z' if b.len() == at + 1 => 0_i64,
        b'+' | b'-' if b.len() == at + 6 && b.get(at + 3) == Some(&b':') => {
            let oh = digits(b, at + 1, 2)?;
            let om = digits(b, at + 4, 2)?;
            if oh > 23 || om > 59 {
                return None;
            }
            let offset = oh * 3600 + om * 60;
            if zone == b'+' {
                offset
            } else {
                -offset
            }
        }
        _ => return None,
    };

    // Civil Gregorian date to days since Unix epoch, valid for 0001..9999.
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * shifted_month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs =
        i128::from(days) * 86_400 + i128::from(hour * 3600 + minute * 60 + second - offset_seconds);
    Some(secs * NANOS_PER_SECOND + fractional_nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_epoch_offsets_fractional_seconds_and_leap_days() {
        assert_eq!(parse_rfc3339_unix_nanos("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_unix_nanos("1969-12-31T23:59:59Z"),
            Some(-1_000_000_000)
        );
        assert_eq!(
            parse_rfc3339_unix_nanos("1970-01-01T00:00:00.000000001Z"),
            Some(1)
        );
        assert_eq!(
            parse_rfc3339_unix_nanos("1970-01-01T00:00:00.1Z"),
            Some(100_000_000)
        );
        assert_eq!(
            parse_rfc3339_unix_nanos("1970-01-01T01:30:00+01:30"),
            Some(0)
        );
        assert_eq!(
            parse_rfc3339_unix_nanos("1969-12-31T22:30:00-01:30"),
            Some(0)
        );
        assert_eq!(
            parse_rfc3339_unix_nanos("2000-02-29T00:00:00Z"),
            Some(951_782_400_000_000_000)
        );
    }

    #[test]
    fn malformed_calendar_zone_and_precision_fail_closed() {
        for bad in [
            "",
            "1970-01-01T00:00:00",
            "1970-01-01t00:00:00Z",
            "1970-01-01T00:00:00z",
            "1970-01-01T00:00:00Zgarbage",
            "1970-01-01T00:00:00+00",
            "1970-01-01T00:00:00+24:00",
            "1970-01-01T00:00:00+00:60",
            "1970-01-01T00:00:00+00:00Z",
            "1970-01-01T00:00:00.1.0Z",
            "1970-01-01T00:00:00.Z",
            "1970-01-01T00:00:00.0000000001Z",
            "1970-01-01T00:00:60Z",
            "1900-02-29T00:00:00Z",
            "2001-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "0000-01-01T00:00:00Z",
            "10000-01-01T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:00+0a:00",
            "2026-01-01T00:00:00+00:0a",
            "2026-01-01T00:00:00+00:00\n",
        ] {
            assert_eq!(parse_rfc3339_unix_nanos(bad), None, "must reject {bad:?}");
        }
    }
}
