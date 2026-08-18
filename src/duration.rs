//! A minimal ISO 8601 duration parser for `checkpoint_cadence` (core spec §7.3).
//!
//! # Scope and a reported assumption
//!
//! The profile requires `checkpoint_cadence` to be an ISO 8601 duration but does not fix
//! which subset. This parser accepts the standard `P[n"Y"][n"M"][n"D"]["T"[n"H"][n"M"][n"S"]]`
//! form and the alternative `P[n"W"]` (weeks) form, both integer-only in the calendar part and
//! allowing a decimal `S` (fractional seconds). Calendar components — `Y` (years) and `M`
//! (months) before `T` — have no fixed length in ISO 8601 itself; this parser converts them
//! using fixed civil-calendar-free approximations (365 days/year, 30 days/month), which is
//! adequate for cadence values expressed in the smaller units a checkpoint cadence realistically
//! uses (seconds through days) but not exact for a cadence declared in years or months. Reported
//! as an implementer's assumption, not a specification quotation.

use crate::error::{MirrorError, MirrorResult};

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_DAY: u64 = 86_400;
const SECONDS_PER_WEEK: u64 = 7 * SECONDS_PER_DAY;
const SECONDS_PER_MONTH_APPROX: u64 = 30 * SECONDS_PER_DAY;
const SECONDS_PER_YEAR_APPROX: u64 = 365 * SECONDS_PER_DAY;

/// Parse an ISO 8601 duration to a total nanosecond count.
///
/// # Errors
///
/// Returns [`MirrorError::BadDuration`] if `value` is not a well-formed duration of the
/// supported subset (see module docs), or if the total overflows `u64` nanoseconds.
pub fn parse_iso8601_duration_nanos(value: &str) -> MirrorResult<u64> {
    let bad = || MirrorError::BadDuration { value: value.to_owned() };
    let rest = value.strip_prefix('P').ok_or_else(bad)?;
    if rest.is_empty() {
        return Err(bad());
    }

    // Weeks are an alternative, exclusive form: "P<n>W".
    if let Some(weeks) = rest.strip_suffix('W') {
        let weeks: u64 = weeks.parse().map_err(|_| bad())?;
        return weeks
            .checked_mul(SECONDS_PER_WEEK)
            .and_then(|s| s.checked_mul(NANOS_PER_SECOND))
            .ok_or_else(bad);
    }

    let (date_part, time_part) = match rest.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (rest, None),
    };

    let mut total_seconds: u64 = 0;
    let mut cursor = date_part;
    for (unit, seconds_per_unit) in
        [('Y', SECONDS_PER_YEAR_APPROX), ('M', SECONDS_PER_MONTH_APPROX), ('D', SECONDS_PER_DAY)]
    {
        if let Some((n, remainder)) = take_component(cursor, unit)? {
            total_seconds = total_seconds
                .checked_add(n.checked_mul(seconds_per_unit).ok_or_else(bad)?)
                .ok_or_else(bad)?;
            cursor = remainder;
        }
    }
    if !cursor.is_empty() {
        return Err(bad());
    }

    let mut extra_nanos: u64 = 0;
    if let Some(time_part) = time_part {
        if time_part.is_empty() {
            return Err(bad());
        }
        let mut cursor = time_part;
        for (unit, seconds_per_unit) in [('H', SECONDS_PER_HOUR), ('M', SECONDS_PER_MINUTE)] {
            if let Some((n, remainder)) = take_component(cursor, unit)? {
                total_seconds = total_seconds
                    .checked_add(n.checked_mul(seconds_per_unit).ok_or_else(bad)?)
                    .ok_or_else(bad)?;
                cursor = remainder;
            }
        }
        if let Some(seconds_str) = cursor.strip_suffix('S') {
            if seconds_str.is_empty() {
                return Err(bad());
            }
            let (whole, frac_nanos) = match seconds_str.split_once('.') {
                Some((w, f)) => {
                    if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(bad());
                    }
                    let mut digits = f.to_owned();
                    digits.truncate(9);
                    while digits.len() < 9 {
                        digits.push('0');
                    }
                    (w, digits.parse::<u64>().map_err(|_| bad())?)
                }
                None => (seconds_str, 0),
            };
            let whole: u64 = whole.parse().map_err(|_| bad())?;
            total_seconds = total_seconds.checked_add(whole).ok_or_else(bad)?;
            extra_nanos = frac_nanos;
            cursor = "";
        }
        if !cursor.is_empty() {
            return Err(bad());
        }
    }

    total_seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|n| n.checked_add(extra_nanos))
        .ok_or_else(bad)
}

/// Consume a leading `"<digits><unit>"` component from `input`, if the next unit character
/// present in `input` (before any other recognised unit letter) is `unit`. Returns the parsed
/// value and the remainder, or `None` if `input` does not start with a component of this unit.
fn take_component(input: &str, unit: char) -> MirrorResult<Option<(u64, &str)>> {
    let Some(pos) = input.find(unit) else { return Ok(None) };
    let digits = &input[..pos];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MirrorError::BadDuration { value: input.to_owned() });
    }
    let n: u64 =
        digits.parse().map_err(|_| MirrorError::BadDuration { value: input.to_owned() })?;
    Ok(Some((n, &input[pos + 1..])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_cadence_values_parse() {
        assert_eq!(parse_iso8601_duration_nanos("PT1S").expect("valid"), 1_000_000_000);
        assert_eq!(parse_iso8601_duration_nanos("PT5M").expect("valid"), 300_000_000_000);
        assert_eq!(parse_iso8601_duration_nanos("PT1H").expect("valid"), 3_600_000_000_000);
        assert_eq!(parse_iso8601_duration_nanos("P1D").expect("valid"), 86_400_000_000_000);
        assert_eq!(
            parse_iso8601_duration_nanos("P1DT12H").expect("valid"),
            (86_400 + 43_200) * 1_000_000_000
        );
        assert_eq!(parse_iso8601_duration_nanos("P1W").expect("valid"), 604_800_000_000_000);
    }

    #[test]
    fn fractional_seconds_are_honoured() {
        assert_eq!(parse_iso8601_duration_nanos("PT0.5S").expect("valid"), 500_000_000);
        assert_eq!(parse_iso8601_duration_nanos("PT1.000000001S").expect("valid"), 1_000_000_001);
    }

    #[test]
    fn malformed_durations_are_rejected() {
        assert!(parse_iso8601_duration_nanos("5M").is_err()); // missing P
        assert!(parse_iso8601_duration_nanos("P").is_err()); // empty
        assert!(parse_iso8601_duration_nanos("PT").is_err()); // empty time part
        assert!(parse_iso8601_duration_nanos("PTM").is_err()); // no digits
        assert!(parse_iso8601_duration_nanos("PT5X").is_err()); // unknown unit
        assert!(parse_iso8601_duration_nanos("P1H").is_err()); // H without T
        assert!(parse_iso8601_duration_nanos("PT1.S").is_err()); // empty fraction
    }
}
