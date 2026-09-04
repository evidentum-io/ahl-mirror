//! An ISO 8601 duration parser for `checkpoint_cadence`/`witness_grace_period` (core spec
//! §7.3).
//!
//! Core spec §7.3 restricts these fields to the time-only subset of ISO 8601:
//! `P[n]DT[n]H[n]M[n]S` — days, hours, minutes, seconds. Years and calendar months are
//! **PROHIBITED**, normatively, because their length is context-dependent: admitting them
//! would make cadence, frontier, completeness and incorporation-time-bound computations
//! implementation-dependent, since two conformant parsers could map the same manifest to
//! different nanosecond totals. A value carrying `Y`, or `M` in the date part (a calendar
//! month, as opposed to `M` after `T`, which is minutes), is malformed and MUST be rejected
//! rather than approximated — this parser does so with a distinct
//! [`crate::error::MirrorError::ProhibitedDurationComponent`], never silently converting.
//!
//! The alternative `PnW` (weeks) form ISO 8601 also permits is outside the grammar core spec
//! §7.3 gives (`P[n]DT[n]H[n]M[n]S` has no `W`) and is rejected the same way any other
//! unrecognised trailing content is: as [`crate::error::MirrorError::BadDuration`].
//!
//! Fractional seconds MAY carry **at most nine digits**; core spec §7.3 requires anything
//! longer to be rejected outright — never truncated or rounded to nine — since either would
//! make the parsed value implementation-dependent (see
//! [`crate::error::MirrorError::DurationFractionTooLong`]). `checkpoint_cadence` additionally
//! MUST be greater than zero (see [`parse_checkpoint_cadence_nanos`]); this crate does not
//! impose the same floor on `witness_grace_period`, since core spec §7.3 states it only for
//! `checkpoint_cadence`.

use crate::error::{MirrorError, MirrorResult};

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_DAY: u64 = 86_400;

/// Parse an ISO 8601 duration of the core spec §7.3 time-only subset to a total nanosecond
/// count.
///
/// # Errors
///
/// Returns [`MirrorError::ProhibitedDurationComponent`] if `value` carries `Y`, or `M` in the
/// date part (core spec §7.3 forbids both, normatively — see the module docs). Returns
/// [`MirrorError::BadDuration`] if `value` is otherwise not a well-formed duration of the
/// `P[n]DT[n]H[n]M[n]S` grammar, or if the total overflows `u64` nanoseconds.
pub fn parse_iso8601_duration_nanos(value: &str) -> MirrorResult<u64> {
    let bad = || MirrorError::BadDuration { value: value.to_owned() };
    let rest = value.strip_prefix('P').ok_or_else(bad)?;
    if rest.is_empty() {
        return Err(bad());
    }

    if rest.contains('Y') {
        return Err(MirrorError::ProhibitedDurationComponent {
            value: value.to_owned(),
            component: 'Y',
        });
    }

    let (date_part, time_part) = match rest.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (rest, None),
    };

    // A literal `M` in the date part is a calendar month (prohibited); a literal `M` in the
    // time part, after `T`, is minutes (allowed) — checked only on `date_part` here.
    if date_part.contains('M') {
        return Err(MirrorError::ProhibitedDurationComponent {
            value: value.to_owned(),
            component: 'M',
        });
    }

    let mut total_seconds: u64 = 0;
    let mut cursor = date_part;
    if let Some((n, remainder)) = take_component(cursor, 'D')? {
        total_seconds = n.checked_mul(SECONDS_PER_DAY).ok_or_else(bad)?;
        cursor = remainder;
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
                    if f.len() > 9 {
                        return Err(MirrorError::DurationFractionTooLong {
                            value: value.to_owned(),
                        });
                    }
                    // Fewer than nine digits pads with trailing zeros, which is exact — not
                    // truncation — since a shorter decimal expansion implies exactly-zero
                    // digits beyond what was written (`0.5S` is exactly `500_000_000` ns).
                    let mut digits = f.to_owned();
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

/// Parse a `checkpoint_cadence` value: [`parse_iso8601_duration_nanos`], plus core spec
/// §7.3's additional requirement that it be greater than zero.
///
/// # Errors
///
/// Whatever [`parse_iso8601_duration_nanos`] returns, or
/// [`MirrorError::NonPositiveCadence`] if `value` parses but to exactly zero nanoseconds.
pub fn parse_checkpoint_cadence_nanos(value: &str) -> MirrorResult<u64> {
    let nanos = parse_iso8601_duration_nanos(value)?;
    if nanos == 0 {
        return Err(MirrorError::NonPositiveCadence { value: value.to_owned() });
    }
    Ok(nanos)
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
    // The remainder starts one character past `unit`. `len_utf8` rather than a literal 1 so
    // the split stays on a character boundary whatever `unit` is; `find` returned `pos`, so
    // the sum is at most `input.len()` and the lookup always succeeds.
    let rest = input
        .get(pos.saturating_add(unit.len_utf8())..)
        .ok_or_else(|| MirrorError::BadDuration { value: input.to_owned() })?;
    Ok(Some((n, rest)))
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
    }

    #[test]
    fn fractional_seconds_are_honoured() {
        assert_eq!(parse_iso8601_duration_nanos("PT0.5S").expect("valid"), 500_000_000);
        assert_eq!(parse_iso8601_duration_nanos("PT1.000000001S").expect("valid"), 1_000_000_001);
        // Exactly nine digits: the maximum core spec §7.3 allows, still accepted exactly.
        assert_eq!(
            parse_iso8601_duration_nanos("PT1.123456789S").expect("nine digits is the max"),
            1_123_456_789
        );
    }

    #[test]
    fn a_tenth_fractional_digit_is_rejected_not_truncated() {
        // Core spec §7.3: "at most nine digits; a value with more is malformed and MUST be
        // rejected, never truncated or rounded." Both worked examples from the spec: silently
        // truncating would make `PT0.0000000009S` collapse to zero and `PT1.0000000009S`
        // collapse to exactly one second — an implementation-dependent loss the rejection
        // rule exists to foreclose.
        assert!(matches!(
            parse_iso8601_duration_nanos("PT0.0000000009S"),
            Err(MirrorError::DurationFractionTooLong { .. })
        ));
        assert!(matches!(
            parse_iso8601_duration_nanos("PT1.0000000009S"),
            Err(MirrorError::DurationFractionTooLong { .. })
        ));
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

    #[test]
    fn weeks_are_outside_the_core_spec_grammar_and_rejected() {
        // `PnW` is valid ISO 8601 in general, but core spec §7.3's grammar is
        // `P[n]DT[n]H[n]M[n]S` — no `W` — so this is an ordinary malformed duration, not a
        // prohibited-component case.
        assert!(matches!(
            parse_iso8601_duration_nanos("P1W"),
            Err(MirrorError::BadDuration { .. })
        ));
    }

    #[test]
    fn years_are_rejected_as_a_prohibited_component_not_approximated() {
        let err = parse_iso8601_duration_nanos("P1Y").expect_err("years are prohibited");
        assert!(matches!(err, MirrorError::ProhibitedDurationComponent { component: 'Y', .. }));
    }

    #[test]
    fn calendar_months_are_rejected_as_a_prohibited_component_not_approximated() {
        let err = parse_iso8601_duration_nanos("P1M").expect_err("calendar months are prohibited");
        assert!(matches!(err, MirrorError::ProhibitedDurationComponent { component: 'M', .. }));
        // A composite value combining a prohibited calendar month with an allowed day.
        let err =
            parse_iso8601_duration_nanos("P1M2D").expect_err("calendar months are prohibited");
        assert!(matches!(err, MirrorError::ProhibitedDurationComponent { component: 'M', .. }));
    }

    #[test]
    fn minutes_after_t_are_not_confused_with_calendar_months() {
        // `M` after `T` is minutes, not a calendar month, and MUST be accepted.
        assert_eq!(parse_iso8601_duration_nanos("PT10M").expect("valid"), 600_000_000_000);
    }

    #[test]
    fn a_year_component_is_rejected_even_alongside_other_prohibited_or_valid_parts() {
        assert!(matches!(
            parse_iso8601_duration_nanos("P1Y2D"),
            Err(MirrorError::ProhibitedDurationComponent { component: 'Y', .. })
        ));
    }

    #[test]
    fn checkpoint_cadence_must_be_greater_than_zero() {
        // Core spec §7.3: `checkpoint_cadence` MUST be greater than zero.
        assert!(matches!(
            parse_checkpoint_cadence_nanos("PT0S"),
            Err(MirrorError::NonPositiveCadence { .. })
        ));
        // Every component present but each individually (and jointly) zero still nets to
        // zero nanoseconds — the check is on the parsed total, not the literal spelling.
        assert!(matches!(
            parse_checkpoint_cadence_nanos("P0DT0H0M0S"),
            Err(MirrorError::NonPositiveCadence { .. })
        ));
    }

    #[test]
    fn a_positive_checkpoint_cadence_parses_normally() {
        assert_eq!(parse_checkpoint_cadence_nanos("PT5M").expect("positive"), 300_000_000_000);
    }

    #[test]
    fn checkpoint_cadence_parsing_still_propagates_ordinary_duration_errors() {
        // The zero-check is additional, not a replacement for the underlying grammar and
        // prohibited-component checks.
        assert!(matches!(
            parse_checkpoint_cadence_nanos("P1Y"),
            Err(MirrorError::ProhibitedDurationComponent { component: 'Y', .. })
        ));
        assert!(matches!(
            parse_checkpoint_cadence_nanos("not-a-duration"),
            Err(MirrorError::BadDuration { .. })
        ));
    }
}
