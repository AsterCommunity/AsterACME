//! One fixed UTC display format for all human CLI times; machine formats keep precision.

pub(crate) fn timestamp(value: Option<time::OffsetDateTime>) -> String {
    let Some(value) = value else {
        return "—".into();
    };
    let at = value.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

#[cfg(test)]
mod tests {
    use crate::common::time::*;
    #[test]
    fn utc_normalization_subseconds_and_unknown_times_use_one_display() {
        let epoch = time::OffsetDateTime::from_unix_timestamp(0)
            .unwrap()
            .replace_nanosecond(123_456_789)
            .unwrap();
        assert_eq!(timestamp(Some(epoch)), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            timestamp(Some(
                epoch.to_offset(time::UtcOffset::from_hms(8, 0, 0).unwrap())
            )),
            "1970-01-01 00:00:00 UTC"
        );
        assert_eq!(timestamp(None), "—");
    }
}
