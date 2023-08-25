use chrono::format::{DelayedFormat, StrftimeItems};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};

pub fn convert_time<'a>(value: i64) -> DelayedFormat<StrftimeItems<'a>> {
    let time = NaiveDateTime::from_timestamp_millis(value);
    let datetime = DateTime::<Local>::from_utc(time.unwrap(), Local.offset_from_utc_datetime(&time.unwrap()));
    return datetime.format("%Y-%m-%d %H:%M:%S");
}