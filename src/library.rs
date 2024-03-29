use std::fs;
use std::fs::File;
use std::io::Read;

use chrono::{DateTime, Duration, Local, NaiveDateTime, TimeZone};
use chrono::format::{DelayedFormat, StrftimeItems};
use dirs::config_dir;

use crate::structs::{RipperData, UserData};

pub fn convert_time<'a>(value: u64) -> DelayedFormat<StrftimeItems<'a>> {
    let time = NaiveDateTime::from_timestamp_millis(value as i64).unwrap() - Duration::hours(9);
    let datetime = DateTime::<Local>::from_utc(time, Local.offset_from_utc_datetime(&time));
    return datetime.format("%Y-%m-%d %H:%M:%S");
}

pub fn get_user() -> Vec<UserData> {
    let data: Vec<UserData> = serde_json::from_str(&*fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/user_id.json")).unwrap_or_else(|_| {
        fs::write(config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.json"), "[]").expect("파일 쓰기 오류");
        return fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/user_id.json")).expect("파일 읽기 오류");
    })).unwrap_or_else(|_| {
        serde_json::from_str(&*fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/user_id.json")).unwrap()).unwrap()
    });
    return data;
}

pub fn get_ripper() -> Vec<RipperData> {
    let data: Vec<RipperData> = serde_json::from_str(&*fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/ripper.json")).unwrap_or_else(|_| {
        fs::write(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json"), "[]").expect("파일 쓰기 오류");
        return fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/ripper.json")).expect("파일 읽기 오류");
    })).unwrap_or_else(|_| {
        fs::write(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json"), "[]").expect("파일 쓰기 오류");
        serde_json::from_str(&*fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/ripper.json")).unwrap()).unwrap()
    });
    return data;
}

pub fn get_id() -> String {
    let user_id_file_path = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.txt");
    let mut file = File::open(user_id_file_path).expect("파일 읽기 오류");
    let mut user_id = String::new();
    file.read_to_string(&mut user_id).expect("파일 읽기 오류");
    return user_id;
}

pub fn set_user(json: Vec<UserData>) {
    let ids = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.json");
    fs::write(ids, serde_json::to_string(&json).unwrap()).unwrap();
}

pub fn set_ripper(json: Vec<RipperData>) {
    let ids = config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json");
    fs::write(ids, serde_json::to_string(&json).unwrap()).unwrap();
}