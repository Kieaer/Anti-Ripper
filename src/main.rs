use std::cell::Cell;
use std::collections::HashMap;
use std::{fs, thread};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, stderr, Write};
use std::ops::Add;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::thread::available_parallelism;
use std::time::{Duration, SystemTime};

use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, TimeZone, Utc};
use chrono::format::{DelayedFormat, StrftimeItems};
use dirs::{config_dir, home_dir};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::ThreadPoolBuilder;
use regex::Regex;
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::cookie::Cookie;
use reqwest::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderValue, USER_AGENT};
use rusqlite::Connection;
use serde_json::{json, Map, Number, Value};
use text_io::read;
use ua_generator::ua::spoof_ua;

use crate::library::convert_time;
use crate::structs::{AvatarData, AvatarList, Item, SaveData, SearchData, UserData};

mod structs;
mod library;

const LOGIN_URL: &str = "https://api.vrchat.cloud/api/1/auth/user";
const TOTP_URL: &str = "https://api.vrchat.cloud/api/1/auth/twofactorauth/totp/verify";
const EMAIL_URL: &str = "https://api.vrchat.cloud/api/1/auth/twofactorauth/emailotp/verify";
const API_URL: &str = "https://api.ripper.store/api/v2/avatars/search";
const API_DETAIL_URL: &str = "https://api.ripper.store/api/v2/avatars/detail";
const PROGRAM_USER_AGENT: &str = "Ripper Store User Detector / dev cloud9350@naver.com";

fn login() -> Result<(), Box<dyn std::error::Error>> {
    fn filter_cookie<'a>(response: impl Iterator<Item=Cookie<'a>> + 'a) -> String {
        return response.collect::<Vec<_>>().iter().map(|cookie| format!("{}={}", cookie.name(), cookie.value())).collect::<Vec<_>>().join("; ");
    }

    loop {
        // 로그인
        println!("아이디를 입력 해 주세요");
        let id: String = read!();
        println!("비밀번호를 입력 해 주세요");
        let pw: String = read!();

        // 로그인 Header 생성
        let account_auth_header = HeaderValue::from_str(&format!("Basic {}", general_purpose::STANDARD_NO_PAD.encode(&format!("{}:{}", id, pw))))?;

        let client = Client::new();

        // 아이디/비밀번호로 로그인 시도
        let mut login_header = HeaderMap::new();
        login_header.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
        login_header.insert(AUTHORIZATION, account_auth_header);
        let login_get_response = client.get(LOGIN_URL).headers(login_header).send()?;

        if login_get_response.status().is_success() {
            let token_cookie = login_get_response.cookies();

            println!("2단계 인증 코드 6자리를 입력하세요. 인증 앱 또는 이메일을 확인하시면 됩니다.");
            let code: String = read!();
            let mut map = HashMap::new();
            map.insert("code", code);

            let mut post_headers = HeaderMap::new();
            post_headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
            post_headers.insert(COOKIE, HeaderValue::from_str(&filter_cookie(token_cookie))?);

            // 2단계 인증이 인증 앱인지 이메일 인증인지 확인
            let mut post_request: RequestBuilder;
            if login_get_response.text().unwrap().contains("totp") {
                post_request = client.post(TOTP_URL).headers(post_headers);
            } else {
                post_request = client.post(EMAIL_URL).headers(post_headers);
            };

            post_request = post_request.json(&map);

            let post_response = post_request.send()?;

            if post_response.status().is_success() {
                let token_cookie = post_response.cookies();
                let account_auth_header = HeaderValue::from_str(&format!("Basic {}", general_purpose::STANDARD_NO_PAD.encode(&format!("{}:{}", id, pw))))?;

                let mut token_login_headers = HeaderMap::new();
                token_login_headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
                token_login_headers.insert(AUTHORIZATION, account_auth_header);
                token_login_headers.insert(COOKIE, HeaderValue::from_str(&filter_cookie(token_cookie))?);

                let token_login = client.get(LOGIN_URL).headers(token_login_headers).send()?;

                if token_login.status().is_success() {
                    let data = config_dir().unwrap().join("VRCX/Anti-Ripper/auth");
                    fs::write(data, &filter_cookie(token_login.cookies()))?;
                    println!("로그인 성공");
                    break;
                }
            } else {
                println!("2단계 인증 코드가 맞지 않습니다!");
                Err("Wrong 2-FA Code")?;
            }
        } else {
            println!("아이디 또는 비밀번호가 틀렸습니다. 다시 입력 해 주세요.");
            Err("Wrong ID or Password")?;
        }
    }

    Ok(())
}

fn get_info_from_server(user_name: String) -> Value {
    let token = fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/auth")).unwrap();
    let url = format!("https://api.vrchat.cloud/api/1/users?search={}&n={}", user_name, 1);
    let client = Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
    headers.insert(COOKIE, HeaderValue::from_str(&*token).unwrap());
    let response = client.get(url).headers(headers).send().unwrap();

    return if response.status().is_success() {
        let body = response.text().unwrap();
        let json: Value = serde_json::from_str(&*body).unwrap();
        json
    } else {
        println!("FAILED");
        json!({})
    };
}

// working
fn get_info_from_ripper(user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let ua = spoof_ua();

    let page = "1";
    let params = [("category", "authorid"), ("page", page), ("search", user_id), ("status", "both"), ("ordering", "none"), ("platform", "all"), ("limit", "36")];
    let response = client.get(API_URL)
        .form(&params)
        .header(USER_AGENT, ua)
        .send()?;
    if response.status().is_success() {
        let body = response.text().unwrap();
        let json: Value = serde_json::from_str(&*body)?;
        let avatars = json["avatars"].as_array().unwrap();
        let mut idents = Vec::new();

        for avatar in avatars {
            let avatar: SearchData = serde_json::from_value(avatar.clone())?;
            idents.push(avatar.ident);
        }

        let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");
        let ripper_path = config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json");
        let conn = Connection::open(database_path)?;

        for ident in idents {
            let params = [("ident", ident)];
            let response = client.get(API_DETAIL_URL)
                .form(&params)
                .header(USER_AGENT, ua)
                .send()?;
            if response.status().is_success() {
                let json: Value = serde_json::from_str(&*body)?;

                // 처음 뜯긴 시간에서 뒤로 5분 범위
                let base_time = convert_time(json["dateAdded"].as_i64().unwrap() - 300000);

                // 처음 뜯긴 시간에서 앞으로 5분 범위
                let range_time = convert_time(json["dateAdded"].as_i64().unwrap() + 300000);

                // 뜯긴 시점에 있던 사람들 검색
                let sql = format!("SELECT created_at,display_name,user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined' BETWEEN '{}' AND '{}'", base_time, range_time);
                let mut stmt = conn.prepare(&sql)?;

                let total_user = Rc::new(Cell::new(0));
                let result = stmt.query_map([], |row| {
                    let total_user = Rc::clone(&total_user);
                    total_user.set(total_user.get() + 1);
                    Ok(UserData {
                        created_at: row.get(0)?,
                        display_name: row.get(1)?,
                        user_id: row.get(2)?,
                    })
                })?;

                if !ripper_path.exists() {
                    let map = Map::new();
                    let mut writer = BufWriter::new(File::create(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json").to_str().unwrap())?);
                    serde_json::to_writer(&mut writer, &map)?;
                    writer.flush()?;
                }

                let mut file = File::open(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json"))?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;

                let mut json: Map<String, Value> = serde_json::from_str(&contents)?;

                for value in result {
                    let data = value;
                    let name = data.unwrap().display_name;

                    if json.contains_key(&name) {
                        json.insert(name.clone(), Value::from(Number::from(json.get(&*name).unwrap().as_i64().unwrap() + 1)));
                    } else {
                        json.insert(name, Value::Number(Number::from(0)));
                    }
                }

                if !json["lastUpdated"].is_null() {
                    // 마지막으로 뜯긴 시간에서 뒤로 5분 범위
                    let base_time = convert_time(json["lastUpdated"].as_i64().unwrap() - 300000);

                    // 마지막으로 뜯긴 시간에서 뒤로 5분 범위
                    let range_time = convert_time(json["lastUpdated"].as_i64().unwrap() + 300000);

                    let sql = format!("SELECT created_at,display_name,user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined' BETWEEN '{}' AND '{}'", base_time, range_time);
                    let mut stmt = conn.prepare(&sql)?;

                    let total_user = Rc::new(Cell::new(0));
                    let result = stmt.query_map([], |row| {
                        let total_user = Rc::clone(&total_user);
                        total_user.set(total_user.get() + 1);
                        Ok(UserData {
                            created_at: row.get(0)?,
                            display_name: row.get(1)?,
                            user_id: row.get(2)?,
                        })
                    })?;

                    if !ripper_path.exists() {
                        let map = Map::new();
                        let mut writer = BufWriter::new(File::create(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json").to_str().unwrap())?);
                        serde_json::to_writer(&mut writer, &map)?;
                        writer.flush()?;
                    }

                    let mut file = File::open(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json"))?;
                    let mut contents = String::new();
                    file.read_to_string(&mut contents)?;

                    let mut json: Map<String, Value> = serde_json::from_str(&contents)?;

                    for value in result {
                        let data = value;
                        let name = data.unwrap().display_name;

                        if json.contains_key(&name) {
                            json.insert(name.clone(), Value::from(Number::from(json.get(&*name).unwrap().as_i64().unwrap() + 1)));
                        } else {
                            json.insert(name, Value::Number("0".parse().unwrap()));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn search_old_logs() -> Result<(), Box<dyn std::error::Error>> {
    let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");

    // VRCX 데이터를 수정하기 전에 백업
    fs::copy(database_path.clone(), config_dir().unwrap().join("VRCX/VRCX_backup.sqlite3"))?;

    let conn = Connection::open(database_path)?;
    let mut stmt = conn.prepare("SELECT created_at, display_name, user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined'")?;
    let ready_count = Rc::new(Cell::new(0));
    let mut data_list: Vec<UserData> = vec![];
    let parse_data = stmt.query_map([], |row| {
        Ok(UserData {
            created_at: row.get(0)?,
            display_name: row.get(1)?,
            user_id: row.get(2)?,
        })
    })?;

    for user in parse_data {
        data_list.push(user.unwrap());
    }

    for value in data_list.clone().into_iter() {
        if value.user_id.unwrap().is_empty() {
            ready_count.set(ready_count.get() + 1);
        }
    }

    let mut checked = vec![];

    println!("프로그램이 VRCX 데이터에서 누락된 사용자 ID를 추가 하고 있습니다.");
    let datetime: DateTime<Utc> = SystemTime::now().add(Duration::from_secs(3 * ready_count.get())).into();
    println!("예상 완료 시간: {}", datetime.format("%F %r"));

    let mut user_list = vec![];
    let pb = ProgressBar::new(ready_count.get());

    for value in data_list.into_iter() {
        if value.user_id.unwrap().is_empty() {
            if !checked.contains(&value.display_name) {
                let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");
                let conn = Connection::open(database_path).unwrap();
                let mut select_query = conn.prepare("SELECT created_at, display_name, user_id FROM gamelog_join_leave WHERE display_name = ?1").unwrap();
                let mut select = |user_id: String| {
                    let _ = select_query.query_map([user_id], |row| {
                        Ok(UserData {
                            created_at: row.get(0)?,
                            display_name: row.get(1)?,
                            user_id: row.get(2)?,
                        })
                    }).expect("SQL Failed");
                };

                let json = get_info_from_server(value.display_name.clone());
                if value.display_name.clone() == json[0]["displayName"] {
                    user_list.push(select(json[0]["id"].to_string()));
                }
                checked.push(value.display_name);

                thread::sleep(Duration::from_secs(60));
            }
        }
        pb.inc(1);
    }

    let ids = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.json");
    fs::write(ids, serde_json::to_string(&*user_list).unwrap())?;
    user_list.clear();
    pb.finish_with_message("완료");

    Ok(())
}

fn search_store(user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    fn convert_time<'a>(value: i64) -> DelayedFormat<StrftimeItems<'a>> {
        let time = NaiveDateTime::from_timestamp_millis(value);
        let datetime = DateTime::<Local>::from_utc(time.unwrap(), Local.offset_from_utc_datetime(&time.unwrap()));
        return datetime.format("%Y-%m-%d %H:%M:%S");
    }

    let client = Client::new();
    let ua = spoof_ua();

    // todo page 많을 경우 추가
    let page = "1";
    let params = [("category", "authorid"), ("page", page), ("search", user_id), ("status", "both"), ("ordering", "none"), ("platform", "all"), ("limit", "36")];
    let response = client.get(API_URL)
        .form(&params)
        .header(USER_AGENT, ua)
        .send()?;
    if response.status().is_success() {
        let body = response.text().unwrap();
        let json: Value = serde_json::from_str(&*body)?;
        let avatars = json["avatars"].as_array().unwrap();
        let mut idents = Vec::new();

        let avatar_total = Rc::new(Cell::new(0));
        let m = MultiProgress::new();
        let sty = ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
        )
            .unwrap()
            .progress_chars("##-");


        for avatar in avatars {
            let avatar: SearchData = serde_json::from_value(avatar.clone())?;
            idents.push(avatar.ident);
            avatar_total.set(avatar_total.get() + 1);
        }

        let avatar_progress = m.add(ProgressBar::new(avatar_total.get()));
        avatar_progress.set_style(sty.clone());
        avatar_progress.set_message("Avatar ");

        let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");
        let ripper_path = config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json");
        let conn = Connection::open(database_path)?;

        for ident in idents {
            let params = [("ident", ident)];
            let response = client.get(API_DETAIL_URL)
                .form(&params)
                .header(USER_AGENT, ua)
                .send()?;
            if response.status().is_success() {
                let json: Value = serde_json::from_str(&*body)?;

                // 처음 뜯긴 시간에서 뒤로 5분 범위
                let base_time = convert_time(json["dateAdded"].as_i64().unwrap() - 300000);

                // 처음 뜯긴 시간에서 앞으로 5분 범위
                let range_time = convert_time(json["dateAdded"].as_i64().unwrap() + 300000);

                // 뜯긴 시점에 있던 사람들 검색
                let sql = format!("SELECT created_at,display_name,user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined' BETWEEN '{}' AND '{}'", base_time, range_time);
                let mut stmt = conn.prepare(&sql)?;

                let total_user = Rc::new(Cell::new(0));
                let result = stmt.query_map([], |row| {
                    let total_user = Rc::clone(&total_user);
                    total_user.set(total_user.get() + 1);
                    Ok(UserData {
                        created_at: row.get(0)?,
                        display_name: row.get(1)?,
                        user_id: row.get(2)?,
                    })
                })?;

                let user_progress = m.add(ProgressBar::new(total_user.get()));
                user_progress.set_style(sty.clone());
                user_progress.set_message("User ");

                if !ripper_path.exists() {
                    let map = Map::new();
                    let mut writer = BufWriter::new(File::create(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json").to_str().unwrap())?);
                    serde_json::to_writer(&mut writer, &map)?;
                    writer.flush()?;
                }

                let mut file = File::open(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json"))?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;

                let mut json: Map<String, Value> = serde_json::from_str(&contents)?;

                for value in result {
                    let data = value;
                    let name = data.unwrap().display_name;

                    if json.contains_key(&name) {
                        json.insert(name.clone(), Value::from(Number::from(json.get(&*name).unwrap().as_i64().unwrap() + 1)));
                    } else {
                        json.insert(name, Value::Number(Number::from(0)));
                    }

                    user_progress.inc(1);
                }
                user_progress.finish_with_message("완료");
                m.remove(&user_progress);

                if !json["lastUpdated"].is_null() {
                    // 마지막으로 뜯긴 시간에서 뒤로 5분 범위
                    let base_time = convert_time(json["lastUpdated"].as_i64().unwrap() - 300000);

                    // 마지막으로 뜯긴 시간에서 뒤로 5분 범위
                    let range_time = convert_time(json["lastUpdated"].as_i64().unwrap() + 300000);

                    let sql = format!("SELECT created_at,display_name,user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined' BETWEEN '{}' AND '{}'", base_time, range_time);
                    let mut stmt = conn.prepare(&sql)?;

                    let total_user = Rc::new(Cell::new(0));
                    let result = stmt.query_map([], |row| {
                        let total_user = Rc::clone(&total_user);
                        total_user.set(total_user.get() + 1);
                        Ok(UserData {
                            created_at: row.get(0)?,
                            display_name: row.get(1)?,
                            user_id: row.get(2)?,
                        })
                    })?;

                    let user_progress = m.add(ProgressBar::new(total_user.get()));
                    user_progress.set_style(sty.clone());
                    user_progress.set_message("User ");

                    if !ripper_path.exists() {
                        let map = Map::new();
                        let mut writer = BufWriter::new(File::create(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json").to_str().unwrap())?);
                        serde_json::to_writer(&mut writer, &map)?;
                        writer.flush()?;
                    }

                    let mut file = File::open(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json"))?;
                    let mut contents = String::new();
                    file.read_to_string(&mut contents)?;

                    let mut json: Map<String, Value> = serde_json::from_str(&contents)?;

                    for value in result {
                        let data = value;
                        let name = data.unwrap().display_name;

                        if json.contains_key(&name) {
                            json.insert(name.clone(), Value::from(Number::from(json.get(&*name).unwrap().as_i64().unwrap() + 1)));
                        } else {
                            json.insert(name, Value::Number("0".parse().unwrap()));
                        }

                        user_progress.inc(1);
                    }
                    user_progress.finish_with_message("완료");
                    m.remove(&user_progress);
                }
            }

            avatar_progress.set_message(format!("{}번째 아바타", avatar_total.get()));
            avatar_progress.inc(1);
        }

        avatar_progress.finish_with_message("완료");

        let checked = config_dir().unwrap().join("VRCX/Anti-Ripper/store_check.txt");
        fs::write(checked, "VRCX 데이터를 사용하여 리퍼 스토어에서 뜯긴 아바타를 모두 계산 했다는 확인 파일")?;
    }

    Ok(())
}

fn check_log(file_path: &str) {
    if let Ok(file) = File::open(file_path) {
        let reader = BufReader::new(file);
        let mut paragraph = String::new();
        let mut empty_line_count = 0;

        for line in reader.lines() {
            if let Ok(line) = line {
                if line.trim().is_empty() {
                    empty_line_count += 1;
                    if empty_line_count == 2 {
                        paragraph.clear();
                        empty_line_count = 0;
                    }
                } else {
                    paragraph.push_str(&line);
                    paragraph.push('\n');
                }
            }
        }

        if !paragraph.is_empty() {
            let pattern = r"OnPlayerJoined\s+(\w+)";
            let re = Regex::new(pattern).unwrap();

            if let Some(captures) = re.captures(paragraph.trim()) {
                if let Some(word_after) = captures.get(1) {
                    // 확인
                    let json = get_info_from_server(word_after.as_str().to_string());
                }
            } else {
                println!("No match found.");
            }
        }
    } else {
        println!("Failed to open the file");
    }
}

fn check_current_count(user_id: &str) {
    fn set_params(page: &str, user_id: &str) -> [(String, String); 7] {
        return [
            ("category".to_string(), "authorid".to_string()),
            ("page".to_string(), page.to_string()),
            ("search".to_string(), user_id.to_string()),
            ("status".to_string(), "both".to_string()),
            ("ordering".to_string(), "none".to_string()),
            ("platform".to_string(), "all".to_string()),
            ("limit".to_string(), "36".to_string()),
        ];
    }

    // 파일에 저장할 정보
    let count: u32;
    let mut idents: Vec<String> = vec![];
    let mut avatar_list = vec![];

    // 리퍼 스토어에게 안걸리도록 무작위 User-Agent 전송
    let client = Client::new();
    let ua = spoof_ua();

    let response = client.get(API_URL)
        .form(&set_params("1", user_id))
        .header(USER_AGENT, ua)
        .send()
        .unwrap();
    if response.status().is_success() {
        let data: AvatarList = serde_json::from_str(&*response.text().unwrap()).unwrap();
        count = data.count;
        let avatars = data.avatars;

        // 아바타가 1개라도 뜯겼을 경우
        if data.count != 0 {
            // 모든 페이지를 돌아가며 아바타의 ident 값을 확인한다
            for _ in 1..=data.pages {
                for avatar in avatars.iter() {
                    idents.push(avatar.ident.clone());
                }
            }
            // 모든 ident 값을 돌아가며 확인한다.
            let idents_clone = idents.clone();
            let cpu_thread = available_parallelism().unwrap().get();
            let pool = ThreadPoolBuilder::new().num_threads(cpu_thread).build().unwrap();

            // 브챗 서버와 달리 리퍼 스토어는 제한이 없으므로 멀티 스레드로 한꺼번에 긁어오자
            pool.install(|| {
                for ident in idents_clone {
                    let client = Client::new();
                    let response = client.get(API_DETAIL_URL)
                        .form(&[("ident", ident)])
                        .header(USER_AGENT, ua)
                        .send()
                        .unwrap();
                    if response.status().is_success() {
                        let data: Item = serde_json::from_str(&*response.text().unwrap()).unwrap();
                        let name = data.name;
                        let created = data.pc.created;
                        let added = data.pc.dateAdded;
                        let updated = data.pc.lastUpdated;
                        let result = AvatarData { name, created, added, updated };
                        avatar_list.push(result);
                    }
                }
            })

            // 완료
        }

        // 저장 되어있는걸 불러오고 비교하기
        let path = config_dir().unwrap().join("VRCX/Anti-Ripper/save.json");
        if !path.clone().exists() {
            File::create(path.clone()).unwrap();
        } else {
            let data: SaveData = serde_json::from_reader(File::open(path.clone()).unwrap()).unwrap();
            if count != data.count {
                // TODO 이 인간은 한번도 뜯기지 않은 아바타가 드디어 뜯겨버렸다. 라는 코드를 쓰자
                println!("아바타가 새로 뜯겼습니다.")
            }
        }

        // 저장
        let save = SaveData { count, idents, avatar_list };
        let file = File::open(path).unwrap();
        serde_json::to_writer(file, &save).unwrap();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(config_dir().unwrap().join("VRCX/Anti-Ripper"))?;

    let auth_token = config_dir().unwrap().join("VRCX/Anti-Ripper/auth");
    let user_id = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.txt");
    let user_json = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.json");
    let checked = config_dir().unwrap().join("VRCX/Anti-Ripper/store_check.txt");

    // 자동 로그인을 위해 계정 정보 가져오기
    if !auth_token.exists() {
        login()?;
    }
    // VRCX 에서 누락된 데이터를 찾고 추가하기
    if !user_json.exists() {
        search_old_logs()?;
    }
    // 로그인 된 user_id 값을 확인하고 파일로 저장
    if !user_id.exists() {
        let mut file = File::open(auth_token.clone())?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let client = Client::new();
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
        headers.insert(COOKIE, contents.parse().unwrap());
        let response = client.get(LOGIN_URL)
            .headers(headers)
            .send()
            .expect("통신 오류");

        if response.status().is_success() {
            let body = response.text().unwrap();
            let json: Value = serde_json::from_str(&*body).expect("JSON 오류");
            fs::write(user_id.clone(), json["id"].as_str().unwrap())?;
        }
    }

    // 리퍼 스토어에서 정보 확인
    if auth_token.exists() && user_json.exists() && user_id.exists() {
        let mut file = File::open(user_id.clone())?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        search_store(&text)?;
    }

    if auth_token.exists() && user_json.exists() && user_id.exists() && checked.exists() {
        let dir_path = home_dir().unwrap().join("AppData").join("LocalLow").join("VRChat");
        let specific_word = "output_log";
        let mut path: String = String::new();

        if let Ok(entries) = fs::read_dir(dir_path) {
            let mut earliest_creation_time: Option<std::time::SystemTime> = None;
            let mut earliest_file_path: Option<String> = None;

            for entry in entries {
                if let Ok(entry) = entry {
                    if let Some(file_name) = entry.file_name().to_str() {
                        if file_name.contains(specific_word) {
                            let metadata = entry.metadata().unwrap();
                            if let Ok(creation_time) = metadata.created() {
                                if earliest_creation_time.is_none() || creation_time < earliest_creation_time.unwrap() {
                                    earliest_creation_time = Some(creation_time);
                                    earliest_file_path = Some(entry.path().to_string_lossy().into_owned());
                                }
                            }
                        }
                    }
                }
            }

            if let Some(file_path) = earliest_file_path {
                path = file_path;
            }
        }

        let (tx, rx) = channel();
        let mut watcher: RecommendedWatcher = Watcher::new(tx, Config::default()).unwrap();
        watcher.watch(PathBuf::from(path.clone()).as_path(), RecursiveMode::NonRecursive).unwrap();

        loop {
            match rx.recv() {
                Ok(_) => {
                    check_log(String::from(path.clone()).as_str());
                }
                Err(e) => println!("watch error: {:?}", e),
            }
        }
    }

    Ok(())
}