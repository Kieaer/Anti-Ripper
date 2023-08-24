use std::cell::Cell;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc::channel;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use chrono::format::{DelayedFormat, StrftimeItems};
use dirs::{config_dir, home_dir};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use notify::{Config, Event, EventKind, recommended_watcher, RecommendedWatcher, RecursiveMode, Watcher};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::cookie::Cookie;
use reqwest::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderValue, USER_AGENT};
use rusqlite::Connection;
use serde_json::{Map, Number, Value};
use text_io::read;
use ua_generator::ua::spoof_ua;

use crate::structs::{SearchData, UserData};

mod structs;

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

fn search_old_logs() -> Result<(), Box<dyn std::error::Error>> {
    let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");

    // VRCX 데이터를 수정하기 전에 백업
    fs::copy(database_path.clone(), config_dir().unwrap().join("VRCX/VRCX_backup.sqlite3"))?;

    let conn = Connection::open(database_path)?;
    let mut stmt = conn.prepare("SELECT created_at, display_name, user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined'")?;
    let ready_count = Rc::new(Cell::new(0));
    let result = stmt.query_map([], |row| {
        let data = UserData {
            created_at: row.get(0)?,
            display_name: row.get(1)?,
            user_id: row.get(2)?,
        };

        if !data.user_id.is_empty() {
            ready_count.set(ready_count.get() + 1);
        }

        Ok(data)
    })?;

    let mut checked = Vec::new();

    println!("프로그램이 VRCX 데이터에서 누락된 사용자 ID를 추가 하고 있습니다.");

    let mut user_list = vec![];

    let pb = ProgressBar::new(ready_count.get());
    let token = fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/auth")).unwrap();
    for value in result {
        let data = value.unwrap();
        if data.user_id.is_empty() {
            if !checked.contains(&data.display_name) {
                let url = format!("https://api.vrchat.cloud/api/1/users?search={}?n={}&developerType=internal", data.display_name, 1);
                let client = Client::new();
                let mut headers = HeaderMap::new();
                headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
                headers.insert(COOKIE, HeaderValue::from_str(&*token)?);
                let response = client.get(url).headers(headers).send()?;
                let display_name = data.display_name.clone();

                let mut select_query = conn.prepare("SELECT created_at, display_name, user_id FROM gamelog_join_leave WHERE display_name = ?1")?;

                let mut select = |user_id: String| {
                    let _ = select_query.query_map([user_id], |row| {
                        Ok(UserData {
                            created_at: row.get(0)?,
                            display_name: row.get(1)?,
                            user_id: row.get(2)?,
                        })
                    }).expect("SQL Failed");
                };

                if response.status().is_success() {
                    let body = response.text().unwrap();
                    let json: Value = serde_json::from_str(&*body)?;
                    if data.display_name == json["display_name"] {
                        user_list.push(select(json["id"].to_string()))
                    }
                    checked.push(display_name);
                }
            }
            pb.inc(1);
        }
    }

    let ids = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.json");
    fs::write(ids, serde_json::to_string(&user_list).unwrap())?;
    user_list.clear();
    pb.finish();

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
                        json.insert(name, Value::Number("0".parse().unwrap()));
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

fn check(file_path: &str) {
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
            // 로그 확인
            println!("Last Paragraph:\n{}", paragraph.trim());
        }
    } else {
        println!("Failed to open the file");
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
                    check(String::from(path.clone()).as_str());
                },
                Err(e) => println!("watch error: {:?}", e),
            }
        }
    }

    Ok(())
}