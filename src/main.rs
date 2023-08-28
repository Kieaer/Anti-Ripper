use std::{fs, thread};
use std::cell::Cell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::channel;
use std::thread::available_parallelism;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use chrono::format::{DelayedFormat, StrftimeItems};
use dirs::{config_dir, home_dir};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use rayon::ThreadPoolBuilder;
use regex::Regex;
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::cookie::Cookie;
use reqwest::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderValue, USER_AGENT};
use rpassword::read_password;
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
        print!("아이디: ");
        let id: String = read!();
        print!("비밀번호: ");
        let pw: String = read_password()?;

        // 로그인 Header 생성
        let account_auth_header = HeaderValue::from_str(&format!("Basic {}", general_purpose::STANDARD_NO_PAD.encode(&format!("{}:{}", id, pw))))?;

        let client = Client::new();

        // 아이디/비밀번호로 로그인 시도
        let mut login_header = HeaderMap::new();
        login_header.insert(USER_AGENT, PROGRAM_USER_AGENT.parse()?);
        login_header.insert(AUTHORIZATION, account_auth_header);
        let login_get_response = client.get(LOGIN_URL).headers(login_header.clone()).send()?;
        let cloned = client.get(LOGIN_URL).headers(login_header).send()?;

        if login_get_response.status().is_success() {
            let otp_type = cloned.text()?.contains("totp");

            println!("2단계 인증 코드 6자리를 입력하세요. 인증 앱 또는 이메일을 확인하시면 됩니다.");
            loop {
                let token_cookie = login_get_response.cookies();
                let code: String = read!();
                let mut map = HashMap::new();
                map.insert("code", code);

                let mut post_headers = HeaderMap::new();
                post_headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse()?);
                post_headers.insert(COOKIE, HeaderValue::from_str(&filter_cookie(token_cookie))?);

                // 2단계 인증이 인증 앱인지 이메일 인증인지 확인
                let mut post_request: RequestBuilder;
                if otp_type {
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
                    token_login_headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse()?);
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
            }
            break;
        } else {
            println!("아이디 또는 비밀번호가 틀렸습니다. 다시 입력 해 주세요.");
            Err("Wrong ID or Password")?;
        }
    }

    Ok(())
}

fn get_info_from_server(user_name: String, pb: &ProgressBar) -> Value {
    let token = fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/auth")).unwrap();
    let url = format!("https://api.vrchat.cloud/api/1/users?search={}&n={}", user_name, 1);
    let client = Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
    headers.insert(COOKIE, HeaderValue::from_str(&*token).unwrap());

    let mut response = client.get(url.clone()).headers(headers.clone()).send().unwrap();
    while !response.status().is_success() {
        pb.set_message("브챗 서버가 과열 되었습니다! 식을 때 까지 대기중...");
        thread::sleep(Duration::from_secs(305));
        response = client.get(url.clone()).headers(headers.clone()).send().unwrap();
    }
    pb.set_message("");

    return if response.status().is_success() {
        let body = response.text().unwrap();
        let json: Value = serde_json::from_str(&*body).unwrap();
        json
    } else {
        json!({})
    };
}

fn get_info_from_ripper(user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let ua = spoof_ua();

    let params = [("category", "authorid"), ("page", "1"), ("search", user_id), ("status", "both"), ("ordering", "none"), ("platform", "all"), ("limit", "36")];
    let response = client.get(API_URL)
        .form(&params)
        .header(USER_AGENT, ua)
        .send()?;
    if response.status().is_success() {
        let body = response.text()?;
        let json: Value = serde_json::from_str(&*body)?;
        let page: u64 = json["pages"].as_u64().unwrap();

        let avatar_total = json["count"].as_u64().unwrap();
        let sty = ProgressStyle::with_template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")?.progress_chars("##-");
        let avatar_progress = ProgressBar::new(avatar_total);
        avatar_progress.set_style(sty.clone());

        for i in 1..page {
            let params = [("category", "authorid"), ("page", &i.to_string()), ("search", user_id), ("status", "both"), ("ordering", "none"), ("platform", "all"), ("limit", "36")];
            let response = client.get(API_URL)
                .form(&params)
                .header(USER_AGENT, ua)
                .send()?;
            if response.status().is_success() {
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

                        // 처음 뜯긴 시간에서 뒤로 1분 범위
                        let base_time = convert_time(json["dateAdded"].as_i64().unwrap() - 60000);

                        // 처음 뜯긴 시간에서 앞으로 1분 범위
                        let range_time = convert_time(json["dateAdded"].as_i64().unwrap() + 60000);

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
                            let name = data?.display_name;

                            if json.contains_key(&name) {
                                json.insert(name.clone(), Value::from(Number::from(json.get(&*name).unwrap().as_i64().unwrap() + 1)));
                            } else {
                                json.insert(name, Value::Number(Number::from(0)));
                            }
                        }

                        if !json["lastUpdated"].is_null() {
                            // 마지막으로 뜯긴 시간에서 뒤로 1분 범위
                            let base_time = convert_time(json["lastUpdated"].as_i64().unwrap() - 60000);

                            // 마지막으로 뜯긴 시간에서 뒤로 1분 범위
                            let range_time = convert_time(json["lastUpdated"].as_i64().unwrap() + 60000);

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
                                let name = data?.display_name;

                                if json.contains_key(&name) {
                                    json.insert(name.clone(), Value::from(Number::from(json.get(&*name).unwrap().as_i64().unwrap() + 1)));
                                } else {
                                    json.insert(name, Value::Number("0".parse()?));
                                }
                            }
                        }

                        avatar_progress.inc(1);
                    }
                }
            }
        }
        avatar_progress.finish_and_clear();
    }

    let checked = config_dir().unwrap().join("VRCX/Anti-Ripper/store_check.txt");
    fs::write(checked, "VRCX 데이터를 사용하여 리퍼 스토어에서 뜯긴 아바타를 모두 계산 했다는 확인 파일")?;

    Ok(())
}

fn search_old_logs() -> Result<(), Box<dyn std::error::Error>> {
    let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");

    // VRCX 데이터를 수정하기 전에 백업
    fs::copy(database_path.clone(), config_dir().unwrap().join("VRCX/VRCX_backup.sqlite3"))?;

    let conn = Connection::open(database_path)?;
    let mut stmt = conn.prepare("SELECT created_at, display_name, user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined'")?;
    let mut ready_count = 0;
    let mut data_list: Vec<UserData> = vec![];
    let parse_data = stmt.query_map([], |row| {
        Ok(UserData {
            created_at: row.get(0)?,
            display_name: row.get(1)?,
            user_id: row.get(2)?,
        })
    })?;

    for user in parse_data {
        data_list.push(user?);
    }

    for _ in data_list.clone().into_iter() {
        ready_count = ready_count + 1;
    }

    let style = ProgressStyle::with_template("{wide_bar:.cyan/blue} {pos}/{len}\n{msg}")?.progress_chars("#>-");
    let pb = ProgressBar::new(ready_count);
    pb.set_style(style);

    let mut checked = vec![];

    println!("프로그램이 VRCX 데이터에서 누락된 사용자 ID를 추가 하고 있습니다.");
    let mut user_list: Vec<UserData> = vec![];

    if config_dir().unwrap().join("VRCX/Anti-ripper/user_id.json").exists() {
        let file_json: Vec<UserData> = serde_json::from_str(&*fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/user_id.json"))?)?;
        user_list = file_json;
    }

    for v in user_list.clone() {
        checked.push(v.display_name);
        pb.inc(1);
        pb.set_message("이미 저장된 데이터를 확인하는 중...")
    }
    pb.set_message("");

    for value in data_list.into_iter() {
        if value.clone().user_id.is_empty() {
            if !checked.contains(&value.display_name) {
                let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");
                let conn = Connection::open(database_path)?;

                let json = get_info_from_server(value.display_name.clone(), &pb);
                if !config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.json").exists() {
                    fs::write(config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.json"), "[]")?;
                }

                let user_data_file = fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/user_id.json"))?;
                if value.display_name.clone() == json[0]["displayName"] && !user_data_file.contains(&value.display_name) {
                    let mut select_query = conn.prepare(&format!("SELECT created_at FROM gamelog_join_leave WHERE display_name = {}", json[0]["displayName"]))?;
                    let result = select_query.query_map([], |row| {
                        Ok(UserData {
                            created_at: row.get(0)?,
                            display_name: json[0]["displayName"].to_string().replace("\"", ""),
                            user_id: json[0]["id"].to_string().replace("\"", ""),
                        })
                    })?;

                    for data in result {
                        user_list.push(data?);
                        break;
                    }

                    let ids = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.json");
                    fs::write(ids, serde_json::to_string(&user_list)?)?;
                }
            }
        } else {
            if !checked.contains(&value.display_name) {
                user_list.push(UserData {
                    created_at: value.created_at,
                    display_name: value.display_name.clone(),
                    user_id: value.user_id,
                });

                let ids = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.json");
                fs::write(ids, serde_json::to_string(&user_list)?)?;
            }
        }
        checked.push(value.display_name);
        pb.inc(1);
    }

    let ids = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id_done.txt");
    fs::write(ids, "모든 ID 확인이 끝났다는걸 확인하는 파일")?;
    user_list.clear();
    pb.finish_with_message("완료");

    Ok(())
}

fn check_log(file_path: &str, m: &MultiProgress) -> Result<(), Box<dyn std::error::Error>> {
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
            let re = Regex::new(pattern)?;

            if let Some(captures) = re.captures(paragraph.trim()) {
                if let Some(word_after) = captures.get(1) {
                    let target_name = word_after.clone().as_str().to_string();

                    let pb = m.add(ProgressBar::new(1));
                    let style = ProgressStyle::with_template("{spinner} {wide_msg}").unwrap().tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");
                    pb.set_style(style);
                    pb.set_message(format!("{} - 유저 확인중...", target_name));

                    let file_json: Vec<UserData> = serde_json::from_str(&*fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/user_id.json")).unwrap()).unwrap();
                    let exists = file_json.iter().find(|a| target_name == a.display_name);
                    if exists.is_none() {
                        pb.set_message(format!("{} - 서버에서 검색중...", target_name));
                        let json = get_info_from_server(word_after.as_str().to_string(), &pb);

                        let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");
                        let conn = Connection::open(database_path).unwrap();

                        let mut user_list: Vec<UserData> = serde_json::from_str(&*fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/user_id.json")).unwrap()).unwrap();
                        let mut select_query = conn.prepare(&format!("SELECT created_at FROM gamelog_join_leave WHERE display_name = {}", json[0]["displayName"])).unwrap();
                        let result = select_query.query_map([], |row| {
                            Ok(UserData {
                                created_at: row.get(0)?,
                                display_name: json[0]["displayName"].to_string().replace("\"", ""),
                                user_id: json[0]["id"].to_string().replace("\"", ""),
                            })
                        }).unwrap();

                        for data in result {
                            user_list.push(data.unwrap());
                            break;
                        }

                        let ids = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.json");
                        fs::write(ids, serde_json::to_string(&user_list).unwrap()).unwrap();
                    } else {
                        pb.set_message(format!("{} - 이미 등록된 유저", target_name));
                    }
                    pb.set_message(format!("{} - 확인중...", target_name));

                    thread::spawn(move || {
                        thread::sleep(Duration::from_secs(30));

                        let user_id_file_path = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.txt");
                        let mut file = File::open(user_id_file_path).unwrap();
                        let mut user_id = String::new();
                        file.read_to_string(&mut user_id).unwrap();

                        let ripper_path = config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json");
                        let mut file = File::open(ripper_path).unwrap();
                        let mut ripper = String::new();
                        file.read_to_string(&mut ripper).unwrap();
                        let map: Map<String, Value> = serde_json::from_str(&*ripper).unwrap();

                        let result = check_current_count(&ripper);
                        pb.finish_and_clear();
                        if result {
                            let count = map.get(&*target_name).unwrap().as_u64().unwrap();
                            println!("{} 유저가 입장했을 때 뜯겼습니다. 현재 이 유저의 감지 횟수는 {}회.", target_name, count + 1);
                        }
                    });
                }
            }
        }
    }

    Ok(())
}

fn check_current_count(user_id: &str) -> bool {
    fn set_params(page: u32, user_id: &str) -> [(String, String); 7] {
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
        .form(&set_params(1, user_id))
        .header(USER_AGENT, ua)
        .send()
        .unwrap();
    if response.status().is_success() {
        let data: AvatarList = serde_json::from_str(&*response.text().unwrap()).unwrap();
        count = data.count;

        // 아바타가 1개라도 뜯겼을 경우
        if data.count != 0 {
            // 모든 페이지를 돌아가며 아바타의 ident 값을 확인한다
            for page in 1..=data.pages {
                let response = client.get(API_URL)
                    .form(&set_params(page, user_id))
                    .header(USER_AGENT, ua)
                    .send()
                    .unwrap();
                if response.status().is_success() {
                    let data: AvatarList = serde_json::from_str(&*response.text().unwrap()).unwrap();
                    let avatars = data.avatars;

                    for avatar in avatars.iter() {
                        idents.push(avatar.ident.clone());

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
                                } else {}
                            }
                        })
                    }
                }
            }
        }

        // 저장 되어있는걸 불러오고 비교하기
        let path = config_dir().unwrap().join("VRCX/Anti-Ripper/save.json");
        if !path.clone().exists() {
            File::create(path.clone()).unwrap();
        } else {
            let data: SaveData = serde_json::from_reader(File::open(path.clone()).unwrap()).unwrap();
            if count != data.count {
                println!("아바타가 새로 뜯겼습니다.");
                true;
            } else {
                for value in data.avatar_list {
                    if value.updated != avatar_list.iter().find(|a| a.name == value.name).unwrap().updated {
                        println!("{} 아바타가 또 뜯겼습니다.", value.name);
                        true;
                    }
                }
            }
        }

        // 저장
        let save = SaveData { count, idents, avatar_list };
        let file = File::open(path).unwrap();
        serde_json::to_writer(file, &save).unwrap();
    }

    false
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(config_dir().unwrap().join("VRCX/Anti-Ripper"))?;

    let auth_token = config_dir().unwrap().join("VRCX/Anti-Ripper/auth");
    let user_id = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.txt");
    let user_json = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id_done.txt");
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
        get_info_from_ripper(&text)?;
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

        let m = MultiProgress::new();

        loop {
            match rx.recv() {
                Ok(_) => {
                    check_log(String::from(path.clone()).as_str(), &m)?;
                }
                Err(e) => println!("watch error: {:?}", e),
            }
        }
    }

    Ok(())
}