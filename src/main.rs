use std::{fs, ptr, thread};
use std::cell::Cell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Command, exit};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread::available_parallelism;
use std::time::{Duration, SystemTime};

use base64::{Engine as _, engine::general_purpose};
use chrono::format::{DelayedFormat, StrftimeItems};
use dirs::{config_dir, home_dir};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use notify::Watcher;
use rayon::ThreadPoolBuilder;
use regex::Regex;
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::cookie::Cookie;
use reqwest::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderValue, USER_AGENT};
use rodio::{Decoder, OutputStream, Source};
use rusqlite::Connection;
use self_update::cargo_crate_version;
use serde_json::{json, Value};
use shadow_rs::shadow;
use text_io::read;
use ua_generator::ua::spoof_ua;
use winapi::shared::minwindef::{DWORD, MAX_PATH};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32};

use crate::library::{convert_time, get_id, get_ripper, get_user, set_ripper, set_user};
use crate::structs::{AvatarData, AvatarItem, AvatarList, RipperData, SaveData, SearchData, UserData};

mod structs;
mod library;

const LOGIN_URL: &str = "https://api.vrchat.cloud/api/1/auth/user";
const TOTP_URL: &str = "https://api.vrchat.cloud/api/1/auth/twofactorauth/totp/verify";
const EMAIL_URL: &str = "https://api.vrchat.cloud/api/1/auth/twofactorauth/emailotp/verify";
const API_URL: &str = "https://api.ripper.store/api/v2/avatars/search";
const API_DETAIL_URL: &str = "https://api.ripper.store/api/v2/avatars/detail";
const PROGRAM_USER_AGENT: &str = "Ripper Store User Detector / dev cloud9350@naver.com";

shadow!(build);

fn login() {
    fn filter_cookie<'a>(response: impl Iterator<Item=Cookie<'a>> + 'a) -> String {
        return response.collect::<Vec<_>>().iter().map(|cookie| format!("{}={}", cookie.name(), cookie.value())).collect::<Vec<_>>().join("; ");
    }

    loop {
        // 로그인
        println!("아이디를 입력하세요");
        let id: String = read!();
        println!("비밀번호를 입력하세요");
        //let pw: String = read_password().expect("비밀번호 입력 오류");
        let pw: String = read!();

        // 로그인 Header 생성
        let account_auth_header = HeaderValue::from_str(&format!("Basic {}", general_purpose::STANDARD_NO_PAD.encode(&format!("{}:{}", id, pw)))).unwrap();

        let client = Client::new();

        // 아이디/비밀번호로 로그인 시도
        let mut login_header = HeaderMap::new();
        login_header.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
        login_header.insert(AUTHORIZATION, account_auth_header);
        let login_get_response = client.get(LOGIN_URL).headers(login_header.clone()).send().expect("브챗 로그인 오류");
        let cloned = client.get(LOGIN_URL).headers(login_header).send().expect("브챗 로그인 오류");

        if login_get_response.status().is_success() {
            let otp_type = cloned.text().expect("데이터 변환 오류").contains("totp");

            println!("2단계 인증 코드 6자리를 입력하세요. 인증 앱 또는 이메일을 확인하시면 됩니다.");
            loop {
                let token_cookie = login_get_response.cookies();
                let code: String = read!();
                let mut map = HashMap::new();
                map.insert("code", code);

                let mut post_headers = HeaderMap::new();
                post_headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
                post_headers.insert(COOKIE, HeaderValue::from_str(&filter_cookie(token_cookie)).expect("쿠키 값 가져오기 실패"));

                // 2단계 인증이 인증 앱인지 이메일 인증인지 확인
                let mut post_request: RequestBuilder;
                if otp_type {
                    post_request = client.post(TOTP_URL).headers(post_headers);
                } else {
                    post_request = client.post(EMAIL_URL).headers(post_headers);
                };

                post_request = post_request.json(&map);

                let post_response = post_request.send().expect("브챗 2단계 로그인 오류");

                if post_response.status().is_success() {
                    let token_cookie = post_response.cookies();
                    let account_auth_header = HeaderValue::from_str(&format!("Basic {}", general_purpose::STANDARD_NO_PAD.encode(&format!("{}:{}", id, pw)))).unwrap();

                    let mut token_login_headers = HeaderMap::new();
                    token_login_headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
                    token_login_headers.insert(AUTHORIZATION, account_auth_header);
                    token_login_headers.insert(COOKIE, HeaderValue::from_str(&filter_cookie(token_cookie)).expect("쿠키 값 가져오기 실패"));

                    let token_login = client.get(LOGIN_URL).headers(token_login_headers).send().expect("브챗 인증 토큰 로그인 오류");

                    if token_login.status().is_success() {
                        let data = config_dir().unwrap().join("VRCX/Anti-Ripper/auth");
                        fs::write(data, &filter_cookie(token_login.cookies())).expect("파일 쓰기 오류");
                        println!("로그인 성공");
                        break;
                    }
                } else {
                    println!("2단계 인증 코드가 맞지 않습니다!");
                }
            }
            break;
        } else {
            println!("아이디 또는 비밀번호가 틀렸습니다. 다시 입력 해 주세요.");
        }
    }
}

fn get_info_from_server(user_name: String, pb: &ProgressBar) -> Value {
    let token = fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/auth")).expect("인증 토큰 파일 읽기 오류");
    let url = format!("https://api.vrchat.cloud/api/1/users?search={}&n={}", user_name, 1);
    let client = Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
    headers.insert(COOKIE, HeaderValue::from_str(&*token).expect("인증 토큰 파일 변환 오류"));

    let mut response = client.get(url.clone()).headers(headers.clone()).send().expect("브챗 데이터 다운로드 오류");
    while !response.status().is_success() {
        pb.set_message("브챗 서버가 과열 되었습니다! 식을 때 까지 대기중...");
        thread::sleep(Duration::from_secs(305));
        response = client.get(url.clone()).headers(headers.clone()).send().expect("브챗 데이터 다운로드 오류");
        pb.set_message("");
    }


    return if response.status().is_success() {
        let body = response.text().expect("브챗 데이터 읽기 오류");
        let json: Value = serde_json::from_str(&*body).expect("브챗 데이터 해석 오류");
        json
    } else {
        json!({})
    };
}

fn get_info_from_ripper(user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    fn put(base_time: DelayedFormat<StrftimeItems>, range_time: DelayedFormat<StrftimeItems>) {
        let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");
        let conn = Connection::open(database_path).expect("VRCX 데이터베이스 오류");
        let sql = format!("SELECT created_at,display_name,user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined' BETWEEN '{}' AND '{}'", base_time, range_time);
        let mut stmt = conn.prepare(&sql).expect("데이터베이스 쿼리 오류");

        let total_user = Rc::new(Cell::new(0));
        let result = stmt.query_map([], |row| {
            let total_user = Rc::clone(&total_user);
            total_user.set(total_user.get() + 1);
            Ok(UserData {
                created_at: row.get(0).expect("데이터베이스에서 created_at 값 읽기 오류"),
                display_name: row.get(1).expect("데이터베이스 display_name 값 읽기 오류"),
                user_id: row.get(2).expect("데이터베이스 user_id 값 읽기 오류"),
            })
        }).expect("데이터베이스 쿼리 실행 오류");

        get_ripper();

        for value in result {
            let data = value;
            let name = data.unwrap().display_name;

            let mut ripper_json = get_ripper();
            for mut r in ripper_json.clone() {
                if r.name == name {
                    r.count += 1;
                }
            }

            if ripper_json.iter().find(|a| a.name == name).is_none() {
                ripper_json.push(RipperData { name, count: 0 })
            }

            set_ripper(ripper_json);
        }
    }

    let client = Client::new();
    let ua = spoof_ua();

    let params = format!("?category=authorId&page={}&search={}&status=both&ordering=none&platform=all&limit=36", "1", user_id);
    let response = client.get(format!("{}{}", API_URL, params))
        .header(USER_AGENT, ua)
        .send()
        .expect("리퍼 스토어 데이터 요청 오류");
    if response.status().is_success() {
        let body = response.text().expect("리퍼 스토어 데이터 읽기 오류");
        let json: Value = serde_json::from_str(&*body).expect("리퍼 스토어 데이터 해석 오류");
        let page: u64 = json["pages"].as_u64().expect("리퍼 스토어 데이터 형식 변환 오류");

        let avatar_total = json["count"].as_u64().expect("리퍼 스토어 데이터 형식 변환 오류");
        let sty = ProgressStyle::with_template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}").expect("진행바 구문 오류").progress_chars("##-");
        let avatar_progress = ProgressBar::new(avatar_total);
        avatar_progress.set_style(sty.clone());

        for i in 0..page {
            let params = format!("?category=authorId&page={}&search={}&status=both&ordering=none&platform=all&limit=36", i + 1, user_id);
            let response = client.get(format!("{}{}", API_URL, params))
                .header(USER_AGENT, ua)
                .send()
                .expect("리퍼 스토어 데이터 요청 오류");
            if response.status().is_success() {
                let avatars = json["avatars"].as_array().expect("리퍼 스토어 데이터 형식 변환 오류");
                let mut idents = Vec::new();

                for avatar in avatars {
                    let avatar: SearchData = serde_json::from_value(avatar.clone()).expect("리퍼 스토어 데이터 해석 오류");
                    idents.push(avatar.ident);
                }

                for ident in idents {
                    let response = client.get(format!("{}?ident={}", API_DETAIL_URL, ident))
                        .header(USER_AGENT, ua)
                        .send()
                        .expect("리퍼 스토어 데이터 요청 오류");
                    if response.status().is_success() {
                        let rr = response.text().unwrap();
                        let json: AvatarItem = serde_json::from_str(&*rr).expect("리퍼 스토어 데이터 해석 오류");

                        // 생성 날짜가 없으면 검색할 수 없으므로 건너뛰기
                        if json.pc.created.is_some() {
                            // 처음 뜯긴 시간에서 뒤로 1분 범위
                            let base_time = convert_time(json.pc.created.unwrap() - 300000);

                            // 처음 뜯긴 시간에서 앞으로 1분 범위
                            let range_time = convert_time(json.pc.created.unwrap() + 300000);

                            // 뜯긴 시점에 있던 사람들 등록
                            put(base_time, range_time);

                            if json.pc.lastUpdated.is_some() {
                                // 마지막으로 뜯긴 시간에서 뒤로 1분 범위
                                let base_time = convert_time(json.pc.lastUpdated.unwrap() - 300000);

                                // 마지막으로 뜯긴 시간에서 뒤로 1분 범위
                                let range_time = convert_time(json.pc.lastUpdated.unwrap() + 300000);

                                // 뜯긴 시점에 있던 사람들 등록
                                put(base_time, range_time);
                            }
                        }

                        avatar_progress.inc(1);
                    }
                }
            }
        }
        avatar_progress.finish_and_clear();
    }

    if get_ripper().is_empty() {
        println!("검색된 리퍼 유저 데이터가 없습니다.");
        println!("뜯긴 아바타는 있는데 검색되지 않은 경우는 VRCX 사용 이전에 뜯겼거나, 리퍼 스토어가 업데이트 되기 전에 뜯겨서 날짜가 기록되지 않은 경우입니다.");
    }

    let checked = config_dir().unwrap().join("VRCX/Anti-Ripper/store_check.txt");
    fs::write(checked, "VRCX 데이터를 사용하여 리퍼 스토어에서 뜯긴 아바타를 모두 계산 했다는 확인 파일").expect("리퍼 스토어 검사 확인 파일 쓰기 오류");

    Ok(())
}

fn search_old_logs() -> Result<(), Box<dyn std::error::Error>> {
    let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");

    let conn = Connection::open(database_path).expect("VRCX 데이터베이스 오류");
    let mut stmt = conn.prepare("SELECT created_at, display_name, user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined'").expect("데이터베이스 쿼리 오류");
    let mut ready_count = 0;
    let mut data_list: Vec<UserData> = vec![];
    let parse_data = stmt.query_map([], |row| {
        Ok(UserData {
            created_at: row.get(0).expect("데이터베이스에서 created_at 값 읽기 오류"),
            display_name: row.get(1).expect("데이터베이스 display_name 값 읽기 오류"),
            user_id: row.get(2).expect("데이터베이스 user_id 값 읽기 오류"),
        })
    }).expect("데이터베이스 쿼리 실행 오류");

    for user in parse_data {
        data_list.push(user.expect("쿼리 결과 오류"));
    }

    for _ in data_list.clone().into_iter() {
        ready_count += 1;
    }

    let style = ProgressStyle::with_template("{msg}\n{wide_bar:.cyan/blue} {pos}/{len}").expect("진행바 구문 오류").progress_chars("#>-");
    let pb = ProgressBar::new(ready_count);
    pb.set_style(style);

    let mut checked = vec![];

    println!("프로그램이 VRCX 데이터에서 누락된 사용자 ID를 추가 하고 있습니다.");
    let user_list = get_user();

    let mut already_count = 0;
    for v in user_list {
        checked.push(v.display_name);
        already_count += 1;
        pb.set_message(format!("이미 저장된 데이터를 확인하는 중... {}", already_count));
    }

    for value in data_list.into_iter() {
        if checked.iter().find(|a| a.to_string() == value.display_name).is_some() {
            pb.set_message(format!("{} exists", &value.display_name.replace("\u{2028}", "").replace("\u{2029}", "")));
            pb.inc(1);
        } else {
            if value.clone().user_id.is_empty() {
                let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");
                let conn = Connection::open(database_path).expect("VRCX 데이터베이스 오류");

                pb.set_message(format!("{} 유저 데이터 다운로드중...", &value.display_name.replace("\u{2028}", "").replace("\u{2029}", "")));

                let json = get_info_from_server(value.display_name.clone(), &pb);

                let mut user_list = get_user();
                if value.display_name.clone() == json[0]["displayName"] && user_list.iter().find(|a| a.display_name == value.display_name).is_none() {
                    let mut select_query = conn.prepare(&format!("SELECT created_at FROM gamelog_join_leave WHERE display_name = {}", json[0]["displayName"])).expect("데이터베이스 쿼리 오류");
                    let result = select_query.query_map([], |row| {
                        Ok(UserData {
                            created_at: row.get(0).expect("데이터베이스에서 created_at 값 읽기 오류"),
                            display_name: json[0]["displayName"].to_string().replace("\"", ""),
                            user_id: json[0]["id"].to_string().replace("\"", ""),
                        })
                    }).expect("데이터베이스 쿼리 실행 오류");

                    for data in result {
                        user_list.push(data.expect("쿼리 결과 오류"));
                        break;
                    }

                    set_user(user_list);
                }
            } else {
                let mut user_list = get_user();
                pb.set_message(format!("{}", &value.display_name.replace("\u{2028}", "").replace("\u{2029}", "")));
                user_list.push(UserData {
                    created_at: value.created_at,
                    display_name: value.display_name.clone(),
                    user_id: value.user_id,
                });

                set_user(user_list);
            }
            checked.push(value.display_name);
            pb.inc(1);
        }
    }

    let ids = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id_done.txt");
    fs::write(ids, "모든 ID 확인이 끝났다는걸 확인하는 파일").expect("사용자 데이터 확인 완료 파일 쓰기 오류");
    pb.finish_with_message("완료");

    Ok(())
}

fn check_log(file_path: &str, m: &MultiProgress) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;

    let mut buffer = [0; 4096];
    let mut last_line = String::new();
    let mut position = file.seek(SeekFrom::End(0))? as i64;

    loop {
        let read_size = if position >= buffer.len() as i64 {
            buffer.len()
        } else {
            position as usize
        };

        position -= read_size as i64;
        file.seek(SeekFrom::Start(position as u64))?;

        file.read_exact(&mut buffer[..read_size])?;
        let read_content = String::from_utf8_lossy(&buffer[..read_size]);
        let lines: Vec<_> = read_content.lines().collect();

        if lines.len() > 1 {
            last_line = lines[lines.len() - 2].to_string();
            if last_line.chars().any(|c| c.is_alphabetic()) {
                break;
            }
        }

        if position <= 0 {
            break;
        }
    }

    let pattern = r"OnPlayerJoined\s+(\w+)";
    let re = Regex::new(pattern).expect("정규식 패턴 오류");

    if let Some(captures) = re.captures(last_line.trim()) {
        if let Some(word_after) = captures.get(1) {
            let target_name = word_after.clone().as_str().to_string();

            let pb = Arc::new(Mutex::new(m.add(ProgressBar::new(1))));
            let pb_clone = Arc::clone(&pb);
            let style = ProgressStyle::with_template("{spinner} {wide_msg}").unwrap().tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ");
            pb.lock().unwrap().set_style(style);
            pb.lock().unwrap().set_message(format!("{} - 유저 확인중...", target_name));

            let file_json: Vec<UserData> = serde_json::from_str(&*fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/user_id.json")).expect("파일 오류")).expect("JSON 구문 오류");
            let exists = file_json.iter().find(|a| target_name == a.display_name);
            if exists.is_none() {
                pb.lock().unwrap().set_message(format!("{} - 서버에서 검색중...", target_name));
                let json = get_info_from_server(last_line.as_str().to_string(), &pb.lock().unwrap());

                let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");
                let conn = Connection::open(database_path).expect("VRCX 데이터베이스 오류");

                let mut user_list: Vec<UserData> = serde_json::from_str(&*fs::read_to_string(config_dir().unwrap().join("VRCX/Anti-ripper/user_id.json")).expect("파일 오류")).expect("JSON 구문 오류");
                let mut select_query = conn.prepare(&format!("SELECT created_at FROM gamelog_join_leave WHERE display_name = {}", json[0]["displayName"])).expect("데이터베이스 쿼리 오류");
                let result = select_query.query_map([], |row| {
                    Ok(UserData {
                        created_at: row.get(0).expect("데이터베이스에서 created_at 값 읽기 오류"),
                        display_name: json[0]["displayName"].to_string().replace("\"", ""),
                        user_id: json[0]["id"].to_string().replace("\"", ""),
                    })
                }).expect("데이터베이스 쿼리 실행 오류");

                for data in result {
                    user_list.push(data.expect("쿼리 결과 오류"));
                    break;
                }

                set_user(user_list);
            } else {
                pb.lock().unwrap().set_message(format!("{} - 이미 등록된 유저", target_name));
            }
            pb.lock().unwrap().set_message(format!("{} - 확인중...", target_name));

            thread::spawn(move || {
                thread::sleep(Duration::from_secs(150));
                let result = check_current_count(&get_id());
                let pb = pb_clone.lock().unwrap();
                pb.finish_and_clear();
                if result {
                    let mut json = get_ripper();
                    let count = json.clone().iter().find(|a| a.name == target_name).expect("JSON 파싱 오류").count;

                    if let Some(index) = json.iter().position(|a| a.name == target_name) {
                        json[index].count += 1;
                        set_ripper(json);
                    }
                    play_audio();
                    println!("{} 유저가 입장했을 때 뜯겼습니다. 현재 이 유저의 감지 횟수는 {}회.", target_name, count + 1);
                }
            });
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
        .expect("리퍼 스토어 데이터 요청 오류");
    if response.status().is_success() {
        let data: AvatarList = serde_json::from_str(&*response.text().expect("리퍼 스토어 데이터 읽기 오류")).expect("리퍼 스토어 데이터 형식 캐스트 오류");
        count = data.count;

        // 아바타가 1개라도 뜯겼을 경우
        if data.count != 0 {
            // 모든 페이지를 돌아가며 아바타의 ident 값을 확인한다
            for page in 1..=data.pages {
                let response = client.get(API_URL)
                    .form(&set_params(page, user_id))
                    .header(USER_AGENT, ua)
                    .send()
                    .expect("리퍼 스토어 데이터 요청 오류");
                if response.status().is_success() {
                    let data: AvatarList = serde_json::from_str(&*response.text().expect("리퍼 스토어 데이터 읽기 오류")).expect("리퍼 스토어 데이터 형식 캐스트 오류");
                    let avatars = data.avatars;

                    for avatar in avatars.iter() {
                        idents.push(avatar.ident.clone());

                        // 모든 ident 값을 돌아가며 확인한다.
                        let idents_clone = idents.clone();
                        let cpu_thread = available_parallelism().expect("CPU 스레드 개수 읽기 오류").get();
                        let pool = ThreadPoolBuilder::new().num_threads(cpu_thread).build().expect("스레드 풀 생성 오류");

                        // 브챗 서버와 달리 리퍼 스토어는 제한이 없으므로 멀티 스레드로 한꺼번에 긁어오자
                        pool.install(|| {
                            for ident in idents_clone {
                                let client = Client::new();
                                let response = client.get(API_DETAIL_URL)
                                    .form(&[("ident", ident)])
                                    .header(USER_AGENT, ua)
                                    .send()
                                    .expect("리퍼 스토어 데이터 요청 오류");
                                if response.status().is_success() {
                                    let data: AvatarItem = serde_json::from_str(&*response.text().expect("리퍼 스토어 데이터 읽기 오류")).expect("리퍼 스토어 데이터 해석 오류");
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
            File::create(path.clone()).expect("파일 생성 오류");
        } else {
            let data: SaveData = serde_json::from_reader(File::open(path.clone()).expect("파일 읽기 오류")).expect("JSON 구문 해석 오류");
            if count != data.count {
                println!("아바타가 새로 뜯겼습니다.");
                true;
            } else {
                for value in data.avatar_list {
                    if value.updated != avatar_list.iter().find(|a| a.name == value.name).expect("JSON 파싱 오류").updated {
                        println!("{} 아바타가 또 뜯겼습니다.", value.name);
                        true;
                    }
                }
            }
        }

        // 저장
        let save = SaveData { count, idents, avatar_list };
        let file = File::open(path).expect("파일 읽기 오류");
        serde_json::to_writer(file, &save).expect("JSON 파일 쓰기 오류");
    }

    false
}

fn print_author() {
    println!("Anti-ripper {} / {} / {}", build::PKG_VERSION, build::RUST_VERSION, build::BUILD_OS);
    println!("빌드 날짜: {}", build::BUILD_TIME);
    println!();
    println!("제작자: 키에르");
    println!("Github: https://github.com/kieaer/Anti-Ripper");
}

fn auto_update() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let response = client.get("https://api.github.com/repos/kieaer/Anti-ripper/releases/latest")
        .header(USER_AGENT, PROGRAM_USER_AGENT)
        .send()
        .expect("Github 연결 오류");
    if response.status().is_success() {
        let release: Value = response.json().expect("JSON 파싱 오류");
        let tag_name = release["tag_name"].as_str().unwrap_or("Unknown");
        let description = release["body"].as_str().unwrap_or("No description available");

        if tag_name != build::PKG_VERSION {
            println!();
            println!("{} 버전이 나왔습니다. (현재 {} 버전)", tag_name, build::PKG_VERSION);
            println!();
            println!("== 업데이트 내용");
            println!("{}", description);

            self_update::backends::github::Update::configure()
                .repo_owner("Kieaer")
                .repo_name("Anti-Ripper")
                .bin_name("github")
                .show_download_progress(true)
                .current_version(cargo_crate_version!())
                .target("")
                .no_confirm(true)
                .show_output(false)
                .build()?
                .update()?;

            println!("업데이트 완료. 5초후 재시작 합니다.");
            thread::sleep(Duration::from_secs(5));
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            let args: Vec<String> = std::env::args().collect();
            cmd.args(args.iter().skip(1));
            match cmd.spawn() {
                Ok(_) => {
                    exit(0);
                }
                Err(_) => {
                    exit(1);
                }
            }
        } else {
            println!("현재 최신 버전입니다.");
        }
    } else {
        println!("업데이트 정보를 가져오는데 실패 했습니다.");
    }
    println!();
    Ok(())
}

fn play_audio() {
    let (_stream, stream_handle) = OutputStream::try_default().unwrap();
    let file = BufReader::new(File::open("alert.wav").unwrap());
    let source = Decoder::new(file).unwrap();
    stream_handle.play_raw(source.convert_samples()).unwrap();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_author();
    auto_update().expect("업데이트 확인 오류");

    fs::create_dir_all(config_dir().unwrap().join("VRCX/Anti-Ripper")).expect("폴더 생성 오류");

    let auth_token = config_dir().unwrap().join("VRCX/Anti-Ripper/auth");
    let user_id = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.txt");
    let user_json = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id_done.txt");
    let checked = config_dir().unwrap().join("VRCX/Anti-Ripper/store_check.txt");
    let version = config_dir().unwrap().join("VRCX/Anti-Ripper/updated.txt");
    let database = config_dir().unwrap().join("VRCX/VRCX.sqlite3");

    if (!version.exists() && checked.exists()) || (version.exists() && checked.exists() && fs::read_to_string(version.clone()).unwrap() == "1") {
        fs::remove_file(config_dir().unwrap().join("VRCX/Anti-Ripper/store_check.txt")).expect("파일 삭제 오류");
        fs::remove_file(config_dir().unwrap().join("VRCX/Anti-Ripper/ripper.json")).expect("파일 삭제 오류");
        fs::write(version, "2").expect("파일 쓰기 오류");
    }

    if !database.exists() {
        panic!("VRCX 가 설치되지 않았습니다. 프로그램 종료됨.");
    }

    // 자동 로그인을 위해 계정 정보 가져오기
    if !auth_token.exists() {
        login();
    }

    // VRCX 에서 누락된 데이터를 찾고 추가하기
    if !user_json.exists() {
        search_old_logs().expect("VRCX 데이터 검색 오류");
    }

    // 로그인 된 user_id 값을 확인하고 파일로 저장
    if !user_id.exists() {
        let mut file = File::open(auth_token.clone()).expect("파일 열기 오류");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("파일 읽기 오류");

        let client = Client::new();
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, PROGRAM_USER_AGENT.parse().unwrap());
        headers.insert(COOKIE, contents.parse().unwrap());
        let response = client.get(LOGIN_URL)
            .headers(headers)
            .send()
            .expect("브챗 서버 로그인 실패");
        if response.status().is_success() {
            let body = response.text().unwrap();
            let json: Value = serde_json::from_str(&*body).expect("JSON 파싱 실패");
            fs::write(user_id.clone(), json["id"].as_str().unwrap()).expect("파일 쓰기 실패");
        }
    }

    // 리퍼 스토어에서 정보 확인
    if auth_token.exists() && user_json.exists() && user_id.exists() && !checked.exists() {
        get_info_from_ripper(&get_id()).expect("리퍼 스토어 정보 확인 실패");
    }

    if auth_token.exists() && user_json.exists() && user_id.exists() && checked.exists() {
        fn is_process_running(target_process_name: &str) -> bool {
            let snapshot = unsafe { CreateToolhelp32Snapshot(0x00000002, 0) };

            if snapshot != ptr::null_mut() {
                let mut entry: PROCESSENTRY32 = PROCESSENTRY32 {
                    dwSize: std::mem::size_of::<PROCESSENTRY32>() as DWORD,
                    cntUsage: 0,
                    th32ProcessID: 0,
                    th32DefaultHeapID: 0,
                    th32ModuleID: 0,
                    cntThreads: 0,
                    th32ParentProcessID: 0,
                    pcPriClassBase: 0,
                    dwFlags: 0,
                    szExeFile: [0; MAX_PATH],
                };

                if unsafe { Process32First(snapshot, &mut entry) } != 0 {
                    loop {
                        let process_name = entry.szExeFile.iter()
                            .take_while(|&&c| c != 0)
                            .map(|&c| c as u8 as char)
                            .collect::<String>();

                        if process_name.to_lowercase() == target_process_name.to_lowercase() {
                            return true;
                        }

                        if unsafe { Process32Next(snapshot, &mut entry) } == 0 {
                            break;
                        }
                    }
                }

                unsafe { winapi::um::handleapi::CloseHandle(snapshot) };
            }

            false
        }

        thread::spawn(|| {
            loop {
                loop {
                    if is_process_running("VRChat.exe") {
                        break;
                    }

                    thread::sleep(Duration::from_secs(30));
                }

                let dir_path = home_dir().unwrap().join("AppData\\LocalLow\\VRChat\\VRChat");
                let specific_word = "output_log";
                let mut path: String = String::new();

                if let Ok(entries) = fs::read_dir(dir_path.clone()) {
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

                println!("로그 경로: {}", path.clone());

                fn get_last_modified_time(path: &str) -> SystemTime {
                    let metadata = fs::metadata(Path::new(path)).expect("Failed to read metadata");
                    metadata.modified().expect("Failed to get last modified time")
                }

                let m = MultiProgress::new();
                let mut last_modified = get_last_modified_time(&*path.clone());

                loop {
                    thread::sleep(Duration::from_millis(10));

                    let current_modified = get_last_modified_time(&*path.clone());
                    if current_modified > last_modified {
                        if !is_process_running("VRChat.exe") {
                            println!("브챗 종료됨.");
                            break;
                        }

                        check_log(String::from(path.clone()).as_str(), &m).expect("로그 읽기 실패");
                        last_modified = current_modified;
                    }
                }
            }
        });

        println!("프로그램 종료를 할 때에는 그냥 닫으시면 됩니다.");
        println!("a를 입력하여 카운트 확인.");

        loop {
            let command: String = read!();

            if command == "a" {
                let ripper_json = get_ripper();
                let user_json = get_user();
                let mut found = false;
                for value in ripper_json {
                    if value.count != 0 {
                        found = true;
                        if user_json.iter().find(|a| a.display_name == value.name).is_some() {
                            println!("{}({}) - {}회", value.name, user_json.iter().find(|a| a.display_name == value.name).unwrap().user_id, value.count);
                        } else {
                            println!("{} - {}회", value.name, value.count);
                        }
                    }
                }
                if !found {
                    println!("발견된 리퍼충이 없습니다.")
                }
            }
        }
    }

    Ok(())
}