use std::cell::Cell;
use std::collections::HashMap;
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::header::{HeaderValue, COOKIE, USER_AGENT, AUTHORIZATION, HeaderMap};
use base64::{Engine as _, engine::general_purpose};
use reqwest::cookie::Cookie;
use text_io::read;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::rc::Rc;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use chrono::format::{DelayedFormat, StrftimeItems};
use dirs::config_dir;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use ua_generator::ua::spoof_ua;

const LOGIN_URL: &str = "https://api.vrchat.cloud/api/1/auth/user";
const TOTP_URL: &str = "https://api.vrchat.cloud/api/1/auth/twofactorauth/totp/verify";
const EMAIL_URL: &str = "https://api.vrchat.cloud/api/1/auth/twofactorauth/emailotp/verify";
const API_URL: &str = "https://api.ripper.store/api/v2/avatars/search";
const API_DETAIL_URL: &str = "https://api.ripper.store/api/v2/avatars/detail";
const PROGRAM_USER_AGENT: &str = "Ripper Store User Detector / dev cloud9350@naver.com";

fn filter_cookie<'a>(response: impl Iterator<Item = Cookie<'a>> + 'a) -> String {
    return response.collect::<Vec<_>>().iter().map(|cookie| format!("{}={}", cookie.name(), cookie.value())).collect::<Vec<_>>().join("; ");
}

fn login() -> Result<(), Box<dyn std::error::Error>> {
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

struct UserData {
    display_name: String,
    user_id: String
}

#[derive(Debug, Serialize, Deserialize)]
struct UserRipperData {
    display_name: String,
    user_id: String,
    count: i64
}
#[derive(Deserialize)]
struct SearchData {
    name: String,
    image: String,
    ident: String,
    status: String,
    #[serde(rename = "360image")]
    image_360: Option<String>,
    isNSFW: u8,
    purchases: u64,
    platforms: Vec<String>,
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
                let sql = format!("SELECT display_name,user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined' BETWEEN '{}' AND '{}'", base_time, range_time);
                let mut stmt = conn.prepare(&sql)?;

                let total_user = Rc::new(Cell::new(0));
                let result = stmt.query_map([], |row| {
                    let total_user = Rc::clone(&total_user);
                    total_user.set(total_user.get() + 1);
                    Ok(UserData {
                        display_name: row.get(0)?,
                        user_id: row.get(1)?,
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

                    let sql = format!("SELECT display_name,user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined' BETWEEN '{}' AND '{}'", base_time, range_time);
                    let mut stmt = conn.prepare(&sql)?;

                    let total_user = Rc::new(Cell::new(0));
                    let result = stmt.query_map([], |row| {
                        let total_user = Rc::clone(&total_user);
                        total_user.set(total_user.get() + 1);
                        Ok(UserData {
                            display_name: row.get(0)?,
                            user_id: row.get(1)?,
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

fn search_old_logs() -> Result<(), Box<dyn std::error::Error>> {
    let database_path = config_dir().unwrap().join("VRCX/VRCX.sqlite3");
    let conn = Connection::open(database_path)?;
    let mut stmt = conn.prepare("SELECT display_name, user_id FROM gamelog_join_leave WHERE type='OnPlayerJoined'")?;
    let count_result = stmt.query_map([], |row| {
        Ok(UserData {
            display_name: row.get(0)?,
            user_id: row.get(1)?,
        })
    })?;

    let ready_count = Rc::new(Cell::new(0));
    for data in count_result {
        if !data.unwrap().user_id.is_empty() {
            ready_count.set(ready_count.get() + 1);
        }
    }

    let result = stmt.query_map([], |row| {
        Ok(UserData {
            display_name: row.get(0)?,
            user_id: row.get(1)?,
        })
    })?;

    let mut checked = Vec::new();

    println!("프로그램이 VRCX 데이터에서 누락된 사용자 ID를 추가 하고 있습니다.");
    println!("절대로 창을 닫지 말아주세요. (닫으면 VRCX 데이터가 증발합니다)");

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
                let update = |display_name: String, user_id: String| -> Result<(), rusqlite::Error> {
                    let mut stmt = conn.prepare("UPDATE gamelog_join_leave SET user_id = ?1 WHERE display_name = ?2")?;
                    stmt.execute(params![display_name, user_id])?;
                    Ok(())
                };

                if response.status().is_success() {
                    let body = response.text().unwrap();
                    let json: Value = serde_json::from_str(&*body)?;
                    if data.display_name == json["display_name"] {
                        update(data.display_name, json["display_name"].to_string())?;
                    }
                    checked.push(display_name);
                }
            }
            pb.inc(1);
        }
    }
    pb.finish();

    let checked = config_dir().unwrap().join("VRCX/Anti-Ripper/db_check.txt");
    fs::write(checked, "VRCX 에서 기록되지 않은 user_id 값을 모두 검사했다는 것을 확인한 파일")?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(config_dir().unwrap().join("VRCX/Anti-Ripper"))?;

    let auth_token = config_dir().unwrap().join("VRCX/Anti-Ripper/auth");
    let checked = config_dir().unwrap().join("VRCX/Anti-Ripper/db_check.txt");
    let user_id = config_dir().unwrap().join("VRCX/Anti-Ripper/user_id.txt");

    if !auth_token.exists() {
        login()?;
    }
    if !checked.exists() {
        search_old_logs()?;
    }
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

    if auth_token.exists() && checked.exists() {
        let mut file = File::open(user_id.clone())?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        search_store(&text)?;
    }

    Ok(())

    // 감시 코드 작성
}