use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct UserData {
    pub created_at: String,
    pub display_name: String,
    pub user_id: String
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRipperData {
    pub display_name: String,
    pub user_id: String,
    pub count: i64
}

#[derive(Deserialize)]
pub struct SearchData {
    name: String,
    image: String,
    pub ident: String,
    status: String,
    #[serde(rename = "360image")]
    image_360: Option<String>,
    isNSFW: u8,
    purchases: u64,
    platforms: Vec<String>
}