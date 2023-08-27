use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    pub created_at: String,
    pub display_name: String,
    pub user_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SaveData {
    pub count: u32,
    pub idents: Vec<String>,
    pub avatar_list: Vec<AvatarData>,
}

#[derive(Serialize, Deserialize)]
pub struct ParseData {
    display_name: String,
    id: String,
}

#[derive(Serialize, Deserialize)]
pub struct AvatarData {
    pub name: String,
    pub created: u64,
    pub added: u64,
    pub updated: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SearchData {
    pub name: String,
    pub img: String,
    pub ident: String,
    pub status: String,
    #[serde(rename = "360image")]
    pub _360image: u32,
    pub isNSFW: u32,
    pub purchases: u32,
    pub platforms: Vec<String>,
    pub image: String,
}

#[derive(Debug, Deserialize)]
pub struct AvatarList {
    pub count: u32,
    pub pages: u32,
    pub avatars: Vec<Avatar>,
}


#[derive(Debug, Deserialize)]
pub struct Hierarchy {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct PcInfo {
    pub version: u32,
    pub size: u64,
    pub unityVersion: String,
    pub platform: String,
    pub dateAdded: u64,
    pub lastUpdated: Option<u64>,
    pub created: u64,
}

#[derive(Debug, Deserialize)]
pub struct Avatar {
    pub ident: String,
    pub img: String,
    pub isNSFW: u32,
    pub image: String,
}

#[derive(Debug, Deserialize)]
pub struct MoreFromAuthor {
    pub avatars: Vec<Avatar>,
    pub avatarsCount: u32,
}

#[derive(Debug, Deserialize)]
pub struct Item {
    pub isLoggedIn: bool,
    pub isPurchased: bool,
    pub isNSFW: u32,
    pub has360Image: bool,
    pub hierarchy: String,
    pub price: u32,
    pub authorName: String,
    pub authorId: Option<String>,
    pub name: String,
    pub description: String,
    pub image: String,
    pub status: String,
    pub platforms: Vec<String>,
    pub pc: PcInfo,
    pub moreFromAuthor: MoreFromAuthor,
}