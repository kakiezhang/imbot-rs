use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use base64;
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};

use serde::{Deserialize, Serialize};
use serde_qs;
use serde_xml_rs;

use aes;
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use cbc;
use sha1::{Digest, Sha1};

use std::collections::HashMap;

use chrono::{Datelike, Timelike, Utc};
use config;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;

// 定义全局变量
type MatesData = Arc<Mutex<HashMap<String, HashMap<String, String>>>>;
static DATE_FORMAT: &'static str = "%Y-%m-%d";

fn load_config() -> BotConfig {
    let mut settings = config::Config::default();
    settings
        .merge(config::Environment::new().prefix("APP"))
        .unwrap();
    settings.merge(config::File::with_name("config")).unwrap();
    let mut botconf: BotConfig = settings.clone().try_into().unwrap();
    botconf.sys.aes_key = Some(WXWork::decode_aes_key(&botconf.sys.enc_aes_key));
    botconf
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Mates {
    pub name: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Sys {
    corp_id: String,
    token: String,
    enc_aes_key: String,
    aes_key: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct BotConfig {
    pub mates: Mates,
    pub sys: Sys,
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    msg_signature: String,
    timestamp: String,
    nonce: String,
    echostr: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XmlRecvData {
    ToUserName: String,
    AgentID: String,
    Encrypt: String,
}

// 表单结构体
#[derive(Debug, Deserialize)]
struct GreetMessage {
    name: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct IncomingMessage {
    msgtype: String,
    text: Option<MessageContent>,
    // 在这里可以添加其他消息类型的字段
}

#[derive(Debug, Deserialize, Serialize)]
struct MessageContent {
    content: String,
}

#[derive(Debug, Serialize)]
struct OutgoingMessage {
    msgtype: String,
    text: MessageContent,
}

#[get("/callback")]
async fn get_callback(data: web::Data<Arc<Mutex<BotConfig>>>, req: HttpRequest) -> impl Responder {
    // 获取原始的查询字符串
    println!("Request query_string：{}", req.query_string());

    // 打印所有的request header
    println!("Request Headers：{:?}", req.headers());

    // wxdecrypt();

    let config = data.lock().unwrap();
    println!("botconf: {:?}", config);

    HttpResponse::Ok().body("Hello, this is a GET request.")
}

fn aes_decrypt(encrypted_data: &[u8], key: &[u8]) -> Vec<u8> {
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let mut iv: [u8; 16] = [0; 16];
    iv.copy_from_slice(&key[..16]);

    let mut buf = vec![0u8; encrypted_data.len()];

    println!("key: {:?}", key);
    println!("iv: {:?}", iv);
    println!("encrypted_data: {:?}", encrypted_data);

    let pt = Aes256CbcDec::new(key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<NoPadding>(&encrypted_data, &mut buf)
        .unwrap();
    pt.to_vec()
}

fn base64_decode(s: &str) -> Vec<u8> {
    let bytes = engine::GeneralPurpose::new(
        &alphabet::STANDARD,
        general_purpose::PAD.with_decode_allow_trailing_bits(true),
    )
    .decode(s)
    .unwrap();
    bytes
}

// Function to convert the first 4 bytes of a slice into an unsigned integer.
fn str_to_uint(slice: &[u8]) -> u32 {
    ((slice[0] as u32) << 24)
        | ((slice[1] as u32) << 16)
        | ((slice[2] as u32) << 8)
        | (slice[3] as u32)
}

#[derive(Debug)]
struct WXWork<'a> {
    sys: Sys,
    signature: &'a str,
    timestamps: &'a str,
    nonce: &'a str,
    msg_encrypt: &'a str,
}

impl<'a> WXWork<'a> {
    pub fn decode_aes_key(enc_aes_key: &str) -> Vec<u8> {
        let mut encoding_aes_key = String::from(enc_aes_key);
        encoding_aes_key.push('=');
        base64_decode(&encoding_aes_key)
    }

    pub fn decrypt(&self) {
        // Sort the parameters in dictionary order and concatenate them into a single string.
        let mut params = vec![
            ("token", self.sys.token.as_str()),
            ("timestamp", self.timestamps),
            ("nonce", self.nonce),
            ("msg_encrypt", self.msg_encrypt),
        ];
        params.sort_by(|a, b| a.1.cmp(b.1));
        let sorted_params: String = params
            .iter()
            .map(|(key, value)| format!("{}", value))
            .collect();

        println!("sorted_params: {}", sorted_params);

        // Calculate the SHA1 hash of the sorted parameters string.
        let mut hasher = Sha1::new();
        hasher.update(sorted_params.as_bytes());
        let sha1_hash = hasher.finalize();
        println!("sha1_hash: {:?}", sha1_hash);

        // Convert the SHA1 hash to a hexadecimal string.
        let signature_calculated = format!("{:x}", sha1_hash);
        println!("signature_calculated: {}", signature_calculated);

        // Compare the calculated signature with the provided signature.
        if signature_calculated == self.signature {
            println!("Signature is valid!");
        } else {
            println!("Signature is invalid!");
            return;
        }

        // Decode the base64-encoded AES message.
        let aes_msg = base64_decode(self.msg_encrypt);
        println!("aes_msg: {:?}", aes_msg);
        println!("aes_msg_cnt: {:?}", aes_msg.len());

        // println!("aes_key: {:?}", &self.sys.aes_key);

        if self.sys.aes_key.is_none() {
            println!("aes_key is none");
            return;
        }

        // Decrypt the AES message using the AES key.
        let rand_msg = aes_decrypt(&aes_msg, &self.sys.aes_key.clone().unwrap());

        // Get the content by removing the first 16 random bytes.
        let content = &rand_msg[16..];

        // Get the message length (4 bytes) and convert it to an unsigned integer.
        let msg_len_bytes = &content[..4];
        let msg_len = str_to_uint(msg_len_bytes) as usize;

        // Extract the message (from index 4 to msg_len+4).
        let msg = &content[4..(msg_len + 4)];

        // The remaining bytes after the message are assigned to `receiveid`.
        let receiveid = &content[(msg_len + 4)..];

        println!("Message: {:?}", std::str::from_utf8(&msg).unwrap());

        println!("Receiveid: {:?}", std::str::from_utf8(&receiveid).unwrap());
    }
}

#[post("/callback")]
async fn post_callback(
    data: web::Data<Arc<Mutex<BotConfig>>>,
    req: HttpRequest,
    query_str: String,
) -> impl Responder {
    let xml = serde_xml_rs::from_str::<XmlRecvData>(&query_str);
    if xml.is_err() {
        HttpResponse::BadRequest().body("Failed to parse XML data");
    }
    let xml = xml.unwrap();

    let qs = serde_qs::from_str::<QueryParams>(req.query_string());
    if qs.is_err() {
        HttpResponse::BadRequest().body("Error parsing query parameters");
    }
    let qs = qs.unwrap();

    let config = data.lock().unwrap();
    let wxw = WXWork {
        sys: config.sys.clone(),
        signature: &qs.msg_signature,
        timestamps: &qs.timestamp,
        nonce: &qs.nonce,
        msg_encrypt: &xml.Encrypt,
    };
    wxw.decrypt();

    HttpResponse::Ok().body("Hello, this is a Post request.")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mates: MatesData = Arc::new(Mutex::new(HashMap::new()));

    let config = load_config();
    let shared_config = Arc::new(Mutex::new(config));
    let shared_config_clone = shared_config.clone();

    tokio::spawn(async move {
        loop {
            time::sleep(Duration::from_secs(5)).await;

            let mut locked_config = shared_config_clone.lock().unwrap();
            *locked_config = load_config();
        }
    });

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(shared_config.clone()))
            .app_data(web::Data::new(mates.clone()))
            .service(get_callback)
            .service(post_callback)
    })
    .bind("127.0.0.1:9000")?
    .run()
    .await
}
