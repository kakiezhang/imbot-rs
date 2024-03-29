use actix_web::body::BoxBody;
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
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc;
use sha1::{Digest, Sha1};

use std::collections::HashMap;

use byteorder::{BigEndian, WriteBytesExt};
use chrono;
use config;
use rand::Rng;
use std::io::Write;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time;

const LETTER_BYTES: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const BLOCK_SIZE: usize = 32;

type MatesPost = HashMap<String, HashMap<String, String>>;
static DATE_FORMAT: &'static str = "%Y%m%d";

fn load_config() -> BotConfig {
    let mut settings = config::Config::default();
    settings
        .merge(config::Environment::new().prefix("APP"))
        .unwrap();
    let conf_path = settings.get_str("conf_path").unwrap();
    settings.merge(config::File::with_name(&conf_path)).unwrap();
    let mut botconf: BotConfig = settings.clone().try_into().unwrap();
    botconf.sys.aes_key = Some(WXWork::decode_aes_key(&botconf.sys.enc_aes_key));
    botconf
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Mates {
    pub name: Vec<String>,
    pub department: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Admin {
    pub name: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Web {
    port: i32,
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
    pub web_port: i32,
    pub sys: Sys,
    pub mates: Mates,
    pub adm: Admin,
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

#[derive(Debug, Deserialize)]
struct XmlDecyptMsg {
    ToUserName: String,
    FromUserName: String,
    CreateTime: i64,
    MsgType: String,
    Content: String,
    MsgId: String,
    AgentID: i32,
}

#[derive(Debug, Serialize)]
struct CDATA {
    #[serde(rename = "$value")]
    value: String,
}

#[derive(Debug, Serialize)]
struct WXBizMsg4Send {
    #[serde(rename = "xml")]
    xml_name: (),
    #[serde(rename = "Encrypt")]
    encrypt: CDATA,
    #[serde(rename = "MsgSignature")]
    signature: CDATA,
    #[serde(rename = "TimeStamp")]
    timestamp: String,
    #[serde(rename = "Nonce")]
    nonce: CDATA,
}

impl WXBizMsg4Send {
    fn new(encrypt: &str, signature: &str, timestamp: &str, nonce: &str) -> WXBizMsg4Send {
        WXBizMsg4Send {
            xml_name: (),
            encrypt: CDATA {
                value: encrypt.to_string(),
            },
            signature: CDATA {
                value: signature.to_string(),
            },
            timestamp: timestamp.to_string(),
            nonce: CDATA {
                value: nonce.to_string(),
            },
        }
    }

    fn serialize(&self) -> Result<String, CryptError> {
        let xml_msg = serde_xml_rs::to_string(self)
            .map_err(|err| CryptError::new(GEN_XML_ERROR, err.to_string()))?;
        Ok(xml_msg)
    }
}

const VALIDATE_SIGNATURE_ERROR: i32 = -40001;
const PARSE_XML_ERROR: i32 = -40002;
const COMPUTE_SIGNATURE_ERROR: i32 = -40003;
const ILLEGAL_AES_KEY: i32 = -40004;
const VALIDATE_CORPID_ERROR: i32 = -40005;
const ENCRYPT_AES_ERROR: i32 = -40006;
const DECRYPT_AES_ERROR: i32 = -40007;
const ILLEGAL_BUFFER: i32 = -40008;
const ENCODE_BASE64_ERROR: i32 = -40009;
const DECODE_BASE64_ERROR: i32 = -40010;
const GEN_XML_ERROR: i32 = -40010;
const PARSE_JSON_ERROR: i32 = -40012;
const GEN_JSON_ERROR: i32 = -40013;
const ILLEGAL_PROTOCOL_TYPE: i32 = -40014;

#[derive(Debug, Serialize)]
struct CryptError {
    err_code: i32,
    err_msg: String,
}

impl CryptError {
    fn new(err_code: i32, err_msg: String) -> CryptError {
        CryptError { err_code, err_msg }
    }
}

#[get("/callback")]
async fn get_callback(
    botconf: web::Data<Arc<Mutex<BotConfig>>>,
    req: HttpRequest,
) -> impl Responder {
    let qs = serde_qs::from_str::<QueryParams>(req.query_string());
    if qs.is_err() {
        return HttpResponse::BadRequest().body("Error parsing QueryParams");
    }
    let qs = qs.unwrap();

    if qs.echostr.is_none() {
        return HttpResponse::BadRequest().body("Error parsing echostr when validate url");
    }

    let botconf = botconf.lock().unwrap();
    let wxw = WXWork {
        sys: botconf.sys.clone(),
        timestamps: &qs.timestamp,
        nonce: &qs.nonce,
        _tag: PhantomData::default(),
    };
    let msg = wxw.decrypt(&qs.msg_signature, &qs.echostr.unwrap());
    if msg.is_err() {
        return HttpResponse::BadRequest().body(msg.unwrap_err());
    }
    let msg = msg.unwrap();

    HttpResponse::Ok().body(msg)
}

fn aes_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let mut iv: [u8; 16] = [0; 16];
    iv.copy_from_slice(&key[..16]);

    let mut buf = vec![0u8; plaintext.len()];

    let ciphertext = Aes256CbcEnc::new(key.into(), &iv.into())
        .encrypt_padded_b2b_mut::<NoPadding>(&plaintext, &mut buf)
        .unwrap();
    ciphertext.to_vec()
}

fn aes_decrypt(encrypted_data: &[u8], key: &[u8]) -> Vec<u8> {
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let mut iv: [u8; 16] = [0; 16];
    iv.copy_from_slice(&key[..16]);

    let mut buf = vec![0u8; encrypted_data.len()];

    println!("key: {:?}", key);
    println!("iv: {:?}", iv);
    println!("encrypted_data: {:?}", encrypted_data);

    let plaintext = Aes256CbcDec::new(key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<NoPadding>(&encrypted_data, &mut buf)
        .unwrap();
    plaintext.to_vec()
}

fn pkcs7_padding(plaintext: Vec<u8>, block_size: usize) -> Vec<u8> {
    let padding = block_size - (plaintext.len() % block_size);
    let padtext = vec![padding as u8; padding];
    let mut buffer = Vec::with_capacity(plaintext.len() + padding);

    buffer.write_all(&plaintext).unwrap();
    buffer.write_all(&padtext).unwrap();

    buffer
}

fn pkcs7_unpadding(mut plaintext: Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
    let plaintext_len = plaintext.len();

    if plaintext.is_empty() || plaintext_len == 0 {
        return Err("pKCS7Unpadding error nil or zero");
    }

    if plaintext_len % block_size != 0 {
        return Err("pKCS7Unpadding text not a multiple of the block size");
    }

    let padding_len = plaintext[plaintext_len - 1] as usize;
    if padding_len > block_size || padding_len == 0 {
        return Err("pKCS7Unpadding invalid padding length");
    }

    plaintext.truncate(plaintext_len - padding_len);
    Ok(plaintext)
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

fn rand_str(n: usize) -> String {
    let mut rng = rand::thread_rng();

    let mut result = Vec::with_capacity(n);
    for _ in 0..n {
        let idx = rng.gen_range(0..LETTER_BYTES.len());
        result.push(LETTER_BYTES[idx]);
    }

    String::from_utf8(result).unwrap()
}

#[derive(Debug)]
struct WXWork<'a, 'b> {
    sys: Sys,
    timestamps: &'a str,
    nonce: &'a str,
    _tag: PhantomData<&'b str>,
}

impl<'a, 'b> WXWork<'a, 'b> {
    pub fn decode_aes_key(enc_aes_key: &str) -> Vec<u8> {
        let mut encoding_aes_key = String::from(enc_aes_key);
        encoding_aes_key.push('=');
        base64_decode(&encoding_aes_key)
    }

    pub fn get_sign(&self, data: &str) -> String {
        // Sort the parameters in dictionary order and concatenate them into a single string.
        let mut params = vec![
            ("token", self.sys.token.as_str()),
            ("timestamp", self.timestamps),
            ("nonce", self.nonce),
            ("msg_encrypt", data),
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
        signature_calculated
    }

    pub fn decrypt(&self, signature: &str, data: &str) -> Result<String, &'b str> {
        let signature_calculated = self.get_sign(data);

        // Compare the calculated signature with the provided signature.
        if signature_calculated == signature {
            println!("Signature is valid!");
        } else {
            return Err("Signature is invalid!");
        }

        // Decode the base64-encoded AES message.
        let aes_msg = base64_decode(data);
        println!("aes_msg: {:?}", aes_msg);
        println!("aes_msg_cnt: {:?}", aes_msg.len());

        // println!("aes_key: {:?}", &self.sys.aes_key);

        if self.sys.aes_key.is_none() {
            return Err("aes_key is none");
        }

        // Decrypt the AES message using the AES key.
        let mut rand_msg = aes_decrypt(&aes_msg, &self.sys.aes_key.clone().unwrap());

        match pkcs7_unpadding(rand_msg, BLOCK_SIZE) {
            Ok(res) => {
                rand_msg = res;
            }
            Err(e) => {
                return Err(e);
            }
        };

        // Get the content by removing the first 16 random bytes.
        let content = &rand_msg[16..];

        // Get the message length (4 bytes) and convert it to an unsigned integer.
        let msg_len_bytes = &content[..4];
        let msg_len = str_to_uint(msg_len_bytes) as usize;

        // Extract the message (from index 4 to msg_len+4).
        let msg = &content[4..(msg_len + 4)];

        // The remaining bytes after the message are assigned to `receiveid`.
        let receiveid = &content[(msg_len + 4)..];
        println!("Receiveid: {:?}", std::str::from_utf8(&receiveid).unwrap());

        // std::str::from_utf8(&msg).unwrap()

        match String::from_utf8(msg.to_vec()) {
            Ok(rs) => Ok(rs),
            Err(_) => Err("msg data conv from vec to utf8-str failed"),
        }
    }

    pub fn encrypt(&self, reply_msg: String) -> Result<String, CryptError> {
        let rand_str = rand_str(16);

        let mut buffer = Vec::new();
        buffer.extend_from_slice(rand_str.as_bytes());

        let mut msg_len_buf = vec![0; 4];
        (&mut msg_len_buf[..])
            .write_u32::<BigEndian>(reply_msg.len() as u32)
            .unwrap();
        buffer.extend_from_slice(&msg_len_buf);

        buffer.extend_from_slice(reply_msg.as_bytes());
        buffer.extend_from_slice(self.sys.corp_id.as_bytes());

        let pad_msg = pkcs7_padding(buffer, BLOCK_SIZE);

        let ciphertext = aes_encrypt(&pad_msg, &self.sys.aes_key.clone().unwrap());

        let ciphertext = engine::GeneralPurpose::new(
            &alphabet::STANDARD,
            general_purpose::PAD.with_decode_allow_trailing_bits(true),
        )
        .encode(ciphertext);

        let signature = self.get_sign(&ciphertext);

        Ok(format!("<xml><Encrypt><![CDATA[{}]]></Encrypt><MsgSignature><![CDATA[{}]]></MsgSignature><TimeStamp>{}</TimeStamp><Nonce><![CDATA[{}]]></Nonce></xml>", ciphertext, signature, self.timestamps, self.nonce))
    }
}

#[post("/callback")]
async fn post_callback(
    botconf: web::Data<Arc<Mutex<BotConfig>>>,
    mates_post: web::Data<Arc<Mutex<MatesPost>>>,
    req: HttpRequest,
    query_str: String,
) -> impl Responder {
    let rd = serde_xml_rs::from_str::<XmlRecvData>(&query_str);
    if rd.is_err() {
        return HttpResponse::BadRequest().body("Failed to parse XmlRecvData");
    }
    let rd = rd.unwrap();

    let qs = serde_qs::from_str::<QueryParams>(req.query_string());
    if qs.is_err() {
        return HttpResponse::BadRequest().body("Error parsing QueryParams");
    }
    let qs = qs.unwrap();

    let botconf = botconf.lock().unwrap();
    let wxw = WXWork {
        sys: botconf.sys.clone(),
        timestamps: &qs.timestamp,
        nonce: &qs.nonce,
        _tag: PhantomData::default(),
    };
    let msg = wxw.decrypt(&qs.msg_signature, &rd.Encrypt);
    if msg.is_err() {
        return HttpResponse::BadRequest().body(msg.unwrap_err());
    }
    let msg = msg.unwrap();

    let dm = serde_xml_rs::from_str::<XmlDecyptMsg>(&msg);
    if dm.is_err() {
        return HttpResponse::BadRequest().body("Failed to parse XmlDecyptMsg");
    }
    let dm = dm.unwrap();

    println!("dm: {:?}", dm);

    let mate_name;
    let content;
    match dm.MsgType.as_str() {
        "text" => {
            mate_name = &dm.FromUserName;
            content = &dm.Content;
        }
        _ => {
            return HttpResponse::BadRequest().body("Unknown decrypt MsgType");
        }
    };

    let mut mates_post = mates_post.lock().unwrap();

    let date = chrono::Local::now().format(DATE_FORMAT).to_string();

    if botconf.adm.name.contains(mate_name) {
        if content.contains(&date) {
            match get_posts(&botconf.mates.department, &date, &mates_post) {
                Ok(res) => {
                    return send_http(&wxw, res);
                }
                Err(e) => {
                    return send_http(&wxw, e.to_string());
                }
            };
        }
    }

    if !botconf.mates.name.contains(mate_name) {
        return send_http(&wxw, format!("{} is not our mates", mate_name));
    }

    mates_post
        .entry(date.clone())
        .or_insert_with(HashMap::new)
        .insert(mate_name.to_string(), content.to_string());

    if mates_post.get(&date).unwrap().len() == botconf.mates.name.len() {
        match get_posts(&botconf.mates.department, &date, &mates_post) {
            Ok(res) => {
                return send_http(&wxw, res);
            }
            Err(e) => {
                return send_http(&wxw, e.to_string());
            }
        };
    }

    send_http(&wxw, format!("Thank you, {}", mate_name))
}

fn send_http(wxw: &WXWork, res: String) -> HttpResponse<BoxBody> {
    match wxw.encrypt(res) {
        Ok(x) => {
            return HttpResponse::Ok().body(x);
        }
        Err(e) => {
            return HttpResponse::BadRequest().json(e);
        }
    };
}

fn get_posts(department: &str, date: &str, mates_post: &MatesPost) -> Result<String, &'static str> {
    if let Some(mate_contents) = mates_post.get(date) {
        let mut result = String::new();
        for (mate_name, content) in mate_contents {
            result.push_str(&format!("\n{}: \n\n{}\n", mate_name, content));
        }
        result.insert_str(0, &format!("# {}@{}\n", department, date));
        Ok(result)
    } else {
        Err("No mates found for the given date.")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mates_post: MatesPost = HashMap::new();
    let mates_post = Arc::new(Mutex::new(mates_post));

    let config = load_config();
    let webport = config.web_port;
    if webport <= 1024 {
        panic!("web port must be greater than 1024.");
    }
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
            .app_data(web::Data::new(mates_post.clone()))
            .service(get_callback)
            .service(post_callback)
    })
    .bind(format!("0.0.0.0:{}", webport))?
    .run()
    .await
}
