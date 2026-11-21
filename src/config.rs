//! 配置子系统：自定义二进制配置格式 + TOTP（2FA 一次性验证码）
//!
//! 二进制格式（proposal 定义）：
//!   magic u32 LE(0x534D4146 "SMAF") | version u8 | 变长字符串字段... | appid u32 LE |
//!   heartbeat u8 | power u8 | crc32 u32 LE（覆盖 version 到 power 的所有字节）
//!
//! 变长字符串字段编码：len u8 + UTF-8 字节（ssid<=32, pass<=64, account<=32, password<=64, secret<=32）
//! v2 新增 refresh_token（len u16 + 字节，Steam 新版认证 token 较长）；v1 配置仍可解码。
//! v3 新增 auto_start（开机自动挂机）；v1/v2 配置按「自动挂机」迁移。

use crc32fast::Hasher as Crc32;

pub const CFG_MAGIC: u32 = 0x534D_4146; // "SMAF"
pub const CFG_VERSION: u8 = 3;
pub const CFG_PATH: &str = "/littlefs/config.bin";

pub const POWER_SAVE: u8 = 0;
pub const POWER_BALANCED: u8 = 1;
pub const POWER_PERF: u8 = 2;

/// 配置缺失项位掩码（见 Config::missing）
pub const MISS_WIFI: u8 = 1;
pub const MISS_ACCOUNT: u8 = 2;
pub const MISS_PASSWORD: u8 = 4;
pub const MISS_APPID: u8 = 8;

const MAX_SSID: usize = 32;
const MAX_PASS: usize = 64;
const MAX_ACCOUNT: usize = 32;
const MAX_SECRET: usize = 32;
const MAX_TOKEN: usize = 2048;

#[derive(Clone, Debug)]
pub struct Config {
    pub wifi_ssid: String,
    pub wifi_pass: String,
    pub account: String,
    pub password: String,
    /// Steam 移动令牌 shared_secret（base32，大写）
    pub shared_secret: String,
    /// Steam 新版认证得到的 refresh token（CM 登录用 access_token 字段）
    pub refresh_token: String,
    pub appid: u32,
    pub heartbeat_secs: u8,
    pub power_mode: u8,
    /// 开机后自动开始挂机（掉电/重启后无需人工点「启动挂机」）
    pub auto_start: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            wifi_ssid: String::new(),
            wifi_pass: String::new(),
            account: String::new(),
            password: String::new(),
            shared_secret: String::new(),
            refresh_token: String::new(),
            appid: 570, // 默认 Dota 2
            heartbeat_secs: 30,
            power_mode: POWER_BALANCED,
            auto_start: true,
        }
    }
}

impl Config {
    /// 缺失项位掩码：0 表示配置完整
    ///
    /// 这是"能否启动挂机"的**唯一判定规则**：Web `/api/start`、挂机线程启动、
    /// 仪表盘 `ready` 字段全部调用它，避免前后端各写一套导致规则漂移。
    pub fn missing(&self) -> u8 {
        let mut m = 0u8;
        if self.wifi_ssid.is_empty() {
            m |= MISS_WIFI;
        }
        // 凭据二选一：refresh_token，或账号+密码
        let has_creds =
            !self.refresh_token.is_empty() || (!self.account.is_empty() && !self.password.is_empty());
        if !has_creds {
            if self.account.is_empty() {
                m |= MISS_ACCOUNT;
            }
            if self.password.is_empty() {
                m |= MISS_PASSWORD;
            }
        }
        if self.appid == 0 {
            m |= MISS_APPID;
        }
        m
    }

    /// 配置是否足以启动挂机（WiFi + AppID + 凭据）
    pub fn is_ready(&self) -> bool {
        self.missing() == 0
    }

    /// 缺失项的中文描述（用于界面错误提示）
    pub fn missing_text(&self) -> String {
        let m = self.missing();
        let mut items: Vec<&str> = Vec::new();
        if m & MISS_WIFI != 0 {
            items.push("WiFi SSID");
        }
        if m & MISS_ACCOUNT != 0 {
            items.push("Steam 账号");
        }
        if m & MISS_PASSWORD != 0 {
            items.push("Steam 密码");
        }
        if m & MISS_APPID != 0 {
            items.push("AppID");
        }
        items.join("、")
    }

    /// 编码为二进制配置块
    pub fn encode(&self) -> Result<Vec<u8>, ()> {
        let mut buf: Vec<u8> = Vec::with_capacity(1200);
        buf.extend_from_slice(&CFG_MAGIC.to_le_bytes());
        buf.push(CFG_VERSION);
        put_str(&mut buf, &self.wifi_ssid, MAX_SSID)?;
        put_str(&mut buf, &self.wifi_pass, MAX_PASS)?;
        put_str(&mut buf, &self.account, MAX_ACCOUNT)?;
        put_str(&mut buf, &self.password, MAX_PASS)?;
        put_str(&mut buf, &self.shared_secret, MAX_SECRET)?;
        put_str16(&mut buf, &self.refresh_token, MAX_TOKEN)?;
        buf.extend_from_slice(&self.appid.to_le_bytes());
        buf.push(self.heartbeat_secs);
        buf.push(self.power_mode);
        buf.push(self.auto_start as u8);

        // CRC32 覆盖 version 到 power 的所有字节
        let mut crc = Crc32::new();
        crc.update(&buf[4..]);
        let crc_val = crc.finalize();
        buf.extend_from_slice(&crc_val.to_le_bytes());
        Ok(buf)
    }

    /// 从二进制配置块解码（兼容 v1：无 refresh_token；v1/v2：无 auto_start）
    pub fn decode(raw: &[u8]) -> Result<Config, &'static str> {
        if raw.len() < 4 + 1 + 4 {
            return Err("too short");
        }
        if u32::from_le_bytes(raw[0..4].try_into().unwrap()) != CFG_MAGIC {
            return Err("bad magic");
        }
        let version = raw[4];
        if version != 1 && version != 2 && version != CFG_VERSION {
            return Err("unsupported version");
        }
        let mut off = 5usize;
        let wifi_ssid = get_str(raw, &mut off, MAX_SSID)?;
        let wifi_pass = get_str(raw, &mut off, MAX_PASS)?;
        let account = get_str(raw, &mut off, MAX_ACCOUNT)?;
        let password = get_str(raw, &mut off, MAX_PASS)?;
        let shared_secret = get_str(raw, &mut off, MAX_SECRET)?;
        let refresh_token = if version >= 2 {
            get_str16(raw, &mut off, MAX_TOKEN)?
        } else {
            String::new()
        };

        if off + 6 > raw.len() {
            return Err("truncated");
        }
        let appid = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
        off += 4;
        let heartbeat_secs = raw[off];
        off += 1;
        let power_mode = raw[off];
        off += 1;
        // v3 起才有 auto_start；老配置按「开机自动挂机」迁移
        let auto_start = if version >= 3 {
            if off >= raw.len() {
                return Err("truncated");
            }
            let v = raw[off] != 0;
            off += 1;
            v
        } else {
            true
        };

        if off + 4 > raw.len() {
            return Err("no crc");
        }
        let stored_crc = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
        let mut crc = Crc32::new();
        crc.update(&raw[4..off]);
        if crc.finalize() != stored_crc {
            return Err("crc mismatch");
        }

        Ok(Config {
            wifi_ssid,
            wifi_pass,
            account,
            password,
            shared_secret,
            refresh_token,
            appid,
            heartbeat_secs,
            power_mode,
            auto_start,
        })
    }

    /// 脱敏 JSON 视图（Web 仪表盘展示用，密码/密钥打码）
    pub fn masked_json(&self) -> String {
        let pw = mask(&self.password, 2);
        let sec = mask(&self.shared_secret, 3);
        let tok = mask(&self.refresh_token, 6);
        format!(
            "{{\"wifi_ssid\":\"{}\",\"wifi_pass\":\"{}\",\"account\":\"{}\",\"password\":\"{}\",\"shared_secret\":\"{}\",\"refresh_token\":\"{}\",\"appid\":{},\"heartbeat_secs\":{},\"power_mode\":{},\"auto_start\":{},\"ready\":{}}}",
            escape_json(&self.wifi_ssid),
            escape_json(&mask(&self.wifi_pass, 2)),
            escape_json(&self.account),
            escape_json(&pw),
            escape_json(&sec),
            escape_json(&tok),
            self.appid,
            self.heartbeat_secs,
            self.power_mode,
            self.auto_start,
            self.is_ready(),
        )
    }
}

fn put_str(buf: &mut Vec<u8>, s: &str, max: usize) -> Result<(), ()> {
    let b = s.as_bytes();
    if b.len() > max {
        return Err(());
    }
    buf.push(b.len() as u8);
    buf.extend_from_slice(b);
    Ok(())
}

/// u16 长度前缀的字符串（refresh token 可能超过 255 字节）
fn put_str16(buf: &mut Vec<u8>, s: &str, max: usize) -> Result<(), ()> {
    let b = s.as_bytes();
    if b.len() > max {
        return Err(());
    }
    buf.extend_from_slice(&(b.len() as u16).to_le_bytes());
    buf.extend_from_slice(b);
    Ok(())
}

fn get_str(raw: &[u8], off: &mut usize, max: usize) -> Result<String, &'static str> {
    if *off >= raw.len() {
        return Err("truncated str");
    }
    let len = raw[*off] as usize;
    *off += 1;
    if len > max || *off + len > raw.len() {
        return Err("bad str");
    }
    let s = String::from_utf8_lossy(&raw[*off..*off + len]).to_string();
    *off += len;
    Ok(s)
}

fn get_str16(raw: &[u8], off: &mut usize, max: usize) -> Result<String, &'static str> {
    if *off + 2 > raw.len() {
        return Err("truncated str16");
    }
    let len = u16::from_le_bytes([raw[*off], raw[*off + 1]]) as usize;
    *off += 2;
    if len > max || *off + len > raw.len() {
        return Err("bad str16");
    }
    let s = String::from_utf8_lossy(&raw[*off..*off + len]).to_string();
    *off += len;
    Ok(s)
}

pub fn mask(s: &str, keep: usize) -> String {
    if s.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= keep {
        return "*".repeat(chars.len());
    }
    let mut out = String::new();
    out.extend(chars[..keep].iter());
    out.push_str(&"*".repeat(chars.len() - keep));
    out
}

/// JSON 字符串转义（所有 JSON 输出共用这一份实现）
pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// TOTP（HMAC-SHA1 + Steam 专用字母表，5 位）
// ---------------------------------------------------------------------------

/// 根据 Steam 移动令牌 shared_secret（base32）生成当前 5 位 Steam Guard 验证码
///
/// Steam 不使用 Google Authenticator 的 6 位十进制码，而是把 HMAC-SHA1 截断后的
/// 32 位整数反复对 26 取模，映射到字母表 "23456789BCDFGHJKMNPQRTVWXY"。
pub fn steam_guard_code(secret_b32: &str, timestamp_secs: u64) -> Option<String> {
    const ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
    if secret_b32.is_empty() {
        return None;
    }
    let key = base32_decode(secret_b32)?;
    if key.is_empty() {
        return None;
    }
    let counter = timestamp_secs / 30;
    let mut msg = [0u8; 8];
    msg.copy_from_slice(&counter.to_be_bytes());

    let mac = hmac_sha1(&key, &msg);
    let off = (mac[19] & 0x0f) as usize;
    let mut bin_code = ((mac[off] & 0x7f) as u32) << 24
        | ((mac[off + 1] as u32) << 16)
        | ((mac[off + 2] as u32) << 8)
        | (mac[off + 3] as u32);

    let mut out = String::with_capacity(5);
    for _ in 0..5 {
        out.push(ALPHABET[(bin_code % 26) as usize] as char);
        bin_code /= 26;
    }
    Some(out)
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha1::new();
        h.update(key);
        let d = h.finalize();
        k[..20].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    for b in k.iter_mut() {
        *b ^= 0x36;
    }
    let mut inner = Sha1::new();
    inner.update(&k);
    inner.update(data);
    let i = inner.finalize();

    for b in k.iter_mut() {
        *b ^= 0x36 ^ 0x5c;
    }
    let mut outer = Sha1::new();
    outer.update(&k);
    outer.update(i);
    let mut out = [0u8; 20];
    out.copy_from_slice(&outer.finalize());
    out
}

/// RFC 4648 base32 解码（容错：忽略空格/小写/无 padding）
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHA: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits: u64 = 0;
    let mut nbits = 0u32;
    let mut out: Vec<u8> = Vec::new();
    for c in s.chars() {
        let c = c.to_ascii_uppercase();
        if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
            continue;
        }
        let idx = ALPHA.iter().position(|&x| x == c as u8)?;
        bits = (bits << 5) | (idx as u64);
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1u64 << nbits) - 1;
        }
    }
    Some(out)
}
