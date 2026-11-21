//! Steam CM 协议：protobuf wire 编解码 + Steam 标准消息帧封装
//!
//! 帧格式（WebSocket 二进制帧直接承载，SteamKit 标准）：
//!   emsg u32le(最高位=protobuf 标志) | header_len u32le | header | body
//!
//! EMsg 常量（SteamKit 3.5.0 EMsg.cs 确认）：
//!   ClientHello=9805, ClientLogon=5514, ClientLogOnResponse=751,
//!   ClientHeartBeat=703, ClientGamesPlayed=742, ClientLoggedOff=757

pub const EMsg_CLIENT_HELLO: u32 = 9805;
pub const EMsg_CLIENT_LOGON: u32 = 5514;
pub const EMsg_CLIENT_LOGON_RESPONSE: u32 = 751;
pub const EMsg_CLIENT_HEARTBEAT: u32 = 703;
pub const EMsg_CLIENT_GAMES_PLAYED: u32 = 742;
pub const EMsg_CLIENT_LOGGED_OFF: u32 = 757;
/// PICS 产品信息查询：用于登录后校验 AppID 是否存在
pub const EMsg_CLIENT_PICS_PRODUCT_INFO_REQUEST: u32 = 8903;
pub const EMsg_CLIENT_PICS_PRODUCT_INFO_RESPONSE: u32 = 8904;

/// EMsg.Multi：CM 用于把较大的消息（如统一消息服务响应）打包下发，
/// body 为 CMsgMulti{ size_unzipped(1), message_body(2) }，
/// message_body 为「[u32 子消息长度][子消息]…」，size_unzipped>0 时经 gzip 压缩。
pub const EMsg_MULTI: u32 = 1;

pub const PROTOCOL_VERSION: u32 = 65581;

/// 首登时 CMsgProtoBufHeader.steamid 的取值：universe=Public(1)、type=Individual(1)、
/// instance=1、accountid=0，即 76561197960265728。
///
/// SteamKit `SteamUser.LogOn()` 会在 proto header 里显式写入该值，header 因此非空。
/// 固件此前发送 header_len=0（空 header），与参考实现不一致。
pub const STEAM_ID_UNKNOWN: u64 = 76_561_197_960_265_728;

/// 已解析的帧
#[derive(Debug, Clone)]
pub struct Frame {
    pub emsg: u32,
    pub header: Vec<u8>,
    pub body: Vec<u8>,
}

// ---------------------------------------------------------------------------
// protobuf wire
// ---------------------------------------------------------------------------

pub fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(b);
            break;
        }
        buf.push(b | 0x80);
    }
}

pub fn put_str_field(buf: &mut Vec<u8>, field: u32, s: &str) {
    put_varint(buf, ((field as u64) << 3) | 2); // wire 2: length-delimited
    put_varint(buf, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

pub fn put_varint_field(buf: &mut Vec<u8>, field: u32, v: u64) {
    put_varint(buf, (field as u64) << 3); // wire 0: varint
    put_varint(buf, v);
}

pub fn put_bool_field(buf: &mut Vec<u8>, field: u32, v: bool) {
    put_varint_field(buf, field, v as u64);
}

pub fn put_bytes_field(buf: &mut Vec<u8>, field: u32, data: &[u8]) {
    put_varint(buf, ((field as u64) << 3) | 2);
    put_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

pub fn put_fixed64_field(buf: &mut Vec<u8>, field: u32, v: u64) {
    put_varint(buf, ((field as u64) << 3) | 1); // wire 1: fixed64
    buf.extend_from_slice(&v.to_le_bytes());
}

/// 解析第一个 varint 字段（field 匹配）的值
pub fn get_varint_field(body: &[u8], field: u32) -> Option<u64> {
    let mut i = 0usize;
    while i < body.len() {
        let (tag, ni) = read_varint(body, i)?;
        i = ni;
        let f = (tag >> 3) as u32;
        let w = (tag & 7) as u8;
        if w == 0 {
            let (v, ni) = read_varint(body, i)?;
            i = ni;
            if f == field {
                return Some(v);
            }
        } else if w == 2 {
            let (len, ni) = read_varint(body, i)?;
            i = ni + len as usize;
        } else if w == 5 {
            i += 4;
        } else if w == 1 {
            i += 8;
        } else {
            return None;
        }
    }
    None
}

fn read_varint(body: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        if i >= body.len() || shift > 63 {
            return None;
        }
        let b = body[i];
        i += 1;
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((v, i));
        }
        shift += 7;
    }
}

// ---------------------------------------------------------------------------
// 帧封装
// ---------------------------------------------------------------------------

/// 组装 Steam 标准消息帧（WebSocket 二进制帧直接承载）
pub fn make_frame(emsg: u32, header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + header.len() + body.len());
    out.extend_from_slice(&(emsg | 0x8000_0000).to_le_bytes());
    out.extend_from_slice(&(header.len() as u32).to_le_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(body);
    out
}

/// 解析单条完整 WebSocket 消息（服务器每条二进制帧 = 一条完整 Steam 消息）
pub fn parse_message(payload: &[u8]) -> Option<Frame> {
    if payload.len() < 8 {
        return None;
    }
    let emsg = u32::from_le_bytes(payload[0..4].try_into().ok()?) & 0x7fff_ffff;
    let hlen = u32::from_le_bytes(payload[4..8].try_into().ok()?) as usize;
    if 8 + hlen > payload.len() {
        return None;
    }
    let header = payload[8..8 + hlen].to_vec();
    let body = payload[8 + hlen..].to_vec();
    Some(Frame { emsg, header, body })
}

// ---------------------------------------------------------------------------
// 消息构造
// ---------------------------------------------------------------------------

/// CMsgClientHello（登录握手第一帧）
///
/// 严格对齐 SteamKit CMClient.OnClientConnected：只置 protocol_version(field 1)=65581。
/// 不要再写其它字段：CMsgClientHello 在 Steam 端 schema 中仅此一个字段，多写的未知
/// 字段会被当作会话相关字段解析，导致后续未登录态服务调用（9804）被静默丢弃。
pub fn build_client_hello() -> Vec<u8> {
    let mut body = Vec::new();
    put_varint_field(&mut body, 1, PROTOCOL_VERSION as u64); // protocol_version
    make_frame(EMsg_CLIENT_HELLO, &[], &body)
}

/// CMsgClientLogon（登录请求）
///
/// 字段集对齐 SteamKit/ASF（CMsgClientLogon）：
/// 1 protocol_version, 5 client_package_version, 6 client_language,
/// 7 client_os_type, 8 should_remember_password, 50 account_name,
/// 51 password, 96 machine_name, 100 client_instance_id,
/// 101 two_factor_code, 102 supports_rate_limit_response,
/// 108 access_token
///
/// `access_token` 为 Steam 新版认证（IAuthenticationService）拿到的 **refresh token**。
/// 2026 年起 CM 的明文密码登录通道已废弃：无论密码对错一律返回
/// EResult=5(InvalidPassword)，必须改用 access_token 登录（ASF 亦如此）。
pub fn build_client_logon(
    account: &str,
    password: &str,
    two_factor: Option<&str>,
    client_instance_id: u32,
    access_token: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    put_varint_field(&mut body, 1, PROTOCOL_VERSION as u64);
    put_varint_field(&mut body, 5, 1771); // client_package_version
    put_str_field(&mut body, 6, "schinese"); // client_language
    put_varint_field(&mut body, 7, 0x11); // client_os_type
    put_bool_field(&mut body, 8, true); // should_remember_password
    if !account.is_empty() {
        put_str_field(&mut body, 50, account);
    }
    if let Some(token) = access_token {
        put_str_field(&mut body, 108, token); // access_token（refresh token）
    } else {
        put_str_field(&mut body, 51, password);
        if let Some(code) = two_factor {
            put_str_field(&mut body, 101, code);
        }
    }
    put_str_field(&mut body, 96, "ESP32C3-SM-ASF"); // machine_name
    put_varint_field(&mut body, 100, client_instance_id as u64);
    put_bool_field(&mut body, 102, true); // supports_rate_limit_response
    make_frame(EMsg_CLIENT_LOGON, &build_logon_header(), &body)
}

/// CMsgProtoBufHeader（登录用）：fixed64 field 1 = steamid
fn build_logon_header() -> Vec<u8> {
    build_msg_header(STEAM_ID_UNKNOWN)
}

/// 生成消息头：steamid != 0 时写入 CMsgProtoBufHeader.steamid（fixed64 field 1），
/// 否则返回空 header（ClientHello 等登录前消息）。登录成功后应使用服务器下发的真实 steamid。
pub fn build_msg_header(steam_id: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(9);
    if steam_id != 0 {
        put_fixed64_field(&mut header, 1, steam_id);
    }
    header
}

/// CMsgClientHeartBeat
pub fn build_heartbeat(steam_id: u64) -> Vec<u8> {
    make_frame(EMsg_CLIENT_HEARTBEAT, &build_msg_header(steam_id), &[])
}

/// CMsgClientGamesPlayed（上报当前游玩的 AppID）
///
/// 编码对齐 ASF/SteamKit：外层 field 1 嵌套 CMsgGamePlayed 消息，
/// 内层 field 2 = game_id(fixed64)，field 5 = is_secure(bool)。
pub fn build_games_played(appid: u32, steam_id: u64) -> Vec<u8> {
    let mut game = Vec::new();
    put_fixed64_field(&mut game, 2, appid as u64); // game_id (fixed64)
    put_bool_field(&mut game, 5, true); // is_secure
    let mut body = Vec::new();
    put_bytes_field(&mut body, 1, &game); // repeated game_played
    make_frame(EMsg_CLIENT_GAMES_PLAYED, &build_msg_header(steam_id), &body)
}

/// 从 ClientLogOnResponse body 中提取 EResult
pub fn parse_eresult(body: &[u8]) -> Option<i32> {
    get_varint_field(body, 1).map(|v| v as i32)
}

/// CMsgClientPICSProductInfoRequest：查询单个 AppID 是否存在
///
/// 字段（steammessages_clientserver_appinfo.proto）：
///   repeated AppInfo apps = 2（内层 appid = 1）
///   meta_data_only = 3（只回元数据，响应极小）
///   single_response = 7（一次回完，避免分片）
pub fn build_pics_app_request(appid: u32, steam_id: u64) -> Vec<u8> {
    let mut app = Vec::new();
    put_varint_field(&mut app, 1, appid as u64);
    let mut body = Vec::new();
    put_bytes_field(&mut body, 2, &app);
    put_bool_field(&mut body, 3, true);
    put_bool_field(&mut body, 7, true);
    make_frame(
        EMsg_CLIENT_PICS_PRODUCT_INFO_REQUEST,
        &build_msg_header(steam_id),
        &body,
    )
}

/// 解析 CMsgClientPICSProductInfoResponse：
///   返回 (已确认存在的 appid 列表, unknown_appids 列表, 是否还有后续分片)
pub fn parse_pics_response(body: &[u8]) -> (Vec<u32>, Vec<u32>, bool) {
    let mut apps: Vec<u32> = Vec::new();
    let mut unknown: Vec<u32> = Vec::new();
    let mut pending = false;
    let mut i = 0usize;
    while i < body.len() {
        let Some((tag, ni)) = read_varint(body, i) else { break };
        i = ni;
        let f = (tag >> 3) as u32;
        let w = (tag & 7) as u8;
        if w == 0 {
            let Some((v, ni)) = read_varint(body, i) else { break };
            i = ni;
            if f == 2 {
                unknown.push(v as u32); // repeated uint32 未打包
            } else if f == 6 {
                pending = v != 0; // response_pending
            }
        } else if w == 2 {
            let Some((len, ni)) = read_varint(body, i) else { break };
            i = ni;
            let end = i + len as usize;
            if end > body.len() {
                break;
            }
            if f == 2 {
                // repeated uint32 打包编码
                let mut j = i;
                while j < end {
                    let Some((v, nj)) = read_varint(&body[..end], j) else { break };
                    unknown.push(v as u32);
                    j = nj;
                }
            } else if f == 1 {
                // 嵌套 AppInfo.appid = 1
                if let Some(a) = get_varint_field(&body[i..end], 1) {
                    apps.push(a as u32);
                }
            }
            i = end;
        } else if w == 5 {
            i += 4;
        } else if w == 1 {
            i += 8;
        } else {
            break;
        }
    }
    (apps, unknown, pending)
}

/// 解析第一个字符串字段（field 匹配）的值，用于 email_domain 等诊断字段
pub fn get_str_field(body: &[u8], field: u32) -> Option<String> {
    let mut i = 0usize;
    while i < body.len() {
        let (tag, ni) = read_varint(body, i)?;
        i = ni;
        let f = (tag >> 3) as u32;
        let w = (tag & 7) as u8;
        if w == 0 {
            let (_, ni) = read_varint(body, i)?;
            i = ni;
        } else if w == 2 {
            let (len, ni) = read_varint(body, i)?;
            i = ni;
            let end = i + len as usize;
            if end > body.len() {
                return None;
            }
            if f == field {
                return Some(String::from_utf8_lossy(&body[i..end]).to_string());
            }
            i = end;
        } else if w == 5 {
            i += 4;
        } else if w == 1 {
            i += 8;
        } else {
            return None;
        }
    }
    None
}

/// 解析第一个 fixed64 字段（field 匹配）的值，用于从响应 header 取 steamid
pub fn get_fixed64_field(body: &[u8], field: u32) -> Option<u64> {
    let mut i = 0usize;
    while i < body.len() {
        let (tag, ni) = read_varint(body, i)?;
        i = ni;
        let f = (tag >> 3) as u32;
        let w = (tag & 7) as u8;
        if w == 0 {
            let (_, ni) = read_varint(body, i)?;
            i = ni;
        } else if w == 2 {
            let (len, ni) = read_varint(body, i)?;
            i = ni + len as usize;
        } else if w == 5 {
            i += 4;
        } else if w == 1 {
            if i + 8 > body.len() {
                return None;
            }
            if f == field {
                return Some(u64::from_le_bytes(body[i..i + 8].try_into().ok()?));
            }
            i += 8;
        } else {
            return None;
        }
    }
    None
}

/// 解析所有匹配 field 的长度定界字段（repeated 消息 / bytes），按出现顺序返回
pub fn get_repeated_bytes_field(body: &[u8], field: u32) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        let Some((tag, ni)) = read_varint(body, i) else {
            break;
        };
        i = ni;
        let f = (tag >> 3) as u32;
        let w = (tag & 7) as u8;
        if w == 0 {
            let Some((_, ni)) = read_varint(body, i) else {
                break;
            };
            i = ni;
        } else if w == 2 {
            let Some((len, ni)) = read_varint(body, i) else {
                break;
            };
            i = ni;
            let Ok(len) = usize::try_from(len) else {
                break;
            };
            let Some(end) = i.checked_add(len) else {
                break;
            };
            if end > body.len() {
                break;
            }
            if f == field {
                out.push(body[i..end].to_vec());
            }
            i = end;
        } else if w == 5 {
            i += 4;
        } else if w == 1 {
            i += 8;
        } else {
            break;
        }
    }
    out
}

/// 解析第一个匹配 field 的 bytes 字段
pub fn get_bytes_field(body: &[u8], field: u32) -> Option<Vec<u8>> {
    get_repeated_bytes_field(body, field).into_iter().next()
}

/// 解析第一个 float 字段（wire 5），用于认证轮询间隔
pub fn get_f32_field(body: &[u8], field: u32) -> Option<f32> {
    let mut i = 0usize;
    while i < body.len() {
        let (tag, ni) = read_varint(body, i)?;
        i = ni;
        let f = (tag >> 3) as u32;
        let w = (tag & 7) as u8;
        if w == 0 {
            let (_, ni) = read_varint(body, i)?;
            i = ni;
        } else if w == 2 {
            let (len, ni) = read_varint(body, i)?;
            i = ni + usize::try_from(len).ok()?;
        } else if w == 5 {
            if i + 4 > body.len() {
                return None;
            }
            if f == field {
                return Some(f32::from_le_bytes(body[i..i + 4].try_into().ok()?));
            }
            i += 4;
        } else if w == 1 {
            i += 8;
        } else {
            return None;
        }
    }
    None
}

/// 十六进制转储（诊断用）
pub fn hex_dump(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 3);
    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{:02x}", b));
    }
    out
}

// ---------------------------------------------------------------------------
// EMsg.Multi 展开（CM 对较大响应会包一层 Multi + gzip）
// ---------------------------------------------------------------------------

// ESP32-C3 ROM 中的 miniz 解压函数（esp32c3.rom.ld 已导出，libespidf 已链接）
extern "C" {
    fn tinfl_decompress_mem_to_mem(
        p_out_buf: *mut core::ffi::c_void,
        out_buf_len: usize,
        p_src_buf: *const core::ffi::c_void,
        src_buf_len: usize,
        flags: i32,
    ) -> usize;
}

const TINFL_FLAG_PARSE_ZLIB_HEADER: i32 = 1;
/// 解压输出上限，防止异常 size_unzipped 撑爆堆
const MULTI_MAX_OUT: usize = 65536;

/// 展开 EMsg.Multi 帧为若干子帧（每个子帧自带 8 字节 Steam 消息前缀）。
/// 解析失败时返回空列表。
pub fn expand_multi(frame: &Frame) -> Vec<Frame> {
    let mut out = Vec::new();
    let Some((size_unzipped, body)) = parse_multi(&frame.body) else {
        log::warn!("multi: bad CMsgMulti body ({} bytes)", frame.body.len());
        return out;
    };
    let data = if size_unzipped > 0 {
        let cap = (size_unzipped as usize).min(MULTI_MAX_OUT);
        match inflate(&body, cap) {
            Some(d) => d,
            None => {
                log::warn!("multi: inflate failed (in={} out={})", body.len(), size_unzipped);
                return out;
            }
        }
    } else {
        body
    };

    let mut i = 0usize;
    while i + 4 <= data.len() {
        let n = u32::from_le_bytes(data[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if n == 0 || i + n > data.len() {
            log::warn!("multi: bad sub message size {}", n);
            break;
        }
        if let Some(f) = parse_message(&data[i..i + n]) {
            out.push(f);
        }
        i += n;
    }
    out
}

/// 解析 CMsgMulti：size_unzipped(1) / message_body(2)
fn parse_multi(body: &[u8]) -> Option<(u32, Vec<u8>)> {
    let mut size_unzipped = 0u32;
    let mut payload: Option<Vec<u8>> = None;
    let mut i = 0usize;
    while i < body.len() {
        let (tag, ni) = read_varint(body, i)?;
        i = ni;
        let f = (tag >> 3) as u32;
        let w = (tag & 7) as u8;
        if w == 0 {
            let (v, ni) = read_varint(body, i)?;
            i = ni;
            if f == 1 {
                size_unzipped = v as u32;
            }
        } else if w == 2 {
            let (len, ni) = read_varint(body, i)?;
            i = ni;
            let end = i + usize::try_from(len).ok()?;
            if end > body.len() {
                return None;
            }
            if f == 2 {
                payload = Some(body[i..end].to_vec());
            }
            i = end;
        } else if w == 5 {
            i += 4;
        } else if w == 1 {
            i += 8;
        } else {
            return None;
        }
    }
    payload.map(|p| (size_unzipped, p))
}

/// 解压：自动识别 gzip(1f 8b) / zlib(78 xx) / 裸 deflate
fn inflate(src: &[u8], cap: usize) -> Option<Vec<u8>> {
    if cap == 0 {
        return None;
    }
    let (data, flags) = if src.len() > 2 && src[0] == 0x1f && src[1] == 0x8b {
        (skip_gzip_header(src)?, 0)
    } else if src.len() > 2 && src[0] == 0x78 {
        (src, TINFL_FLAG_PARSE_ZLIB_HEADER)
    } else {
        (src, 0)
    };
    let mut out = vec![0u8; cap];
    let n = unsafe {
        tinfl_decompress_mem_to_mem(
            out.as_mut_ptr() as *mut core::ffi::c_void,
            out.len(),
            data.as_ptr() as *const core::ffi::c_void,
            data.len(),
            flags,
        )
    };
    if n == 0 {
        return None;
    }
    out.truncate(n);
    Some(out)
}

/// 跳过 gzip 头，返回裸 deflate 数据（尾部 8 字节 CRC/ISIZE 由 tinfl 自行忽略）
fn skip_gzip_header(src: &[u8]) -> Option<&[u8]> {
    if src.len() < 10 {
        return None;
    }
    let flg = src[3];
    let mut i = 10usize;
    if flg & 0x04 != 0 {
        // FEXTRA
        if i + 2 > src.len() {
            return None;
        }
        i += 2 + u16::from_le_bytes([src[i], src[i + 1]]) as usize;
    }
    if flg & 0x08 != 0 {
        // FNAME
        while i < src.len() && src[i] != 0 {
            i += 1;
        }
        i += 1;
    }
    if flg & 0x10 != 0 {
        // FCOMMENT
        while i < src.len() && src[i] != 0 {
            i += 1;
        }
        i += 1;
    }
    if flg & 0x02 != 0 {
        // FHCRC
        i += 2;
    }
    if i > src.len() {
        return None;
    }
    Some(&src[i..])
}
