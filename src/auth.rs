//! Steam 新版认证（IAuthenticationService）
//!
//! 背景：Steam 已不再在 CM 的 `CMsgClientLogon(5514)` 中校验明文密码，任何密码都返回
//! `EResult=5(InvalidPassword)`。ASF / SteamKit 的做法是先通过统一消息服务完成认证，
//! 拿到 refresh token，再把 refresh token 作为 `CMsgClientLogon.access_token(108)` 登录。
//!
//! 本模块实现该认证流程（与 SteamKit `SteamAuthentication` 一致）：
//!   GetPasswordRSAPublicKey → BeginAuthSessionViaCredentials
//!   → (UpdateAuthSessionWithSteamGuardCode) → PollAuthSessionStatus
//!
//! 传输：请求以 `EMsg 9804(ServiceMethodCallFromClientNonAuthed)` 发送，proto header 带
//! `jobid_source(10, fixed64)` 与 `target_job_name(12)`，body 直接是请求 protobuf
//! （不额外包一层）。响应是 `EMsg 147(ServiceMethodResponse)`，header 的
//! `jobid_target(11, fixed64)` 对应请求的 jobid_source，body 即响应 protobuf。
//!
//! 密码加密：按 Steam 下发 RSA 公钥（hex 的 modulus/exponent）构造 PKCS#1 RSAPublicKey
//! DER，用 PSA（mbed TLS 4.x 唯一可用的非对称加密接口）做 RSA PKCS#1 v1.5 加密，
//! 结果 base64 后作为 encrypted_password 提交。

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use esp_idf_svc::sys::{
    mbedtls_svc_key_id_t, psa_asymmetric_encrypt, psa_crypto_init, psa_destroy_key, psa_import_key,
    psa_key_attributes_s, psa_status_t,
};

use crate::config::steam_guard_code;
use crate::proto::{
    get_bytes_field, get_f32_field, get_fixed64_field, get_repeated_bytes_field, get_str_field,
    get_varint_field, make_frame, put_bool_field, put_bytes_field, put_fixed64_field, put_str_field,
    put_varint_field,
};
use crate::state::AppState;
use crate::steam::now_unix;

/// 服务调用（未登录态）
const EMSG_SERVICE_METHOD_CALL_NON_AUTHED: u32 = 9804;
/// 服务调用响应
pub const EMSG_SERVICE_METHOD_RESPONSE: u32 = 147;

const METHOD_GET_RSA: &str = "Authentication.GetPasswordRSAPublicKey#1";
const METHOD_BEGIN: &str = "Authentication.BeginAuthSessionViaCredentials#1";
const METHOD_POLL: &str = "Authentication.PollAuthSessionStatus#1";
const METHOD_GUARD: &str = "Authentication.UpdateAuthSessionWithSteamGuardCode#1";

/// EAauthSessionGuardType
const GUARD_NONE: u32 = 1;
const GUARD_EMAIL_CODE: u32 = 2;
const GUARD_DEVICE_CODE: u32 = 3;
const GUARD_DEVICE_CONFIRMATION: u32 = 4;
const GUARD_EMAIL_CONFIRMATION: u32 = 5;

/// 认证会话有效期有限（Steam 侧约 2 分钟），超时后重新发起
const AUTH_TIMEOUT: Duration = Duration::from_secs(180);
/// 等待用户输入令牌的上限
const CODE_WAIT_TIMEOUT: Duration = Duration::from_secs(300);

const DEVICE_NAME: &str = "ESP32-C3-SM-ASF";

// PSA 常量（bindgen 未导出 mbedtls 的 #define 常量，这里按 psa/crypto_values.h 取值）
const PSA_KEY_TYPE_RSA_PUBLIC_KEY: u16 = 0x4001;
const PSA_KEY_USAGE_ENCRYPT: u32 = 0x0000_0100;
const PSA_ALG_RSA_PKCS1V15_CRYPT: u32 = 0x0700_0200;
const PSA_SUCCESS: psa_status_t = 0;

/// 认证成功后返回的 refresh token（供 `CMsgClientLogon.access_token` 使用）
pub fn authenticate<F>(
    account: &str,
    password: &str,
    shared_secret: &str,
    state: &Arc<AppState>,
    mut call: F,
) -> Result<String, String>
where
    F: FnMut(u64, &str, &[u8]) -> Result<Vec<u8>, String>,
{
    // 清掉上一次残留的令牌输入，避免误用过期验证码
    state.totp.lock().unwrap().clear();
    let result = do_authenticate(account, password, shared_secret, state, &mut call);
    // 无论成功失败都撤销"等待确认"提示，避免前端一直高亮
    state.awaiting_2fa.store(false, Ordering::Relaxed);
    state.totp.lock().unwrap().clear();
    result
}

fn do_authenticate<F>(
    account: &str,
    password: &str,
    shared_secret: &str,
    state: &Arc<AppState>,
    call: &mut F,
) -> Result<String, String>
where
    F: FnMut(u64, &str, &[u8]) -> Result<Vec<u8>, String>,
{
    // jobid 布局对齐 SteamKit JobID：低 20 位为序号，20..50 位为进程启动时间
    // （2005-01-01 起的秒数）。服务端只把它当作请求/响应的关联标识原样回显。
    let start_time = now_unix().saturating_sub(1_104_537_600) & 0x3fff_ffff;
    let mut job: u64 = (start_time << 20) | 1;

    // ---- 1. 取账号对应的 RSA 公钥 ----
    let mut req = Vec::new();
    put_str_field(&mut req, 1, account);
    let rsa_resp = call(job, METHOD_GET_RSA, &req).map_err(hint_err)?;
    job += 1;
    let (modulus, exponent, timestamp) =
        parse_rsa_pubkey(&rsa_resp).ok_or_else(|| "RSA 公钥响应解析失败".to_string())?;
    let der = der_rsa_public_key(&modulus, &exponent);
    let encrypted = rsa_pkcs1_encrypt(&der, password.as_bytes())?;
    log::info!(
        "auth: rsa key {} bits, password encrypted to {} bytes",
        modulus.len() * 8,
        encrypted.len()
    );

    // ---- 2. 发起凭据认证会话 ----
    let b64 = base64_encode(&encrypted);
    let mut req = Vec::new();
    put_str_field(&mut req, 1, DEVICE_NAME); // device_friendly_name
    put_str_field(&mut req, 2, account); // account_name
    put_str_field(&mut req, 3, &b64); // encrypted_password (base64)
    put_varint_field(&mut req, 4, timestamp); // encryption_timestamp
    put_bool_field(&mut req, 5, true); // remember_login
    put_varint_field(&mut req, 6, 1); // platform_type = SteamClient
    put_varint_field(&mut req, 7, 1); // persistence = Persistent
    put_str_field(&mut req, 8, "Client"); // website_id
    let mut dev = Vec::new();
    put_str_field(&mut dev, 1, DEVICE_NAME);
    put_varint_field(&mut dev, 2, 1); // platform_type = SteamClient
    put_varint_field(&mut dev, 3, 0x11); // os_type
    put_bytes_field(&mut req, 9, &dev); // device_details

    let begin_resp = match call(job, METHOD_BEGIN, &req) {
        Ok(v) => v,
        Err(e) => {
            // 确定性的凭据错误（密码错/无此账号）：主动停止挂机，避免无限重试
            if matches!(err_eresult(&e), Some(5) | Some(25)) {
                let msg = format!("Steam 账号或密码错误（{}），已停止挂机", e);
                log::error!("{}", msg);
                state.halt(msg.clone());
                return Err(msg);
            }
            return Err(hint_err(e));
        }
    };
    job += 1;
    let begin = parse_begin_resp(&begin_resp).ok_or_else(|| "认证会话响应解析失败".to_string())?;
    if !begin.extended_error.is_empty() {
        return Err(format!("认证失败：{}", begin.extended_error));
    }
    if begin.steamid == 0 {
        let msg = "认证失败：Steam 账号或密码错误，已停止挂机".to_string();
        log::error!("{}", msg);
        state.halt(msg.clone());
        return Err(msg);
    }
    if begin.request_id.is_empty() {
        return Err("认证会话响应缺少 request_id".to_string());
    }
    log::info!(
        "auth: session started client_id={} steamid={} interval={:.1}s confirmations={:?}",
        begin.client_id,
        begin.steamid,
        begin.interval,
        begin.confirmations
    );

    // ---- 3. Steam Guard ----
    let has = |t: u32| begin.confirmations.iter().any(|&c| c == t);
    let mut guard_code_type: Option<u32> = None; // 已提交的验证码类型
    if begin.confirmations.is_empty() || has(GUARD_NONE) {
        // 该账号/环境无需二次验证，直接轮询
    } else if !shared_secret.is_empty() && has(GUARD_DEVICE_CODE) {
        // 配置了 shared_secret：自动生成并提交令牌，免人工干预
        let code = steam_guard_code(shared_secret, now_unix())
            .ok_or_else(|| "shared_secret 格式错误，无法生成令牌".to_string())?;
        let body = build_guard_code(begin.client_id, begin.steamid, &code, GUARD_DEVICE_CODE);
        let res = call(job, METHOD_GUARD, &body);
        job += 1;
        match res {
            Ok(_) => {
                log::info!("auth: submitted auto-generated steam guard code");
                guard_code_type = Some(GUARD_DEVICE_CODE);
            }
            Err(e) if is_duplicate(&e) => {
                log::info!("auth: guard code already accepted (duplicate request)");
                guard_code_type = Some(GUARD_DEVICE_CODE);
            }
            Err(e) if is_code_mismatch(&e) => {
                // 通常是设备时间不准：回退到手动输入，避免整体失败
                log::warn!("auth: auto steam guard code rejected: {}", e);
                guard_code_type = Some(send_code_interactive(
                    state,
                    &mut *call,
                    &mut job,
                    &begin,
                    GUARD_DEVICE_CODE,
                    "自动令牌无效（请检查设备时间），请输入 Steam 令牌验证码",
                )?);
            }
            Err(e) => return Err(e),
        }
    } else if has(GUARD_DEVICE_CONFIRMATION) {
        state.awaiting_2fa.store(true, Ordering::Relaxed);
        *state.last_error.lock().unwrap() = "请在 Steam 手机 App 中确认登录".to_string();
    } else if has(GUARD_DEVICE_CODE) {
        guard_code_type = Some(send_code_interactive(
            state,
            &mut *call,
            &mut job,
            &begin,
            GUARD_DEVICE_CODE,
            "请输入 Steam 令牌验证码（手机 App 中显示）",
        )?);
    } else if has(GUARD_EMAIL_CODE) {
        guard_code_type = Some(send_code_interactive(
            state,
            &mut *call,
            &mut job,
            &begin,
            GUARD_EMAIL_CODE,
            "请输入 Steam 发送到邮箱的验证码",
        )?);
    } else if has(GUARD_EMAIL_CONFIRMATION) {
        return Err("该账号需要在邮箱中点击确认链接后才能登录".to_string());
    } else {
        return Err(format!(
            "不支持的 Steam Guard 确认方式：{:?}",
            begin.confirmations
        ));
    }
    if guard_code_type.is_some() {
        state.awaiting_2fa.store(true, Ordering::Relaxed);
    }

    // ---- 4. 轮询认证结果 ----
    let interval = if begin.interval > 0.5 && begin.interval < 60.0 {
        begin.interval
    } else {
        5.0
    };
    let poll_period = Duration::from_millis(((interval * 1000.0) as u64).max(1000));
    let deadline = Instant::now() + AUTH_TIMEOUT;
    let mut client_id = begin.client_id;
    loop {
        if !state.steam_start.load(Ordering::Relaxed) {
            return Err("stopped by user".to_string());
        }
        let body = build_poll(client_id, &begin.request_id);
        let resp = call(job, METHOD_POLL, &body).map_err(hint_err)?;
        job += 1;
        let poll = parse_poll_resp(&resp);
        if poll.new_client_id != 0 {
            client_id = poll.new_client_id;
        }
        if !poll.refresh_token.is_empty() {
            *state.last_error.lock().unwrap() = String::new();
            log::info!(
                "auth: OK, refresh token acquired (account={})",
                poll.account_name
            );
            return Ok(poll.refresh_token);
        }
        if Instant::now() >= deadline {
            return Err("认证超时：未在 Steam 手机 App 中确认".to_string());
        }
        log::debug!("auth: waiting for confirmation...");
        thread_sleep(poll_period);
    }
}

/// 等待用户从 Web 页面提交令牌并提交给 Steam，返回提交的确认类型
fn send_code_interactive<F>(
    state: &Arc<AppState>,
    call: &mut F,
    job: &mut u64,
    begin: &BeginAuth,
    code_type: u32,
    prompt: &str,
) -> Result<u32, String>
where
    F: FnMut(u64, &str, &[u8]) -> Result<Vec<u8>, String>,
{
    state.awaiting_2fa.store(true, Ordering::Relaxed);
    *state.last_error.lock().unwrap() = prompt.to_string();
    let deadline = Instant::now() + CODE_WAIT_TIMEOUT;
    loop {
        if !state.steam_start.load(Ordering::Relaxed) {
            return Err("stopped by user".to_string());
        }
        let code = {
            let mut t = state.totp.lock().unwrap();
            if t.is_empty() {
                None
            } else {
                Some(std::mem::take(&mut *t))
            }
        };
        if let Some(code) = code {
            let body = build_guard_code(begin.client_id, begin.steamid, &code, code_type);
            let res = call(*job, METHOD_GUARD, &body);
            *job += 1;
            match res {
                Ok(_) => return Ok(code_type),
                Err(e) if is_duplicate(&e) => return Ok(code_type),
                Err(e) if is_code_mismatch(&e) => {
                    log::warn!("auth: guard code rejected: {}", e);
                    *state.last_error.lock().unwrap() = "验证码错误，请重新输入".to_string();
                }
                Err(e) => return Err(e),
            }
        }
        if Instant::now() >= deadline {
            return Err("等待 Steam 令牌超时".to_string());
        }
        thread_sleep(Duration::from_millis(500));
    }
}

/// 服务调用请求帧：header 仅携带 jobid_source(10) 与 target_job_name(12)
pub fn build_service_call(job_id: u64, method: &str, req: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(method.len() + 16);
    put_fixed64_field(&mut header, 10, job_id);
    put_str_field(&mut header, 12, method);
    make_frame(EMSG_SERVICE_METHOD_CALL_NON_AUTHED, &header, req)
}

/// 响应 header 的 jobid_target(11) 是否匹配请求的 jobid_source
pub fn response_matches(header: &[u8], job_id: u64) -> bool {
    get_fixed64_field(header, 11) == Some(job_id)
}

/// 响应 header 的 target_job_name(12)，用于诊断/兜底配对
pub fn response_job_name(header: &[u8]) -> String {
    get_str_field(header, 12).unwrap_or_default()
}

/// 响应 header 的 eresult(13)，缺省视为成功
pub fn response_eresult(header: &[u8]) -> i32 {
    get_varint_field(header, 13).map(|v| v as i32).unwrap_or(1)
}

/// 从形如 "service X: EResult=5 InvalidPassword" 的错误串里取出 EResult 数值
fn err_eresult(e: &str) -> Option<i32> {
    let s = e.split("EResult=").nth(1)?;
    let num: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

/// 响应 header 的 error_message(14)
pub fn response_error_message(header: &[u8]) -> String {
    get_str_field(header, 14).unwrap_or_default()
}

struct BeginAuth {
    client_id: u64,
    request_id: Vec<u8>,
    interval: f32,
    steamid: u64,
    confirmations: Vec<u32>,
    extended_error: String,
}

struct PollResult {
    refresh_token: String,
    new_client_id: u64,
    account_name: String,
}

fn build_poll(client_id: u64, request_id: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    put_varint_field(&mut b, 1, client_id);
    put_bytes_field(&mut b, 2, request_id);
    b
}

fn build_guard_code(client_id: u64, steamid: u64, code: &str, code_type: u32) -> Vec<u8> {
    let mut b = Vec::new();
    put_varint_field(&mut b, 1, client_id);
    put_fixed64_field(&mut b, 2, steamid); // fixed64!
    put_str_field(&mut b, 3, code);
    put_varint_field(&mut b, 4, code_type as u64);
    b
}

fn parse_rsa_pubkey(body: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u64)> {
    let n_hex = get_str_field(body, 1)?;
    let e_hex = get_str_field(body, 2)?;
    let timestamp = get_varint_field(body, 3).unwrap_or(0);
    let n = hex_decode(&n_hex)?;
    let e = hex_decode(&e_hex)?;
    if n.is_empty() || e.is_empty() {
        return None;
    }
    Some((n, e, timestamp))
}

fn parse_begin_resp(body: &[u8]) -> Option<BeginAuth> {
    let client_id = get_varint_field(body, 1)?;
    let request_id = get_bytes_field(body, 2).unwrap_or_default();
    let interval = get_f32_field(body, 3).unwrap_or(0.0);
    let confirmations = get_repeated_bytes_field(body, 4)
        .iter()
        .filter_map(|m| get_varint_field(m, 1).map(|v| v as u32))
        .collect();
    let steamid = get_varint_field(body, 5).unwrap_or(0);
    let extended_error = get_str_field(body, 8).unwrap_or_default();
    Some(BeginAuth {
        client_id,
        request_id,
        interval,
        steamid,
        confirmations,
        extended_error,
    })
}

fn parse_poll_resp(body: &[u8]) -> PollResult {
    PollResult {
        new_client_id: get_varint_field(body, 1).unwrap_or(0),
        refresh_token: get_str_field(body, 3).unwrap_or_default(),
        account_name: get_str_field(body, 6).unwrap_or_default(),
    }
}

fn is_duplicate(err: &str) -> bool {
    err.contains("EResult=29") || err.contains("DuplicateRequest")
}

fn is_code_mismatch(err: &str) -> bool {
    err.contains("EResult=65") || err.contains("EResult=88")
}

/// 把服务端 EResult 翻译成用户可读的提示
fn hint_err(err: String) -> String {
    if err.contains("EResult=5") {
        format!("账号或密码错误（{}）", err)
    } else if err.contains("EResult=84") {
        format!("登录尝试过于频繁，请稍后重试（{}）", err)
    } else if err.contains("EResult=27") {
        format!("认证会话已过期，请重新点击启动挂机（{}）", err)
    } else {
        err
    }
}

// ---------------------------------------------------------------------------
// RSA：DER PKCS#1 RSAPublicKey + PSA 加密
// ---------------------------------------------------------------------------

/// 构造 DER 编码的 PKCS#1 RSAPublicKey：SEQUENCE { INTEGER n, INTEGER e }
fn der_rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut body = der_uint(modulus);
    body.extend_from_slice(&der_uint(exponent));
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(0x30);
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(&body);
    out
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

/// DER INTEGER：去掉多余前导 0，最高位为 1 时补 0x00
fn der_uint(v: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < v.len() && v[i] == 0 {
        i += 1;
    }
    let v = &v[i..];
    let mut content = Vec::with_capacity(v.len() + 1);
    if !v.is_empty() && v[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(v);
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(0x02);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(&content);
    out
}

/// RSA PKCS#1 v1.5 加密（mbed TLS 4.x 只保留 PSA 接口）
fn rsa_pkcs1_encrypt(der: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    let st = unsafe { psa_crypto_init() };
    if st != PSA_SUCCESS {
        return Err(format!("psa_crypto_init: {}", st));
    }

    let mut attrs = psa_key_attributes_s::default();
    attrs.type_ = PSA_KEY_TYPE_RSA_PUBLIC_KEY;
    attrs.bits = 2048;
    attrs.policy.usage = PSA_KEY_USAGE_ENCRYPT;
    attrs.policy.alg = PSA_ALG_RSA_PKCS1V15_CRYPT;

    let mut key_id: mbedtls_svc_key_id_t = 0;
    let st = unsafe { psa_import_key(&attrs, der.as_ptr(), der.len(), &mut key_id) };
    if st != PSA_SUCCESS {
        return Err(format!("psa_import_key: {}", st));
    }

    let mut out = vec![0u8; 512];
    let mut out_len: usize = 0;
    let st = unsafe {
        psa_asymmetric_encrypt(
            key_id,
            PSA_ALG_RSA_PKCS1V15_CRYPT,
            plain.as_ptr(),
            plain.len(),
            core::ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        )
    };
    unsafe {
        psa_destroy_key(key_id);
    }
    if st != PSA_SUCCESS {
        return Err(format!("psa_asymmetric_encrypt: {}", st));
    }
    out.truncate(out_len);
    Ok(out)
}

// ---------------------------------------------------------------------------
// 编码辅助
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((hex_val(b[i])? << 4) | hex_val(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 极简 base64 编码（RFC 4648）
pub fn base64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn thread_sleep(d: Duration) {
    std::thread::sleep(d);
}
