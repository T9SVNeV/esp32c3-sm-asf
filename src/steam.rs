//! Steam CM 挂机核心：TLS + 自实现 WebSocket(RFC6455) 连接 CM 服务器，登录 + 心跳 + 游戏上报状态机
//!
//! 背景：IDF 6.1 已移除 esp_websocket_client 组件，esp-idf-svc 0.53 的 ws::client 模块因
//! 组件 cfg 不满足而不可用；而 Steam CM 443 端口是 WSS 服务（非裸 TLS 直连，历史裸连
//! 发 protobuf 即被断开）。因此这里用 EspTls 建立 TLS 后，在应用层完成 WebSocket 握手
//! （HTTP Upgrade）与二进制帧收发（RFC 6455，客户端掩码），消息内容即 Steam protobuf
//! 帧（见 proto.rs）。断线自动重连。
//!
//! 连接流程：TLS 连接 cmp1-hkg1.steamserver.net:443 → WS 握手 /cmsocket/
//!   → ClientHello → (无 refresh token 时先走 auth.rs 认证) → ClientLogon
//!   → 心跳循环（处理 ping/pong、close）

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use esp_idf_svc::sys::{
    esp_random, EWOULDBLOCK, ESP_TLS_ERR_SSL_WANT_READ, ESP_TLS_ERR_SSL_WANT_WRITE,
};
use esp_idf_svc::tls::{Config as TlsConfig, EspTls, InternalSocket};

use crate::auth::{self, base64_encode};
use crate::config::Config;
use crate::idle::Idle;
use crate::proto::{
    build_client_hello, build_client_logon, get_fixed64_field, get_str_field, get_varint_field,
    hex_dump, parse_eresult, parse_message, Frame, EMsg_CLIENT_GAMES_PLAYED,
    EMsg_CLIENT_LOGON_RESPONSE, EMsg_CLIENT_LOGGED_OFF, PROTOCOL_VERSION,
};
use crate::state::{AppState, Phase, SteamState};
use crate::verify::AppIdCheck;

/// CM WebSocket 端点（443 = WSS）
const CM_HOST: &str = "cmp1-hkg1.steamserver.net";
const CM_PORT: u16 = 443;
const CM_WS_PATH: &str = "/cmsocket/";
/// 空闲超时：超过该时长无任何包视为断线
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// 首次重试间隔；失败后指数退避，封顶 RETRY_DELAY_MAX
const RETRY_DELAY: Duration = Duration::from_secs(5);
/// 重试间隔上限：避免固定高频重连触发 Steam 登录限流
const RETRY_DELAY_MAX: Duration = Duration::from_secs(300);
/// 连接（TLS + WS 握手）超时
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 统一消息服务单次调用超时
const SERVICE_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// 接收缓冲上限（单条 Steam 消息远小于此，防止异常帧撑爆内存）
const RX_CAP: usize = 8192;

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 挂机主线程入口：无限循环，断线自动重连
pub fn run(state: Arc<AppState>) {
    // 指数退避状态：连续失败次数越多，重连间隔越长（5s→10s→…→300s 封顶）
    let mut retry_delay = RETRY_DELAY;
    loop {
        // 用户可控：未点击"启动挂机"则不连接（替代重启开发板才能启动）
        if !state.steam_start.load(Ordering::Relaxed) {
            // fatal 停止时保留 Error 状态与错误文案，不被"未启动"覆盖
            if !state.fatal.load(Ordering::Relaxed) {
                *state.steam_state.lock().unwrap() = SteamState::Stopped;
                state.awaiting_2fa.store(false, Ordering::Relaxed);
                state.steam_eresult.store(0, Ordering::Relaxed);
                state.set_phase(Phase::Stopped);
            }
            thread_sleep(Duration::from_secs(1));
            continue;
        }

        let cfg = state.cfg.lock().unwrap().clone();
        if !cfg.is_ready() {
            *state.steam_state.lock().unwrap() = SteamState::Stopped;
            *state.last_error.lock().unwrap() =
                format!("配置不完整：缺少 {}", cfg.missing_text());
            thread_sleep(Duration::from_secs(2));
            continue;
        }

        *state.steam_state.lock().unwrap() = SteamState::Connecting;
        match session(&cfg, &state) {
            Ok(reason) => {
                log::info!("steam session ended: {}", reason);
                // 会话曾经建立成功，重置退避
                retry_delay = RETRY_DELAY;
            }
            Err(e) => {
                if e == "stopped by user" || !state.steam_start.load(Ordering::Relaxed) {
                    if !state.fatal.load(Ordering::Relaxed) {
                        *state.steam_state.lock().unwrap() = SteamState::Stopped;
                        state.awaiting_2fa.store(false, Ordering::Relaxed);
                        log::info!("steam stopped by user");
                    }
                } else {
                    log::error!("steam session error: {}", e);
                    *state.last_error.lock().unwrap() = format!("{}", e);
                    *state.steam_state.lock().unwrap() = SteamState::Error;
                    state.steam_eresult.store(0, Ordering::Relaxed);
                    state.set_phase(Phase::Error);
                    // 失败则指数退避，避免固定高频重连触发 Steam 登录限流
                    retry_delay = core::cmp::min(retry_delay * 2, RETRY_DELAY_MAX);
                    log::warn!("next retry in {}s", retry_delay.as_secs());
                }
            }
        }

        if state.reboot_req.load(Ordering::Relaxed) {
            break;
        }
        // 用户已停止则回到 Stopped 空转，未停止则自动重连
        if state.steam_start.load(Ordering::Relaxed) {
            thread_sleep(retry_delay);
        } else {
            retry_delay = RETRY_DELAY;
        }
    }
}

/// 单次完整会话：TLS 连接 → WS 握手 → 登录 → 心跳循环，返回正常结束原因或错误
fn session(cfg: &Config, state: &Arc<AppState>) -> Result<&'static str, String> {
    state.set_phase(Phase::Connecting);
    // 1. TLS 连接（非阻塞轮询，期间可响应停止）
    let mut tls = EspTls::new().map_err(|e| format!("tls init: {}", e))?;
    let tls_cfg = TlsConfig {
        non_block: true,
        timeout_ms: 15000,
        ..Default::default()
    };
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        match tls.connect(CM_HOST, CM_PORT, &tls_cfg) {
            Ok(_) => break,
            Err(e) => {
                let code = e.code();
                if code == ESP_TLS_ERR_SSL_WANT_READ as i32
                    || code == ESP_TLS_ERR_SSL_WANT_WRITE as i32
                    || code == EWOULDBLOCK as i32
                {
                    if !state.steam_start.load(Ordering::Relaxed) {
                        return Err("stopped by user".to_string());
                    }
                    if Instant::now() >= deadline {
                        return Err(format!("tls connect {}:{}: timeout", CM_HOST, CM_PORT));
                    }
                    thread_sleep(Duration::from_millis(20));
                } else {
                    return Err(format!("tls connect {}:{}: {}", CM_HOST, CM_PORT, e));
                }
            }
        }
    }
    log::info!("tls connected to {}:{}", CM_HOST, CM_PORT);

    // 2. WebSocket 握手（rx 缓冲同时供握手与后续帧解析使用）
    let mut rx: Vec<u8> = Vec::with_capacity(RX_CAP);
    ws_handshake(&mut tls, &mut rx, state)?;

    // 3. ClientHello：与 SteamKit CMClient.OnClientConnected 一致，WS 建连后先发
    //    ClientHello(9805, protocol_version=65581)；CM 不回该消息，无需等待。
    send_client_hello(&mut tls, state)?;

    // 4. 认证：Steam 已停用 CM 明文密码登录（无论密码对错都返回 EResult=5），
    //    必须先用统一消息服务 Authentication.* 换取 refresh token，
    //    再把 refresh token 作为 access_token(108) 登录。
    let refresh_token = if cfg.refresh_token.is_empty() {
        if cfg.account.is_empty() || cfg.password.is_empty() {
            return Err("缺少凭据：请填写 Steam 账号和密码".to_string());
        }
        log::info!("no refresh token, authenticating as {}", cfg.account);
        state.set_phase(Phase::Authenticating);
        *state.last_error.lock().unwrap() = "正在进行 Steam 认证...".to_string();
        let token = auth::authenticate(
            &cfg.account,
            &cfg.password,
            &cfg.shared_secret,
            state,
            |job, method, body| cm_service_call(&mut tls, &mut rx, state, job, method, body),
        )?;
        log::info!(
            "authentication OK, refresh token acquired ({} chars)",
            token.len()
        );
        // 立即落盘（main 主循环每 500ms 检查 config_dirty）
        state.cfg.lock().unwrap().refresh_token = token.clone();
        state.config_dirty.store(true, Ordering::Relaxed);
        *state.last_error.lock().unwrap() = String::new();
        token
    } else {
        log::info!("using stored refresh token ({} chars)", cfg.refresh_token.len());
        cfg.refresh_token.clone()
    };

    // 5. ClientLogon（access_token = refresh token）
    let client_instance_id = (unsafe { esp_random() }) & 0x00ff_ffff;
    let logon = build_client_logon(
        &cfg.account,
        &cfg.password,
        None,
        client_instance_id,
        Some(refresh_token.as_str()),
    );
    log::info!(
        "sending ClientLogon (account={}, auth=refresh_token)",
        cfg.account
    );
    ws_send_binary(&mut tls, &logon, state)?;
    state.set_phase(Phase::LoggingIn);

    // 6. 接收循环
    let mut logged_in = false;
    let mut last_activity = Instant::now();
    let mut poll_sleep = Duration::from_millis(50);
    // AppID 存在性校验（独立模块）：登录后查一次，未确认前不上报游戏
    let mut appid_check = AppIdCheck::new();
    // 保活与游戏上报（独立模块）
    let mut idle = Idle::new(cfg.heartbeat_secs as u64);

    loop {
        // 用户点"停止挂机"：立即结束会话
        if !state.steam_start.load(Ordering::Relaxed) {
            state.awaiting_2fa.store(false, Ordering::Relaxed);
            return Err("stopped by user".to_string());
        }

        // 消费 WebSocket 消息（每条 = 一条完整 Steam 消息）
        match ws_read_payload(&mut tls, &mut rx)? {
            WsMsg::Data(payload) => {
                log::debug!("ws data msg ({} bytes)", payload.len());
                last_activity = Instant::now();
                let Some(frame) = parse_message(&payload) else {
                    let hex: Vec<String> = payload.iter().take(64).map(|b| format!("{:02x}", b)).collect();
                    log::warn!(
                        "drop malformed steam message ({} bytes): {}",
                        payload.len(),
                        hex.join(" ")
                    );
                    continue;
                };
                let frames: Vec<Frame> = if frame.emsg == crate::proto::EMsg_MULTI {
                    // Multi 包裹的批量消息：展开后逐条处理
                    crate::proto::expand_multi(&frame)
                } else {
                    vec![frame]
                };
                for sub in frames {
                    // AppID 存在性校验由 verify 模块独立负责（响应可能分片）
                    if appid_check.on_frame(state, &sub, cfg.appid)? {
                        continue;
                    }
                    handle_frame(state, sub, &mut logged_in, &mut poll_sleep)?;
                }
            }
            WsMsg::Ping(p) => {
                log::debug!("ws ping");
                last_activity = Instant::now();
                ws_send_ctrl(&mut tls, 0xA, &p, state)?; // 回 pong
            }
            WsMsg::None => {}
        }

        if logged_in {
            let steam_id = *state.steam_id.lock().unwrap();
            // 验证阶段：查询一次 AppID 是否存在，未完成前禁止上报游戏
            if appid_check.need_request() {
                let req = appid_check.request(cfg.appid, steam_id);
                ws_send_binary(&mut tls, &req, state)?;
                log::info!("verifying appid {} via PICS", cfg.appid);
            }
            appid_check.tick();
            let verified = appid_check.is_done();
            if verified {
                state.set_phase(Phase::Running);
            }
            // 心跳与游戏上报交给 idle 模块；仅在验证通过后允许上报
            let mut send = |bytes: &[u8]| ws_send_binary(&mut tls, bytes, state);
            idle.tick(&mut send, steam_id, cfg.appid, verified, state)?;
        }

        // 接收静默超时只用于登录/认证阶段。登录成功后 CM 可能长时间不下发任何消息
        // （SteamKit 也没有应用层静默超时），此时若仍按 90s 判断会把健康会话误杀，
        // 表现为周期性 "idle timeout" 重连。真实断线由心跳发送失败/TLS 错误发现。
        if !logged_in && last_activity.elapsed() >= IDLE_TIMEOUT {
            return Err("idle timeout".to_string());
        }
        thread_sleep(poll_sleep);
    }
}

// ===================== WebSocket (RFC 6455) 客户端实现 =====================

/// WS 消息：Data=二进制数据帧（Steam protobuf），Ping=服务器 ping（需回 pong），
/// None=暂无完整帧或仅消费了控制帧
enum WsMsg {
    Data(Vec<u8>),
    Ping(Vec<u8>),
    None,
}

/// ClientHello：与 SteamKit CMClient.OnClientConnected 一致，WS 建连后发送一次
/// ClientHello(9805, body.protocol_version=65581)。
///
/// 注意：CM 对 ClientHello **不返回任何消息**（ClientWelcome 9806 是 ClientLogon 成功
/// 之后才下发的），因此这里只发送、不等待响应，随后立即发送 ClientLogon。
fn send_client_hello(
    tls: &mut EspTls<InternalSocket>,
    state: &Arc<AppState>,
) -> Result<(), String> {
    log::info!(
        "sending ClientHello (protocol_version={})",
        PROTOCOL_VERSION
    );
    ws_send_binary(tls, &build_client_hello(), state)?;
    Ok(())
}

/// WS 握手：发送 HTTP Upgrade 请求，读取响应直到 \r\n\r\n，校验 101 状态行。
/// 多余字节保留在 rx 中供后续帧解析复用。
fn ws_handshake(tls: &mut EspTls<InternalSocket>, rx: &mut Vec<u8>, state: &Arc<AppState>) -> Result<(), String> {
    let mut key = [0u8; 16];
    for k in key.iter_mut() {
        *k = (unsafe { esp_random() } & 0xff) as u8;
    }
    let key_b64 = base64_encode(&key);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        CM_WS_PATH, CM_HOST, CM_PORT, key_b64
    );
    send_all(tls, req.as_bytes(), state)?;

    let deadline = Instant::now() + CONNECT_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(pos) = rx.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&rx[..pos]).to_string();
            let status = head.lines().next().unwrap_or("");
            if !status.contains(" 101 ") {
                return Err(format!("ws handshake rejected: {}", status));
            }
            rx.drain(..pos + 4);
            log::info!("ws handshake 101 ok");
            return Ok(());
        }
        // 非阻塞读补充
        let mut tmp = [0u8; 128];
        match tls.read(&mut tmp) {
            Ok(n) if n > 0 => {
                rx.extend_from_slice(&tmp[..n]);
                if rx.len() > RX_CAP {
                    return Err("ws handshake response too large".to_string());
                }
            }
            Ok(_) => {}
            Err(e) => {
                let code = e.code();
                if code != ESP_TLS_ERR_SSL_WANT_READ as i32
                    && code != ESP_TLS_ERR_SSL_WANT_WRITE as i32
                    && code != EWOULDBLOCK as i32
                {
                    return Err(format!("tls read during handshake: {}", e));
                }
            }
        }
        if !state.steam_start.load(Ordering::Relaxed) {
            return Err("stopped by user".to_string());
        }
        thread_sleep(Duration::from_millis(10));
    }
    Err("ws handshake timeout".to_string())
}

/// 读一条完整 WS 消息。缓冲不足时非阻塞补读 TLS；仍无完整帧返回 WsMsg::None。
fn ws_read_payload(
    tls: &mut EspTls<InternalSocket>,
    rx: &mut Vec<u8>,
) -> Result<WsMsg, String> {
    if let Some(m) = try_parse_ws_frame(rx)? {
        return Ok(m);
    }
    let mut tmp = [0u8; 256];
    loop {
        match tls.read(&mut tmp) {
            Ok(n) if n > 0 => {
                log::debug!("tls read {} bytes", n);
                rx.extend_from_slice(&tmp[..n]);
                if rx.len() > RX_CAP {
                    return Err("ws rx buffer overflow".to_string());
                }
                if let Some(m) = try_parse_ws_frame(rx)? {
                    let tag = match &m {
                        WsMsg::Data(d) => format!("Data({})", d.len()),
                        WsMsg::Ping(_) => "Ping".to_string(),
                        WsMsg::None => "Ctrl".to_string(),
                    };
                    log::debug!("ws frame: {}", tag);
                    return Ok(m);
                }
            }
            Ok(_) => break,
            Err(e) => {
                let code = e.code();
                if code == ESP_TLS_ERR_SSL_WANT_READ as i32
                    || code == ESP_TLS_ERR_SSL_WANT_WRITE as i32
                    || code == EWOULDBLOCK as i32
                {
                    break;
                }
                return Err(format!("tls read: {} (code={})", e, code));
            }
        }
    }
    Ok(WsMsg::None)
}

/// 从缓冲解析第一个完整 WS 帧。帧不完整返回 None；收到 close 帧返回 Err；
/// ping 帧返回 Ping（已消费）；pong/未知控制帧返回 None（已消费）。
/// 服务器帧 MASK 位通常为 0，但按规范兼容解掩码。
fn try_parse_ws_frame(rx: &mut Vec<u8>) -> Result<Option<WsMsg>, String> {
    if rx.len() < 2 {
        return Ok(None);
    }
    let b0 = rx[0];
    let b1 = rx[1];
    let opcode = b0 & 0x0f;
    let masked = b1 & 0x80 != 0;
    let mut len = (b1 & 0x7f) as usize;
    let mut hdr = 2usize;
    if len == 126 {
        if rx.len() < 4 {
            return Ok(None);
        }
        len = u16::from_be_bytes([rx[2], rx[3]]) as usize;
        hdr = 4;
    } else if len == 127 {
        if rx.len() < 10 {
            return Ok(None);
        }
        len = u64::from_be_bytes(rx[2..10].try_into().unwrap()) as usize;
        hdr = 10;
    }
    if len > RX_CAP {
        return Err(format!("ws frame too large: {} bytes", len));
    }
    let mask_len = if masked { 4 } else { 0 };
    let total = hdr + mask_len + len;
    if rx.len() < total {
        return Ok(None);
    }
    let mut payload: Vec<u8> = rx[hdr + mask_len..total].to_vec();
    if masked {
        let key = &rx[hdr..hdr + 4];
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= key[i & 3];
        }
    }
    rx.drain(..total);
    match opcode {
        0x1 | 0x2 => Ok(Some(WsMsg::Data(payload))),
        0x9 => Ok(Some(WsMsg::Ping(payload))),
        0xA => Ok(Some(WsMsg::None)), // pong 仅消费
        0x8 => Err("ws closed by server".to_string()),
        0x0 => {
            // continuation 帧（分片）：当前 CM 不会分片，丢弃避免状态错乱
            log::warn!("ws continuation frame dropped ({} bytes)", payload.len());
            Ok(Some(WsMsg::None))
        }
        _ => {
            log::warn!("ws unknown opcode {} dropped", opcode);
            Ok(Some(WsMsg::None))
        }
    }
}

/// 发送一条 WS 二进制数据帧（客户端掩码）
fn ws_send_binary(tls: &mut EspTls<InternalSocket>, payload: &[u8], state: &Arc<AppState>) -> Result<(), String> {
    let mut key = [0u8; 4];
    for k in key.iter_mut() {
        *k = (unsafe { esp_random() } & 0xff) as u8;
    }
    let mut out: Vec<u8> = Vec::with_capacity(6 + payload.len());
    out.push(0x80 | 0x02); // FIN + binary
    if payload.len() < 126 {
        out.push(0x80 | payload.len() as u8);
    } else {
        out.push(0x80 | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(&key);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ key[i & 3]);
    }
    send_all(tls, &out, state)
}

/// 发送 WS 控制帧（ping=0x9 / pong=0xA），控制帧 payload ≤ 125
fn ws_send_ctrl(tls: &mut EspTls<InternalSocket>, opcode: u8, payload: &[u8], state: &Arc<AppState>) -> Result<(), String> {
    let mut key = [0u8; 4];
    for k in key.iter_mut() {
        *k = (unsafe { esp_random() } & 0xff) as u8;
    }
    let mut out: Vec<u8> = Vec::with_capacity(6 + payload.len());
    out.push(0x80 | opcode);
    out.push(0x80 | payload.len() as u8);
    out.extend_from_slice(&key);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ key[i & 3]);
    }
    send_all(tls, &out, state)
}

/// 非阻塞写：处理 WANT_READ/WANT_WRITE/EWOULDBLOCK 轮询直至写完
fn send_all(tls: &mut EspTls<InternalSocket>, data: &[u8], state: &Arc<AppState>) -> Result<(), String> {
    let mut off = 0;
    while off < data.len() {
        match tls.write(&data[off..]) {
            Ok(n) if n > 0 => off += n,
            Ok(_) => thread_sleep(Duration::from_millis(10)),
            Err(e) => {
                let code = e.code();
                if code == ESP_TLS_ERR_SSL_WANT_WRITE as i32
                    || code == ESP_TLS_ERR_SSL_WANT_READ as i32
                    || code == EWOULDBLOCK as i32
                {
                    if !state.steam_start.load(Ordering::Relaxed) {
                        return Err("stopped by user".to_string());
                    }
                    thread_sleep(Duration::from_millis(10));
                } else {
                    return Err(format!("tls write: {}", e));
                }
            }
        }
    }
    Ok(())
}

/// 通过 CM 统一消息服务（未登录态）发送一次请求并等待对应响应，返回响应 body。
///
/// 请求/响应格式见 auth.rs 顶部说明；job_id 用于把响应与请求配对
/// （响应 header.jobid_target == 请求 header.jobid_source）。
fn cm_service_call(
    tls: &mut EspTls<InternalSocket>,
    rx: &mut Vec<u8>,
    state: &Arc<AppState>,
    job_id: u64,
    method: &str,
    req: &[u8],
) -> Result<Vec<u8>, String> {
    let call = auth::build_service_call(job_id, method, req);
    log::info!(
        "service tx: {} job={} ({} bytes) [{}]",
        method,
        job_id,
        call.len(),
        hex_dump(&call)
    );
    ws_send_binary(tls, &call, state)?;

    let deadline = Instant::now() + SERVICE_CALL_TIMEOUT;
    loop {
        if !state.steam_start.load(Ordering::Relaxed) {
            return Err("stopped by user".to_string());
        }
        match ws_read_payload(tls, rx)? {
            WsMsg::Data(payload) => {
                let Some(frame) = parse_message(&payload) else {
                    log::warn!("service rx: malformed payload ({} bytes)", payload.len());
                    continue;
                };
                // CM 会把较大的服务响应包在 EMsg.Multi 里（gzip 压缩），需先展开
                let frames = if frame.emsg == crate::proto::EMsg_MULTI {
                    let subs = crate::proto::expand_multi(&frame);
                    log::info!("service rx: Multi -> {} sub message(s)", subs.len());
                    subs
                } else {
                    vec![frame]
                };
                for frame in frames {
                    let name = auth::response_job_name(&frame.header);
                    log::info!(
                        "service rx: emsg={} hdr={} body={} job_src={} job_tgt={} name='{}'",
                        frame.emsg,
                        frame.header.len(),
                        frame.body.len(),
                        get_fixed64_field(&frame.header, 10).unwrap_or(0),
                        get_fixed64_field(&frame.header, 11).unwrap_or(0),
                        name
                    );
                    if frame.emsg != auth::EMSG_SERVICE_METHOD_RESPONSE {
                        continue;
                    }
                    // 优先按 jobid_target 配对；服务端未回填 jobid 时退化为按方法名配对
                    // （本流程调用是串行的，不会混淆）。
                    if !auth::response_matches(&frame.header, job_id) && name != method {
                        log::warn!("service rx: jobid/name mismatch, ignored");
                        continue;
                    }
                    let eresult = auth::response_eresult(&frame.header);
                    if eresult != 1 {
                        let msg = auth::response_error_message(&frame.header);
                        return Err(format!("service {}: EResult={} {}", method, eresult, msg));
                    }
                    return Ok(frame.body);
                }
            }
            WsMsg::Ping(p) => ws_send_ctrl(tls, 0xA, &p, state)?,
            WsMsg::None => {}
        }
        if Instant::now() >= deadline {
            return Err(format!("service {} timeout", method));
        }
        thread_sleep(Duration::from_millis(20));
    }
}

// ===================== Steam 消息处理 =====================

fn handle_frame(
    state: &Arc<AppState>,
    frame: Frame,
    logged_in: &mut bool,
    poll_sleep: &mut Duration,
) -> Result<(), String> {
    let idle_sleep = Duration::from_millis(500);
    match frame.emsg {
        EMsg_CLIENT_LOGON_RESPONSE => {
            let eresult = parse_eresult(&frame.body).unwrap_or(-1);
            state.steam_eresult.store(eresult as u32, Ordering::Relaxed);
            // 诊断日志：EResult 之外还打印 eresult_extended(10)、email_domain(8)、
            // 登录失败计数(24)、响应 header 中的 steamid，以及原始 header/body 十六进制。
            log::info!(
                "ClientLogOnResponse: eresult={} extended={} steamid={} email_domain='{}' loginfailures={} header=[{}] body=[{}]",
                eresult,
                get_varint_field(&frame.body, 10).unwrap_or(0),
                get_fixed64_field(&frame.header, 1).unwrap_or(0),
                get_str_field(&frame.body, 8).unwrap_or_default(),
                get_varint_field(&frame.body, 24).unwrap_or(0),
                hex_dump(&frame.header),
                hex_dump(&frame.body)
            );
            if eresult == 1 {
                // 记录服务器下发的真实 SteamID，后续消息 proto header 需要它
                let sid = get_fixed64_field(&frame.header, 1).unwrap_or(0);
                if sid != 0 {
                    *state.steam_id.lock().unwrap() = sid;
                    log::info!("logged in as steamid={}", sid);
                }
                *logged_in = true;
                state.awaiting_2fa.store(false, Ordering::Relaxed);
                state.last_error.lock().unwrap().clear();
                *state.steam_state.lock().unwrap() = SteamState::LoggedIn;
                *state.login_at.lock().unwrap() = Some(Instant::now());
                state.set_phase(Phase::Verifying);
                log::info!("login OK (EResult 1)");
                // 游戏上报与首心跳由主循环 logged_in 分支统一发送
                *poll_sleep = idle_sleep;
            } else if eresult == 6 || eresult == 34 {
                // 账号已在其他设备登录且未让出会话：主动停止并报错，保留 token
                return Err(halt_occupied(state, eresult));
            } else if eresult == 5 || eresult == 63 {
                // refresh token 被服务器拒绝（无效/过期/别处注销）：
                // 清掉已存 token，下一轮 run() 会用账号密码重新认证。
                let (had_token, has_password) = {
                    let c = state.cfg.lock().unwrap();
                    (!c.refresh_token.is_empty(), !c.password.is_empty())
                };
                if had_token && has_password {
                    state.cfg.lock().unwrap().refresh_token.clear();
                    state.config_dirty.store(true, Ordering::Relaxed);
                    log::warn!("refresh token rejected by CM, cleared for re-authentication");
                } else if had_token && !has_password {
                    // 只剩失效 token、没有账号密码可重新认证：无法恢复，停止并提示补全
                    let msg = format!(
                        "Refresh Token 已失效（EResult={}），且未配置账号密码，已停止挂机；请在网页补全账号和密码",
                        eresult
                    );
                    log::error!("{}", msg);
                    state.halt(msg.clone());
                    return Err(msg);
                }
                return Err(format!(
                    "login failed EResult={} ({})",
                    eresult,
                    eresult_name(eresult)
                ));
            } else {
                let msg = eresult_name(eresult);
                log::error!("login failed EResult={} ({})", eresult, msg);
                return Err(format!("login failed EResult={} ({})", eresult, msg));
            }
        }
        EMsg_CLIENT_GAMES_PLAYED => {
            log::debug!("games played ACK");
        }
        EMsg_CLIENT_LOGGED_OFF => {
            // CMsgClientLoggedOff.eresult = 1
            let eresult = get_varint_field(&frame.body, 1).unwrap_or(0) as i32;
            if eresult == 6 || eresult == 34 {
                // 被其他设备顶下线：主动停止并报错，保留 token
                return Err(halt_occupied(state, eresult));
            }
            log::warn!("server logged us off (eresult={})", eresult);
            return Err("server logged off".to_string());
        }
        _ => {
            log::debug!("recv emsg={}", frame.emsg);
        }
    }
    Ok(())
}

fn thread_sleep(d: Duration) {
    std::thread::sleep(d);
}

/// 账号被其他设备占用时统一处理：停止挂机、记录错误、保留 token
fn halt_occupied(state: &Arc<AppState>, eresult: i32) -> String {
    let msg = format!(
        "账号已在其他设备登录（EResult={} {}），已停止挂机；请先在其他设备退出 Steam 后重新启动",
        eresult,
        eresult_name(eresult)
    );
    log::error!("{}", msg);
    state.halt(msg.clone());
    msg
}

fn eresult_name(eresult: i32) -> &'static str {
    match eresult {
        1 => "OK",
        2 => "Fail",
        5 => "InvalidPassword",
        6 => "LoggedInElsewhere",
        9 => "AccessDenied",
        10 => "Pending",
        11 => "ServiceUnavailable",
        24 => "DuplicateRequest",
        25 => "NoUser",
        26 => "ServiceUnreadonly",
        34 => "LogonSessionReplaced",
        37 => "DuplicateRequest",
        56 => "LimitExceeded",
        63 => "AccountLogonDenied",
        65 => "TwoFactorCodeMismatch",
        68 => "NeedsTwoFactorCode",
        84 => "TooManyPending",
        _ => "Unknown",
    }
}
