//! Web 仪表盘：ESP HTTP Server，提供状态/配置查看与配置导入

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use embedded_svc::http::Method;
use embedded_svc::io::Write;
use esp_idf_svc::http::server::{Configuration as HttpConf, EspHttpServer};
use esp_idf_svc::io::EspIOError;

use crate::config::{Config, POWER_BALANCED, POWER_PERF, POWER_SAVE};
use crate::state::AppState;
use crate::steam::now_unix;

// 配置表单体上限：refresh token 本身可达 1KB，留足余量
const MAX_BODY: usize = 4096;
const INDEX_HTML: &str = include_str!("index.html");
const PROVISION_HTML: &str = include_str!("provision.html");


pub fn start(state: Arc<AppState>) -> Result<EspHttpServer<'static>, EspIOError> {
    let mut conf = HttpConf::default();
    conf.http_port = 80;
    conf.max_uri_handlers = 8;
    conf.stack_size = 8192;

    let mut server = EspHttpServer::new(&conf)?;

    // 根路径：配网模式渲染配网页，正常模式渲染仪表盘
    server.fn_handler("/", Method::Get, {
        let state = state.clone();
        move |request| -> Result<(), EspIOError> {
            let html = if state.provisioning.load(Ordering::Relaxed) {
                PROVISION_HTML
            } else {
                INDEX_HTML
            };
            let mut resp = request.into_response(
                200,
                Some("OK"),
                &[
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("Cache-Control", "no-store, no-cache, must-revalidate"),
                    ("Pragma", "no-cache"),
                ],
            )?;
            resp.write_all(html.as_bytes())?;
            Ok(())
        }
    })?;

    // 状态 JSON
    server.fn_handler("/api/status", Method::Get, {
        let state = state.clone();
        move |request| -> Result<(), EspIOError> {
            let mut resp = request.into_response(200, Some("OK"), &[("Content-Type", "application/json; charset=utf-8")])?;
            let body = state.status_json(now_unix());
            resp.write_all(body.as_bytes())?;
            Ok(())
        }
    })?;

    // 当前配置（脱敏）
    server.fn_handler("/api/config", Method::Get, {
        let state = state.clone();
        move |request| -> Result<(), EspIOError> {
            let cfg = state.cfg.lock().unwrap().clone();
            let mut resp = request.into_response(200, Some("OK"), &[("Content-Type", "application/json; charset=utf-8")])?;
            resp.write_all(cfg.masked_json().as_bytes())?;
            Ok(())
        }
    })?;

    // 保存配置（application/x-www-form-urlencoded）
    server.fn_handler("/api/config", Method::Post, {
        let state = state.clone();
        move |mut request| -> Result<(), EspIOError> {
            let mut body = Vec::with_capacity(256);
            let mut buf = [0u8; 256];
            loop {
                match request.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        body.extend_from_slice(&buf[..n]);
                        if body.len() > MAX_BODY {
                            let mut resp = request.into_status_response(413)?;
                            resp.write_all(b"body too large")?;
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        log::warn!("read body err: {}", e);
                        break;
                    }
                }
            }
            let body_str = String::from_utf8_lossy(&body).to_string();

            let mut cfg = state.cfg.lock().unwrap().clone();
            let parsed = parse_form(&body_str);
            if let Some(v) = parsed.get("wifi_ssid") {
                cfg.wifi_ssid = v.clone();
            }
            // 密码/密钥类字段：与当前值的脱敏展示串完全一致才视为“未修改”，空值同样跳过。
            // 不能用 contains('*') 判断——真实密码可能本身含 '*'。
            if let Some(v) = parsed.get("wifi_pass") {
                if !v.is_empty() && *v != crate::config::mask(&cfg.wifi_pass, 2) {
                    cfg.wifi_pass = v.clone();
                }
            }
            if let Some(v) = parsed.get("account") {
                cfg.account = v.clone();
            }
            // password_clear=1：显式清空已保存的 Steam 密码（留空生效，用于清除测试值）
            let clear_pwd = matches!(parsed.get("password_clear").map(|s| s.trim()), Some("1") | Some("true"));
            if clear_pwd {
                cfg.password.clear();
            } else if let Some(v) = parsed.get("password") {
                if !v.is_empty() && *v != crate::config::mask(&cfg.password, 2) {
                    cfg.password = v.clone();
                }
            }
            if let Some(v) = parsed.get("shared_secret") {
                let v = v.trim();
                if !v.is_empty() && v.to_ascii_uppercase() != crate::config::mask(&cfg.shared_secret, 3) {
                    cfg.shared_secret = v.to_ascii_uppercase();
                }
            }
            // Refresh Token：Steam 新版认证产物，CM 登录凭据（留空/占位不修改）
            let clear_token = matches!(
                parsed.get("refresh_token_clear").map(|s| s.trim()),
                Some("1") | Some("true")
            );
            if clear_token {
                cfg.refresh_token.clear();
            } else if let Some(v) = parsed.get("refresh_token") {
                let v = v.trim();
                if !v.is_empty() && v != crate::config::mask(&cfg.refresh_token, 6) {
                    cfg.refresh_token = v.to_string();
                }
            }
            if let Some(v) = parsed.get("appid") {
                if let Ok(a) = v.trim().parse::<u32>() {
                    cfg.appid = a;
                }
            }
            if let Some(v) = parsed.get("heartbeat_secs") {
                if let Ok(h) = v.trim().parse::<u8>() {
                    cfg.heartbeat_secs = h.clamp(10, 255);
                }
            }
            if let Some(v) = parsed.get("power_mode") {
                cfg.power_mode = match v.trim() {
                    "0" => POWER_SAVE,
                    "2" => POWER_PERF,
                    _ => POWER_BALANCED,
                };
            }
            if let Some(v) = parsed.get("auto_start") {
                cfg.auto_start = matches!(v.trim(), "1" | "true" | "on");
            }
            *state.cfg.lock().unwrap() = cfg.clone();
            state.config_dirty.store(true, Ordering::Relaxed);

            // 配网模式：提交 WiFi 后短暂停留让响应送达，再通知配网循环切换 STA
            if state.provisioning.load(Ordering::Relaxed) && !cfg.wifi_ssid.is_empty() {
                log::info!("provision config received, notifying setup");
                let mut resp = request.into_response(200, Some("OK"), &[("Content-Type", "application/json; charset=utf-8")])?;
                resp.write_all(b"{\"ok\":true,\"provisioning\":true}")?;
                std::thread::sleep(Duration::from_millis(300));
                state.wifi_submitted.store(true, Ordering::Relaxed);
                return Ok(());
            }

            log::info!("config updated via web, ready={}", cfg.is_ready());

            let mut resp = request.into_response(200, Some("OK"), &[("Content-Type", "application/json; charset=utf-8")])?;
            resp.write_all(b"{\"ok\":true}")?;
            Ok(())
        }
    })?;

    // 启动挂机（实时可控，无需重启开发板）
    server.fn_handler("/api/start", Method::Post, {
        let state = state.clone();
        move |request| -> Result<(), EspIOError> {
            // 服务端统一校验：与挂机线程共用 Config::missing()，前端不再重复实现规则
            let missing = {
                let c = state.cfg.lock().unwrap();
                if c.is_ready() {
                    String::new()
                } else {
                    c.missing_text()
                }
            };
            if !missing.is_empty() {
                log::warn!("start rejected, missing: {}", missing);
                let body = format!(
                    "{{\"ok\":false,\"error\":\"配置不完整：缺少 {}\"}}",
                    crate::config::escape_json(&missing)
                );
                let mut resp = request.into_response(
                    400,
                    Some("Bad Request"),
                    &[("Content-Type", "application/json; charset=utf-8")],
                )?;
                resp.write_all(body.as_bytes())?;
                return Ok(());
            }
            state.fatal.store(false, Ordering::Relaxed);
            state.steam_start.store(true, Ordering::Relaxed);
            state.last_error.lock().unwrap().clear();
            let mut resp = request.into_response(200, Some("OK"), &[("Content-Type", "application/json; charset=utf-8")])?;
            resp.write_all(b"{\"ok\":true}")?;
            Ok(())
        }
    })?;

    // 停止挂机
    server.fn_handler("/api/stop", Method::Post, {
        let state = state.clone();
        move |request| -> Result<(), EspIOError> {
            state.steam_start.store(false, Ordering::Relaxed);
            let mut resp = request.into_response(200, Some("OK"), &[("Content-Type", "application/json; charset=utf-8")])?;
            resp.write_all(b"{\"ok\":true}")?;
            Ok(())
        }
    })?;

    // 提交 Steam Mobile 生成的登录令牌
    server.fn_handler("/api/totp", Method::Post, {
        let state = state.clone();
        move |mut request| -> Result<(), EspIOError> {
            let mut body = Vec::with_capacity(64);
            let mut buf = [0u8; 64];
            loop {
                match request.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        body.extend_from_slice(&buf[..n]);
                        if body.len() > 128 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let body_str = String::from_utf8_lossy(&body).to_string();
            let parsed = parse_form(&body_str);
            if let Some(code) = parsed.get("code") {
                let c = code.trim().to_string();
                if !c.is_empty() {
                    *state.totp.lock().unwrap() = c;
                }
            }
            let mut resp = request.into_response(200, Some("OK"), &[("Content-Type", "application/json; charset=utf-8")])?;
            resp.write_all(b"{\"ok\":true}")?;
            Ok(())
        }
    })?;

    // 重启
    server.fn_handler("/api/reboot", Method::Post, {
        let state = state.clone();
        move |request| -> Result<(), EspIOError> {
            // 先等主循环把未落盘的配置写完，避免"保存配置后立刻重启"导致新密码丢失
            std::thread::sleep(Duration::from_millis(300));
            for _ in 0..20 {
                if !state.config_dirty.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            state.reboot_req.store(true, Ordering::Relaxed);
            let mut resp = request.into_ok_response()?;
            resp.write_all(b"rebooting...")?;
            Ok(())
        }
    })?;

    log::info!("web server started on :80");
    Ok(server)
}

fn parse_form(s: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(url_decode(k), url_decode(v));
    }
    map
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// 供引用避免 Config 未使用告警
#[allow(dead_code)]
fn _cfg_type(_c: Config) {}
