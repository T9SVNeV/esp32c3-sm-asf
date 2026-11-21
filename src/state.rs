//! 共享应用状态（Web 仪表盘与挂机线程之间同步）

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8};
use std::sync::Mutex;

use crate::config::Config;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SteamState {
    Stopped,
    Connecting,
    LoggedIn,
    Error,
}

impl SteamState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SteamState::Stopped => "stopped",
            SteamState::Connecting => "connecting",
            SteamState::LoggedIn => "logged_in",
            SteamState::Error => "error",
        }
    }
}

/// 会话阶段（对外可见，仪表盘按此展示"当前在做什么"）
#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Phase {
    Stopped = 0,
    Connecting,
    Authenticating,
    LoggingIn,
    Verifying,
    Running,
    Error,
}

impl Phase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Stopped => "stopped",
            Phase::Connecting => "connecting",
            Phase::Authenticating => "authenticating",
            Phase::LoggingIn => "logging_in",
            Phase::Verifying => "verifying",
            Phase::Running => "running",
            Phase::Error => "error",
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Phase::Stopped,
            1 => Phase::Connecting,
            2 => Phase::Authenticating,
            3 => Phase::LoggingIn,
            4 => Phase::Verifying,
            5 => Phase::Running,
            _ => Phase::Error,
        }
    }
}

pub struct AppState {
    pub cfg: Mutex<Config>,
    pub wifi_connected: AtomicBool,
    pub wifi_rssi: AtomicU8,
    pub steam_state: Mutex<SteamState>,
    /// 当前会话阶段（connecting/authenticating/logging_in/verifying/running）
    pub phase: AtomicU8,
    pub steam_eresult: AtomicU32,
    /// 登录成功后服务器下发的真实 SteamID（用于后续消息的 proto header）
    /// 注意：ESP32-C3 无 64 位原子指令，std 不提供 AtomicU64，只能用 Mutex。
    pub steam_id: Mutex<u64>,
    pub last_heartbeat: Mutex<u64>, // unix secs
    pub heartbeat_count: AtomicU32,
    /// 登录成功（EResult=1）的时刻，用单调时钟计时，避免 SNTP 未校时导致在线时长失真
    pub login_at: Mutex<Option<std::time::Instant>>,
    pub last_error: Mutex<String>,
    pub reboot_req: AtomicBool,
    pub config_dirty: AtomicBool,
    pub totp: Mutex<String>,
    /// 用户是否已点击"启动挂机"（实时可控，而非重启即自动挂机）
    pub steam_start: AtomicBool,
    /// 因确定不可恢复的错误（AppID 不存在、账号被占用、凭据错误）主动停止：
    /// 不自动重连，界面保持 Error 与错误文案，直到用户再次点击"启动挂机"
    pub fatal: AtomicBool,
    /// 登录需要 Steam Mobile 确认/令牌（前端显示高亮提示并轮询）
    pub awaiting_2fa: AtomicBool,
    /// 是否处于配网模式（SoftAP 开放，根路径渲染配网页）
    pub provisioning: AtomicBool,
    /// 配网表单已提交，通知配网循环切换到 STA
    pub wifi_submitted: AtomicBool,
}

impl AppState {
    pub fn new(cfg: Config) -> Self {
        // 开机自动挂机：配置就绪（WiFi/AppID/凭据齐全）且用户开启了 auto_start 时，
        // 启动即进入挂机状态，无需人工点「启动挂机」；未就绪则保持停止，等配网。
        let auto_start = cfg.auto_start && cfg.is_ready();
        Self {
            cfg: Mutex::new(cfg),
            wifi_connected: AtomicBool::new(false),
            wifi_rssi: AtomicU8::new(0),
            steam_state: Mutex::new(SteamState::Stopped),
            phase: AtomicU8::new(Phase::Stopped as u8),
            steam_eresult: AtomicU32::new(0),
            steam_id: Mutex::new(0),
            last_heartbeat: Mutex::new(0),
            heartbeat_count: AtomicU32::new(0),
            login_at: Mutex::new(None),
            last_error: Mutex::new(String::new()),
            reboot_req: AtomicBool::new(false),
            config_dirty: AtomicBool::new(false),
            totp: Mutex::new(String::new()),
            steam_start: AtomicBool::new(auto_start),
            fatal: AtomicBool::new(false),
            awaiting_2fa: AtomicBool::new(false),
            provisioning: AtomicBool::new(false),
            wifi_submitted: AtomicBool::new(false),
        }
    }

    /// 主动停止挂机并记录错误：不清除凭据，也不再自动重连。
    /// 用于 AppID 不存在、账号被其他设备占用、账号密码错误等确定性失败。
    pub fn halt(&self, msg: String) {
        *self.last_error.lock().unwrap() = msg;
        *self.steam_state.lock().unwrap() = SteamState::Error;
        self.awaiting_2fa
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.fatal
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.steam_start
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// 更新会话阶段（供仪表盘展示）
    pub fn set_phase(&self, p: Phase) {
        self.phase
            .store(p as u8, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn status_json(&self, now: u64) -> String {
        let state = *self.steam_state.lock().unwrap();
        let eresult = self.steam_eresult.load(std::sync::atomic::Ordering::Relaxed);
        let hb = self.heartbeat_count.load(std::sync::atomic::Ordering::Relaxed);
        let last_hb = *self.last_heartbeat.lock().unwrap();
        // 在线时长用单调时钟计时：从 ClientLogon 返回 EResult=1（logged_in）开始，
        // 与 SNTP 是否校时无关，避免"已登录但时长一直为 0"。
        let online_secs = if state == SteamState::LoggedIn {
            self.login_at
                .lock()
                .unwrap()
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0)
        } else {
            0
        };
        let started = self.steam_start.load(std::sync::atomic::Ordering::Relaxed);
        let awaiting = self.awaiting_2fa.load(std::sync::atomic::Ordering::Relaxed);
        let err = self.last_error.lock().unwrap().clone();
        // 负值以补码存储，这里按 i8 还原成有符号 RSSI
        let rssi = self.wifi_rssi.load(std::sync::atomic::Ordering::Relaxed) as i8 as i32;
        let wifi = self.wifi_connected.load(std::sync::atomic::Ordering::Relaxed);
        let phase = Phase::from_u8(self.phase.load(std::sync::atomic::Ordering::Relaxed));
        format!(
            "{{\"wifi\":{},\"rssi\":{},\"steam\":\"{}\",\"phase\":\"{}\",\"eresult\":{},\"online_secs\":{},\"heartbeat_count\":{},\"last_heartbeat\":{},\"started\":{},\"awaiting_2fa\":{},\"uptime\":{},\"error\":\"{}\"}}",
            wifi,
            rssi,
            state.as_str(),
            phase.as_str(),
            eresult,
            online_secs,
            hb,
            last_hb,
            started,
            awaiting,
            now,
            crate::config::escape_json(&err),
        )
    }
}
