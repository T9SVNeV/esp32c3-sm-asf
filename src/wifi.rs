//! WiFi 接入与配网（唯一实现）
//!
//! 开机直连与配网成功后切换 STA 共用 `connect_sta()`，避免两处逻辑漂移。

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use embedded_svc::wifi::AuthMethod;
use esp_idf_svc::sntp::{EspSntp, SntpConf};
use esp_idf_svc::wifi::{
    AccessPointConfiguration, ClientConfiguration, Configuration as WifiConf, EspWifi,
};

use crate::config::Config;
use crate::state::AppState;
use crate::storage::Storage;

/// 配网模式开放的 SoftAP 名称（无密码）
pub const AP_SSID: &str = "ESP32-C3-SM-ASF";
/// SoftAP 网关地址，配网页访问入口
pub const AP_IP: &str = "192.168.4.1";

/// 最近一次 STA 断连的 ESP-IDF reason code（0=从未断连过）
static LAST_DISC_REASON: AtomicU16 = AtomicU16::new(0);

/// 记录断连原因（由事件订阅回调调用）
pub fn note_disconnect(reason: u16) {
    LAST_DISC_REASON.store(reason, Ordering::Relaxed);
}

fn take_disconnect_reason() -> u16 {
    LAST_DISC_REASON.swap(0, Ordering::Relaxed)
}

/// WiFi 守护：主循环周期性调用，STA 掉线后按指数退避重连。
///
/// 背景：ESP-IDF 的 station 收到 AP 的 deauth/disassoc（如家用路由的 idle kick，
/// reason=8）后不会自行重连。没有守护时只能重启开发板恢复，表现为挂机一段时间后
/// 仪表盘与挂机同时不可用。
pub struct WifiGuard {
    delay: Duration,
    next_try: Instant,
}

impl WifiGuard {
    pub fn new() -> Self {
        Self {
            delay: Duration::from_secs(2),
            next_try: Instant::now(),
        }
    }

    /// 主循环反复调用（约 2 次/秒）。仅在已配网且非配网模式下生效。
    pub fn tick(&mut self, wifi: &mut EspWifi, state: &Arc<AppState>) {
        // 配网 AP 模式由 provision_softap 独占，守护不介入
        if state.provisioning.load(Ordering::Relaxed) {
            return;
        }
        if state.cfg.lock().unwrap().wifi_ssid.is_empty() {
            return;
        }

        if wifi.is_connected().unwrap_or(false) {
            update_rssi(state);
            // 链路已恢复但尚未确认拿到 IP：补齐状态并复位退避
            if !state.wifi_connected.load(Ordering::Relaxed) {
                if let Ok(info) = wifi.sta_netif().get_ip_info() {
                    if info.ip != embedded_svc::ipv4::Ipv4Addr::new(0, 0, 0, 0) {
                        state.wifi_connected.store(true, Ordering::Relaxed);
                        log::warn!("wifi link restored, ip={}", info.ip);
                        self.delay = Duration::from_secs(2);
                        self.next_try = Instant::now();
                    }
                }
            }
            return;
        }

        state.wifi_connected.store(false, Ordering::Relaxed);
        let now = Instant::now();
        if now < self.next_try {
            return;
        }
        log::warn!("wifi link down, reconnecting in {}s", self.delay.as_secs());
        if let Err(e) = wifi.connect() {
            log::error!("wifi reconnect failed: {}", e);
        }
        self.delay = core::cmp::min(self.delay * 2, Duration::from_secs(30));
        self.next_try = now + self.delay;
    }
}

/// 刷新仪表盘 RSSI（仅连接态有效）
fn update_rssi(state: &Arc<AppState>) {
    let mut ap: esp_idf_svc::sys::wifi_ap_record_t = unsafe { core::mem::zeroed() };
    let r = unsafe { esp_idf_svc::sys::esp_wifi_sta_get_ap_info(&mut ap) };
    if r == esp_idf_svc::sys::ESP_OK {
        // 负值以补码存入 u8，读取时按 i8 还原（见 state.rs status_json）
        state.wifi_rssi.store(ap.rssi as u8, Ordering::Relaxed);
    }
}

/// 连接指定 WiFi 并等待 DHCP，成功后打印入口地址并启动 SNTP。
///
/// 失败时写入 `state.last_error` 并返回 Err，调用方决定继续运行还是重开 AP。
pub fn connect_sta(
    wifi: &mut EspWifi,
    cfg: &Config,
    state: &Arc<AppState>,
) -> anyhow::Result<()> {
    wifi.set_configuration(&WifiConf::Client(ClientConfiguration {
        ssid: heapless::String::<32>::try_from(cfg.wifi_ssid.as_str()).unwrap_or_default(),
        password: heapless::String::<64>::try_from(cfg.wifi_pass.as_str()).unwrap_or_default(),
        ..Default::default()
    }))?;
    wifi.start()?;
    wifi.connect()?;
    log::info!("connecting wifi: {}", cfg.wifi_ssid);
    take_disconnect_reason();

    // 最多等待 30s
    let mut connected = false;
    for _ in 0..300 {
        if wifi.is_connected()? {
            connected = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !connected {
        state.wifi_connected.store(false, Ordering::Relaxed);
        let reason = take_disconnect_reason();
        let msg = if reason != 0 {
            format!(
                "wifi connect failed: {} (disconnect reason={reason}, 0x{reason:04x})",
                cfg.wifi_ssid
            )
        } else {
            format!(
                "wifi connect failed: {} (no disconnect event within 30s)",
                cfg.wifi_ssid
            )
        };
        log::error!("{}", msg);
        *state.last_error.lock().unwrap() = msg.clone();
        return Err(anyhow::anyhow!(msg));
    }

    state.wifi_connected.store(true, Ordering::Relaxed);
    log::info!("wifi connected, waiting dhcp ip...");
    if !wait_sta_ip(wifi, Duration::from_secs(20)) {
        state.wifi_connected.store(false, Ordering::Relaxed);
        let msg = "dhcp timeout: no ip assigned".to_string();
        log::error!("{}", msg);
        *state.last_error.lock().unwrap() = msg.clone();
        return Err(anyhow::anyhow!(msg));
    }
    log_sta_ip(wifi);
    start_sntp();
    Ok(())
}

/// 未配置 WiFi：开放无密码 SoftAP 配网，验证联网成功后持久化并返回
pub fn provision_softap(
    wifi: &mut EspWifi,
    state: &Arc<AppState>,
    storage: &Storage,
) -> anyhow::Result<()> {
    loop {
        // 1. 开启无密码 AP（网关已由 AP netif 配置固定为 192.168.4.1）
        wifi.set_configuration(&WifiConf::AccessPoint(AccessPointConfiguration {
            ssid: heapless::String::<32>::try_from(AP_SSID).unwrap_or_default(),
            auth_method: AuthMethod::None,
            ..Default::default()
        }))?;
        wifi.start()?;
        state.provisioning.store(true, Ordering::Relaxed);
        log::warn!(
            "provisioning AP '{}' open (no password), connect and visit http://{}",
            AP_SSID,
            AP_IP
        );

        // 2. 等待用户提交配网表单（web.rs 置 wifi_submitted）
        while !state.wifi_submitted.swap(false, Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
        }
        state.provisioning.store(false, Ordering::Relaxed);
        log::info!("provision form submitted, switching to STA...");

        // 3. 关闭 AP，切换 STA（与开机直连共用同一实现）
        wifi.stop()?;
        let cfg = state.cfg.lock().unwrap().clone();
        if let Err(e) = connect_sta(wifi, &cfg, state) {
            log::error!("{}", e);
            continue; // 重开 AP 等用户修正
        }

        // 4. 验证外网可达（个人使用场景，无需安全限制）
        if !internet_reachable() {
            state.wifi_connected.store(false, Ordering::Relaxed);
            let msg = "internet check failed".to_string();
            log::error!("{}", msg);
            *state.last_error.lock().unwrap() = msg;
            continue;
        }
        log::info!("internet reachable, provisioning OK");

        // 5. 配置落盘（唯一入口；SNTP 已在 connect_sta 内启动）
        if let Err(e) = crate::storage::persist(state, storage) {
            log::error!("config save failed: {}", e);
            *state.last_error.lock().unwrap() = format!("config save failed: {}", e);
            continue; // 回 AP 让用户重新提交，避免程序整体退出
        }
        return Ok(());
    }
}

/// 等待 STA 通过 DHCP 拿到非 0.0.0.0 的 IP，超时返回 false
fn wait_sta_ip(wifi: &EspWifi, timeout: Duration) -> bool {
    use embedded_svc::ipv4::Ipv4Addr;
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(info) = wifi.sta_netif().get_ip_info() {
            if info.ip != Ipv4Addr::new(0, 0, 0, 0) {
                log::warn!("sta ip acquired: {}", info.ip);
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// 打印 STA 模式下路由器分配的 IP（仪表盘入口）
fn log_sta_ip(wifi: &EspWifi) {
    match wifi.sta_netif().get_ip_info() {
        Ok(info) => log::warn!("dashboard available at http://{}/ on your LAN", info.ip),
        Err(e) => log::warn!("sta ip not ready: {}", e),
    }
}

/// 启动 SNTP 校时（Steam 2FA 需要正确时间）
fn start_sntp() {
    match EspSntp::new(&SntpConf::default()) {
        Ok(_sntp) => log::info!("sntp started"),
        Err(e) => log::warn!("sntp start failed: {}", e),
    }
}

/// 外网验证：TCP 直连公共服务器，任一可达即视为已联网
fn internet_reachable() -> bool {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    let targets = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80),
    ];
    for t in targets {
        if TcpStream::connect_timeout(&t, Duration::from_secs(5)).is_ok() {
            return true;
        }
    }
    false
}
