//! ESP32-C3 SuperMini 极简 Steam 挂机客户端（研究级）
//!
//! M1：配置子系统（LittleFS 持久化 + 二进制编解码 + Web 仪表盘）
//! M2：挂机核心 MVP（WiFi + SNTP + Steam CM 登录/心跳/游戏上报）
//! 配网：未配置 WiFi 时开放无密码 SoftAP 配网页，填表后验证联网并自动切换

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use embedded_svc::ipv4::{Configuration as IpConfig, Ipv4Addr, Mask, RouterConfiguration, Subnet};
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::netif::{EspNetif, NetifConfiguration, NetifStack};
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::esp_restart;
use esp_idf_svc::wifi::{EspWifi, WifiDriver, WifiEvent};

mod auth;
mod config;
mod idle;
mod proto;
mod state;
mod steam;
mod storage;
mod verify;
mod web;
mod wifi;

use state::AppState;
use storage::Storage;

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    log::info!("ESP32-C3 SM ASF starting");

    let peripherals = Peripherals::take().unwrap();
    let sysloop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    // ---- 配置持久化（M1）----
    let storage = Storage::mount().map_err(|e| {
        log::error!("littlefs mount failed: {}", e);
        e
    })?;
    let cfg = storage.load_config().map_err(|e| anyhow::anyhow!("load config failed: {}", e))?.unwrap_or_default();
    if cfg.wifi_ssid.is_empty() {
        log::warn!("no wifi configured, entering provisioning mode");
    } else if cfg.is_ready() {
        log::info!("loaded config: account={}", cfg.account);
    } else {
        log::warn!("wifi configured but account missing, configure via dashboard");
    }

    let state = Arc::new(AppState::new(cfg.clone()));

    // ---- WiFi 初始化（netif 就绪后即可绑定 HTTP :80）----
    // AP netif 固定网关 192.168.4.1，与配网页入口一致
    let modem = peripherals.modem;
    let wifi_driver = WifiDriver::new(modem, sysloop.clone(), Some(nvs))?;
    let mut wifi = EspWifi::wrap_all(
        wifi_driver,
        EspNetif::new(NetifStack::Sta)?,
        EspNetif::new_with_conf(&NetifConfiguration {
            ip_configuration: Some(IpConfig::Router(RouterConfiguration {
                subnet: Subnet {
                    gateway: Ipv4Addr::new(192, 168, 4, 1),
                    mask: Mask(24),
                },
                dhcp_enabled: true,
                dns: Some(Ipv4Addr::new(192, 168, 4, 1)),
                secondary_dns: None,
            })),
            ..NetifConfiguration::wifi_default_router()
        })?,
    )?;

    // ---- 订阅 STA 断连事件，记录 ESP-IDF reason code（用于入网失败确诊）----
    let _disc_sub = sysloop.subscribe::<WifiEvent, _>(move |event: WifiEvent| {
        if let WifiEvent::StaDisconnected(r) = event {
            wifi::note_disconnect(r.reason());
            log::warn!(
                "[diag] STA disconnected: reason={} (0x{:04x}), rssi={}",
                r.reason(),
                r.reason(),
                r.rssi()
            );
        }
    })?;

    // ---- Web 服务：配网与仪表盘共用（持有 server 防止 drop 关闭）----
    let _http_server = web::start(state.clone())?;

    // ---- 接入 WiFi：未配置 → 无密码 SoftAP 配网；已配置 → 直连 STA ----
    if cfg.wifi_ssid.is_empty() {
        wifi::provision_softap(&mut wifi, &state, &storage)?;
        log::info!("provisioning complete, config saved");
    } else if let Err(e) = wifi::connect_sta(&mut wifi, &cfg, &state) {
        // 连不上 WiFi 时继续运行：仪表盘不可达，但串口与 Web 服务仍在
        log::error!("wifi connect failed: {} (continue without network)", e);
    }

    // ---- 启动挂机线程（Steam CM 状态机）----
    // 栈需 >= 48KB：CM 的 Multi 消息解压调用 ROM 版 tinfl_decompress_mem_to_mem，
    // 其内部 tinfl_decompressor 结构体约 12KB 且分配在栈上；8KB 栈会直接触发
    // Stack protection fault（实测 0x3fcad4a4-0x3fcaf4a0 仅 8192 字节）。
    let st = state.clone();
    std::thread::Builder::new()
        .name("steam".into())
        .stack_size(48 * 1024)
        .spawn(move || steam::run(st))?;

    // ---- 主循环：WiFi 守护 + 落盘配置 + 重启控制 ----
    let mut wifi_guard = wifi::WifiGuard::new();
    loop {
        std::thread::sleep(Duration::from_millis(500));

        // STA 掉线自动重连（ESP-IDF 不会自行重连，只能靠这里恢复）
        wifi_guard.tick(&mut wifi, &state);

        // 配置变更落盘（唯一入口）
        if state.config_dirty.swap(false, Ordering::Relaxed) {
            match storage::persist(&state, &storage) {
                Ok(()) => log::info!("config saved to littlefs"),
                Err(_) => log::error!("config save failed"),
            }
        }

        // 请求重启
        if state.reboot_req.swap(false, Ordering::Relaxed) {
            log::warn!("reboot requested, restarting...");
            std::thread::sleep(Duration::from_millis(300));
            unsafe { esp_restart() };
        }
    }
}

