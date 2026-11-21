//! LittleFS 存储：配置文件的持久化读写

use esp_idf_svc::fs::littlefs::Littlefs;
use esp_idf_svc::io::vfs::MountedLittlefs;

use crate::config::{Config, CFG_PATH};
use crate::state::AppState;
use std::sync::Arc;

/// 向 littlefs 写入文件（绕过 Rust std 的 O_CREAT 位错误）。
/// 根因：Rust libc crate 对 esp-idf 目标仍使用旧值 O_CREAT=0x200，
/// 而 IDF 6.1 newlib 实际 O_CREAT=0x40。esp_littlefs 的
/// esp_littlefs_flags_conv 按 IDF 6.1 头文件解析 flags 时看不到
/// O_CREAT 位，导致 lfs open 不存在的文件直接返回 LFS_ERR_NOENT(ENOENT)。
/// 这里显式使用 esp_idf_svc::sys 绑定中的正确常量（O_CREAT=64）。
fn lfs_write(path: &str, data: &[u8]) -> Result<(), &'static str> {
    let c_path = std::ffi::CString::new(path).map_err(|_| "path contains NUL")?;
    let flags =
        (esp_idf_svc::sys::O_WRONLY | esp_idf_svc::sys::O_CREAT | esp_idf_svc::sys::O_TRUNC)
            as i32; // 1|64|512 = 0x241
    let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o644) };
    if fd < 0 {
        log::error!(
            "[lfs_write] open {} -> fd={} errno={:?}",
            path,
            fd,
            std::io::Error::last_os_error().raw_os_error()
        );
        return Err("open failed");
    }
    let mut off = 0usize;
    while off < data.len() {
        let n = unsafe {
            libc::write(
                fd,
                data[off..].as_ptr() as *const libc::c_void,
                data.len() - off,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error().raw_os_error();
            unsafe { libc::close(fd) };
            log::error!("[lfs_write] write {} -> errno={:?}", path, e);
            return Err("write failed");
        }
        off += n as usize;
    }
    unsafe { libc::close(fd) };
    Ok(())
}

pub struct Storage {
    _mount: MountedLittlefs<Littlefs<()>>,
}

impl Storage {
    /// 挂载 storage 分区（littlefs, 256KB）；卷不可用/不可写时强制格式化重建
    pub fn mount() -> Result<Self, esp_idf_svc::sys::EspError> {
        // Safety: "storage" 分区标签在 partitions.csv 中定义
        let littlefs = unsafe { Littlefs::<()>::new_partition("storage") }?;
        match MountedLittlefs::mount(littlefs, "/littlefs") {
            Ok(mount) => {
                log::info!("[diag] littlefs mount OK (first branch)");
                if Self::fs_writable() {
                    log::info!("[diag] probe write OK, existing volume usable");
                    std::fs::create_dir_all("/littlefs").ok();
                    Ok(Self { _mount: mount })
                } else {
                    log::warn!("[diag] existing volume not writable, dropping and reformatting");
                    drop(mount);
                    Self::mount_formatted()
                }
            }
            Err(first_err) => {
                log::warn!("littlefs mount failed ({}), formatting partition...", first_err);
                Self::mount_formatted()
            }
        }
    }

    /// 强制格式化 storage 分区后重新挂载，并验证可写
    fn mount_formatted() -> Result<Self, esp_idf_svc::sys::EspError> {
        let mut lfs = unsafe { Littlefs::<()>::new_partition("storage") }?;
        lfs.format()?;
        log::info!("[diag] format done");
        let mount = MountedLittlefs::mount(lfs, "/littlefs")?;
        log::info!("[diag] littlefs mount OK (after format)");
        if !Self::fs_writable() {
            log::error!("[diag] volume still not writable after format");
            return Err(esp_idf_svc::sys::esp!(esp_idf_svc::sys::ESP_FAIL).unwrap_err());
        }
        std::fs::create_dir_all("/littlefs").ok();
        Ok(Self { _mount: mount })
    }

    /// 写探测：向挂载点写根级文件，验证卷真实可写
    fn fs_writable() -> bool {
        match lfs_write("/littlefs/_probe.bin", b"ok") {
            Ok(_) => {
                let _ = std::fs::remove_file("/littlefs/_probe.bin");
                true
            }
            Err(e) => {
                log::error!("[diag] probe write failed: {}", e);
                false
            }
        }
    }

    pub fn load_config(&self) -> Result<Option<Config>, &'static str> {
        match std::fs::read(CFG_PATH) {
            Ok(raw) => match Config::decode(&raw) {
                Ok(cfg) => Ok(Some(cfg)),
                Err(e) => {
                    log::warn!("config decode failed: {}", e);
                    Ok(None)
                }
            },
            Err(_) => Ok(None),
        }
    }

    pub fn save_config(&self, cfg: &Config) -> Result<(), &'static str> {
        let raw = cfg.encode().map_err(|_| "config encode failed")?;
        log::info!("[diag] save_config: {} bytes -> {:?}", raw.len(), CFG_PATH);
        lfs_write(CFG_PATH, &raw).map_err(|e| {
            log::error!("[diag] save config failed: {}", e);
            "config write failed"
        })
    }
}

/// 唯一配置落盘入口：从共享状态取最新配置写入 LittleFS，并清除脏标记。
/// 主循环与配网流程都走这里，避免出现多条持久化路径。
pub fn persist(state: &Arc<AppState>, storage: &Storage) -> Result<(), &'static str> {
    let cfg = state.cfg.lock().unwrap().clone();
    let r = storage.save_config(&cfg);
    if r.is_ok() {
        state
            .config_dirty
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
    r
}
