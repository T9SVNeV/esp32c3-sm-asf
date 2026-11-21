//! 挂机保活：心跳与游戏时长上报
//!
//! 与传输层解耦：发送动作由调用方注入（闭包），本模块只负责节流与时序。

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::proto::{build_games_played, build_heartbeat};
use crate::state::AppState;
use crate::steam::now_unix;

pub struct Idle {
    heartbeat_interval: Duration,
    last_heartbeat: Instant,
    last_appid: Option<u32>,
}

impl Idle {
    pub fn new(heartbeat_secs: u64) -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(heartbeat_secs.max(10)),
            last_heartbeat: Instant::now(),
            last_appid: None,
        }
    }

    /// 一次节拍：按需发送心跳；`allow_report` 为真时才上报游戏。
    ///
    /// `allow_report` 由验证阶段（verify::AppIdCheck）决定，未通过验证绝不上报，
    /// 避免无效 AppID 造成"已登录但没在挂机"的假象。
    pub fn tick<F>(
        &mut self,
        send: &mut F,
        steam_id: u64,
        appid: u32,
        allow_report: bool,
        state: &Arc<AppState>,
    ) -> Result<(), String>
    where
        F: FnMut(&[u8]) -> Result<(), String>,
    {
        if self.last_heartbeat.elapsed() >= self.heartbeat_interval {
            send(&build_heartbeat(steam_id))?;
            *state.last_heartbeat.lock().unwrap() = now_unix();
            state.heartbeat_count.fetch_add(1, Ordering::Relaxed);
            self.last_heartbeat = Instant::now();
            log::debug!(
                "heartbeat #{}",
                state.heartbeat_count.load(Ordering::Relaxed)
            );
        }
        if allow_report && self.last_appid != Some(appid) {
            send(&build_games_played(appid, steam_id))?;
            self.last_appid = Some(appid);
            log::info!("games played reported: appid={}", appid);
        }
        Ok(())
    }
}
