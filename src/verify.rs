//! 账号与 AppID 验证（挂机流水线的最高优先级阶段）
//!
//! 设计要点：
//! - 验证不单独建连接：复用当前 CM 会话完成，避免二次登录触发 Steam 限流，
//!   因此"验证"是会话流水线的第一个阶段，而不是独立会话。
//! - 只有本模块确认通过后，idle 模块才允许上报游戏，从根上避免
//!   "已登录但 AppID 无效导致静默假成功"。
//! - 账号本身的真实性由 auth::authenticate（凭据）+ CM 登录响应（EResult）保证，
//!   本模块负责登录之后的 AppID 存在性校验。

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::proto::{
    build_pics_app_request, parse_pics_response, Frame, EMsg_CLIENT_PICS_PRODUCT_INFO_RESPONSE,
};
use crate::state::AppState;

/// 等待 PICS 响应的上限；超时放行并告警，避免查询失败卡住挂机
const TIMEOUT: Duration = Duration::from_secs(8);

/// AppID 存在性校验状态机
pub struct AppIdCheck {
    sent: bool,
    done: bool,
    deadline: Instant,
    /// PICS 响应中确认存在的 appid
    apps: Vec<u32>,
    /// PICS 响应中标记为不存在的 appid
    unknown: Vec<u32>,
}

impl AppIdCheck {
    pub fn new() -> Self {
        Self {
            sent: false,
            done: false,
            deadline: Instant::now(),
            apps: Vec::new(),
            unknown: Vec::new(),
        }
    }

    /// 是否还需要发送查询请求
    pub fn need_request(&self) -> bool {
        !self.sent
    }

    /// 生成查询请求帧（协议编码仍由 proto 负责）
    pub fn request(&mut self, appid: u32, steam_id: u64) -> Vec<u8> {
        self.sent = true;
        self.deadline = Instant::now() + TIMEOUT;
        build_pics_app_request(appid, steam_id)
    }

    /// 校验是否已完成（含超时放行）
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// 超时检查：无响应则放行，只告警不影响挂机
    pub fn tick(&mut self) {
        if !self.done && self.sent && Instant::now() >= self.deadline {
            log::warn!("appid verification timeout, proceeding without confirmation");
            self.done = true;
        }
    }

    /// 处理一帧：返回 Ok(true) 表示该帧属于本模块（已消费）
    pub fn on_frame(
        &mut self,
        state: &Arc<AppState>,
        frame: &Frame,
        appid: u32,
    ) -> Result<bool, String> {
        if frame.emsg != EMsg_CLIENT_PICS_PRODUCT_INFO_RESPONSE {
            return Ok(false);
        }
        let (mut apps, mut unknown, pending) = parse_pics_response(&frame.body);
        self.apps.append(&mut apps);
        self.unknown.append(&mut unknown);
        if pending {
            return Ok(true);
        }
        if self.unknown.contains(&appid) {
            let msg = format!(
                "AppID {} 不存在，已停止挂机；请在配置中填写有效的 AppID",
                appid
            );
            log::error!("{}", msg);
            state.halt(msg.clone());
            return Err(msg);
        }
        if self.apps.contains(&appid) {
            log::info!("appid {} verified via PICS", appid);
        } else {
            // 既未确认存在、也未被标为 unknown（例如无访问权限）：放行并告警
            log::warn!("appid {} not confirmed by PICS, proceeding", appid);
        }
        self.done = true;
        Ok(true)
    }
}
