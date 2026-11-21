# ESP32-C3 SM ASF

基于 ESP32-C3 的 Steam 在线状态维持固件（Rust + ESP-IDF 6.1）。

固件在设备本地完成 Steam 新版认证与 CM 登录，不依赖电脑端脚本；提供 Web 仪表盘用于配网、查看状态与修改配置。

## 功能

- **Steam 新版认证**：使用账号密码通过 CM 统一消息服务换取 refresh token，再以 access_token 登录 CM（WebSocket over TLS，443 /cmsocket/）。
- **AppID 校验**：登录后通过 PICS 查询 AppID，不存在时立即停止并显示错误，不做静默上报。
- **账号占用检测**：账号被其他计算机占用、凭据错误时主动停止并提示，不清除已保存的凭据。
- **心跳与游戏时长上报**：按配置的心跳间隔维护在线状态并上报游戏时长。
- **断线自动恢复**：WiFi 链路守护（2s→30s 指数退避重连）与 CM 会话指数退避重连。
- **开机自动挂机**：可在仪表盘开关；配置不完整时不会自行启动。
- **Web 仪表盘**：状态、阶段、在线时长、RSSI、心跳计数、配置项。
- **无密码 SoftAP 配网**：未配置 WiFi 时自动开启 `ESP32-C3-SM-ASF`，访问 `http://192.168.4.1`。
- **低写入持久化**：仅将配置写入 LittleFS 的 `config.bin`（数百字节），不持久化任何日志或运行数据。

## 硬件要求

- ESP32-C3（QFN32），4MB Flash，USB-Serial/JTAG，40MHz 晶振。
- 已验证芯片修订：v0.4（4MB XMC Flash）。
- 不支持 2MB Flash 版本。

> 说明：个别批次的 ESP32-C3 开发板存在射频发射异常（能正常接收、无法发射信标），表现为开启 SoftAP 后任何设备都搜不到该热点。该现象与固件无关，串口日志仍会正常打印 `softAP`。遇到时请更换开发板。

## 发布包内容

| 文件 | 烧录地址 | 说明 |
|---|---|---|
| `esp32c3-sm-asf-merged.bin` | `0x0` | 整包镜像（bootloader + 分区表 + 应用），推荐 |
| `esp32c3-sm-asf.bin` | `0x20000` | 应用镜像 |
| `bootloader.bin` | `0x0` | 引导程序 |
| `partition-table.bin` | `0x8000` | 分区表 |

## 烧录

整包烧录（推荐）：

```bash
esptool --chip esp32c3 -p <端口> -b 460800 write-flash 0x0 esp32c3-sm-asf-merged.bin
```

分文件烧录：

```bash
esptool --chip esp32c3 -p <端口> -b 460800 write-flash \
  0x0 bootloader.bin 0x8000 partition-table.bin 0x20000 esp32c3-sm-asf.bin
```

开发板为空片时会在启动模式与下载模式间反复重启，设备管理器中表现为端口反复出现/消失，属正常现象，烧录有效固件后即恢复稳定。

## 首次使用

1. 上电后连接 WiFi `ESP32-C3-SM-ASF`（开放网络，无密码）。
2. 浏览器打开 `http://192.168.4.1`，填写 WiFi 名称、WiFi 密码、Steam 账号与密码，提交。
3. 设备验证联网成功后切换到 STA 模式，串口会打印分配到的局域网地址。
4. 打开该地址的仪表盘，点击「启动挂机」。
5. 首次登录需要在 Steam 手机 App 中确认；成功后 refresh token 自动保存。

阶段变化：`connecting` → `authenticating` → `logging_in` → `verifying` → `running`。

## 仪表盘字段

| 字段 | 说明 |
|---|---|
| `phase` | 当前阶段 |
| `online_secs` | 本次登录成功后的在线时长（单调时钟计时） |
| `rssi` | 当前 WiFi 信号强度（dBm） |
| `heartbeat_count` | 心跳次数 |
| `awaiting_2fa` | 是否等待 Steam 手机确认 |
| `error` | 最后一次错误信息 |

## 故障排查

- **搜不到 `ESP32-C3-SM-ASF`**：确认供电充足；空片会因无有效固件反复重启。接串口（115200）应能看到 `provisioning AP` 日志。若日志正常但所有设备都搜不到，参考上文射频异常说明。
- **登录失败**：仪表盘 `error` 会给出原因（AppID 不存在、账号被占用、凭据错误等），修复后点击「启动挂机」重试。
- **仪表盘无法访问**：WiFi 掉线后守护会自动重连，串口可见 `wifi link down, reconnecting` 与 `wifi link restored`。
- **配置无法保存**：检查 `storage` 分区是否完整；固件启动时会在串口打印挂载结果。

## 构建

构建前需自行准备 ESP-IDF 6.1 工具链，并设置 `ESP_IDF_PATH`、`IDF_PATH`、`IDF_TOOLS_PATH`、`ESP_ROM_ELF_DIR` 等环境变量。仓库内的 `.cargo/config.toml` 只保留通用配置，不包含任何本机绝对路径。

```bash
cargo build --release
esptool --chip esp32c3 elf2image --flash-mode dio --flash-freq 40m --flash-size 4MB \
  -o esp32c3-sm-asf.bin target/riscv32imc-esp-espidf/release/esp32c3-sm-asf
python tools/finalize_image.py esp32c3-sm-asf.bin
esptool --chip esp32c3 merge-bin -o esp32c3-sm-asf-merged.bin \
  --flash-mode dio --flash-freq 40m --flash-size 4MB \
  0x0 bootloader.bin 0x8000 partition-table.bin 0x20000 esp32c3-sm-asf.bin
```

`tools/finalize_image.py` 会把 ESP-IDF 默认写入的 `App version` 清零，保证发布镜像不内置版本号。

## 版本策略

固件不定义任何版本号；版本信息仅存在于 git tag 与发布包文件名。

## 免责声明

本项目仅供学习与研究使用。使用本固件产生的任何后果由使用者自行承担，请遵守 Steam 服务条款及所在地法律法规。

## 许可证

MIT
