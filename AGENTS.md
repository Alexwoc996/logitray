# AGENTS.md

Windows-only Rust 托盘应用：通过 HID++ 2.0 协议读取罗技无线鼠标的电池电量（不依赖 G HUB/Options+），并支持雷蛇无线键盘（2.4G dongle 私有协议）。

## 命令

- `cargo run` — 启动托盘应用
- `cargo run -- --once` — 打印当前电池电量后退出（设备验证）
- `cargo run -- --diag` — 转储 HID++ 接口、ping 结果与通知探测（硬件调试，需真实接收器）
- 验证顺序（与 CI 一致）：`cargo fmt --check` → `cargo test --all-targets` → `cargo build --release --target x86_64-pc-windows-msvc`
- 无 clippy/其他 linter；CI 只检查格式、测试和 MSVC release 构建（`.github/workflows/pr-build.yml`）

## 工具链坑

- 默认/CI 使用 MSVC 工具链（`x86_64-pc-windows-msvc`），开箱即用。
- 本地用 GNU 工具链需要完整的 MinGW-w64 在 PATH 上（`windows` crates 需要 `dlltool`/`as`，rustup 自带的 MinGW 不够）；`.cargo/config.toml` 指定 GNU 链接器为 `x86_64-w64-mingw32-gcc`。
- 构建目标为 Windows；非 Windows 下 tray 模式会直接报错（`src/app.rs:50`），但 `--once` 路径可编译。

## 结构

- 单一 Cargo 包，库 `src/lib.rs` + 薄壳 `src/main.rs`。`main.rs` 是 `windows_subsystem`（无控制台窗口），CLI 模式（`--once`/`--diag`）通过 `AttachConsole` 重新挂接父控制台，改 CLI 输出时勿破坏这一点（`src/main.rs:12`）。
- `src/hid/` 是核心协议层：`protocol.rs`（HID++ 帧编解码）、`scanner.rs`（接收器枚举）、`receiver.rs`（单接收器会话/通知）、`client.rs`（轮询与状态汇总）、`diag.rs`（调试模式）、`razer.rs`（雷蛇 2.4G dongle 电量，raw FFI 绕开 hidapi 的 feature-length 限制）。
- 其余：`tray.rs`（tao + tray-icon UI）、`icon.rs`（程序化绘制图标）、`config.rs`（`%APPDATA%\logitray\config.toml`）、`device_map.rs`（`devices.toml` 设备缓存，可删会自动重建）、`notify.rs`（tauri-winrt-notification toast + 冷却）、`autostart.rs`（winreg 注册表自启动）、`model.rs`（共享数据结构）。

## 测试

- 测试全部为各模块内 `#[cfg(test)]` 单元测试（`cargo test --all-targets`），多数不依赖硬件。
- 真实硬件行为（HID++ 通信、通知推送）无法用单测覆盖，用 `--once`/`--diag` 配合真实 LIGHTSPEED/Bolt/Unifying 接收器验证。

## 雷蛇模块注意事项（`src/hid/razer.rs`）

- dongle：`VID_1532 PID_027B MI_02`，90 字节 feature report，tid `0x9F`，CRC = bytes 2..=87 XOR。
- **必须用 raw FFI**（CreateFileW + HidD_SetFeature/GetFeature）：该接口 HIDP_CAPS 的 `FeatureReportByteLength=0`，hidapi windows-native 后端按 caps 定长缓冲会全部空回。
- 打开句柄用 **access=0**（rw 打开会 ACCESS_DENIED，因为设备含键盘顶层集合）；feature 传输在 0-access 句柄上仍然有效。
- 传输长度 91 字节（1 rid + 90 payload）；SET 前缀 rid 0x01。
- dongle 在键盘空闲几分钟会休眠，查询回 TIMEOUT——这是正常现象，敲键盘唤醒即可；托盘 worker 每轮轮询会自动恢复。
