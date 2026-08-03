# ChatGPT Desktop Installer V4 Manager

> 独立的第三方安装与恢复管理器。它不隶属于 OpenAI，也不修改或冒充 OpenAI 官方 ChatGPT Desktop 应用。

本仓库是 V4 的正式 Manager Fork。基础平台代码来自 `Wangnov/Codex-App-Manager` 的冻结提交 `3036e05dba76294b02707b2a5b5f8825f6c24570`，并依照 MIT License 保留上游版权。V4 只复用经审计的 Windows/macOS 安装、更新、校验、事务恢复和回滚能力；上游不是运行时依赖。

## 产品边界

V4 Manager 负责：

- 发现并验证官方 ChatGPT Desktop 安装包；
- Windows MSIX/portable 与 macOS DMG/ZIP 生命周期；
- 下载进度、停滞检测、超时、取消、重试、断点续传和缓存；
- 安装事务、失败回滚、崩溃恢复和重启续装；
- 商业领取、设备绑定、配置/语言事务和真实 API/CLI 验收；
- 将父进程、子 Worker、事务和系统产物登记到统一诊断 bundle；
- 安全更新 V4 Manager 自身。

V4 Manager 不负责：

- Codex/ChatGPT UI 皮肤、主题市场或 CDP/WebView 注入；
- 绕过 Windows 签名策略、Gatekeeper、OpenAI 身份或地区限制；
- 扫描聊天软件缓存或上传用户对话正文；
- 在运行时跟随任何第三方仓库的 HEAD、tag 或服务。

## 固定工具链

- Node.js `24.16.0`
- npm `11.13.0`
- Rust `1.97.1`
- Tauri CLI `2.11.4`
- Windows：Visual Studio 2022 Build Tools / MSVC v143

精确来源和校验信息见 `../infra/TOOLCHAIN_LOCK.json`。CI Actions 均固定为完整 commit SHA。

## 本地门禁

```powershell
npm ci --ignore-scripts
npm run lint
npm test
npm run build
cargo check --manifest-path src-tauri/Cargo.toml --all-targets
```

正式验证必须使用 `../.toolchains` 中的锁定版本，而不是碰巧位于系统 PATH 的工具。Rust 编译需在 MSVC developer environment 中运行。

## 发布门禁

本仓库不能单独发布。V4 总门禁要求：

- `147 assigned / 147 implemented / 147 evidenced / 0 waived`；
- Windows x64/ARM64 与 macOS Intel/Apple Silicon 真机；
- Windows Authenticode 与 macOS Developer ID/notary/staple；
- V4 signed manifest、官方 payload 身份、SBOM 和 provenance；
- 商业领取、配置、语言、Responses/SSE/WebSocket、CLI 和 usage 的隔离 E2E；
- 完整诊断 bundle 与 V2 回滚演练。

详见 `../infra/governance/` 与项目 Master Plan。

## Upstream updates

`upstream` remote 只允许 fetch，push URL 被禁用。任何更新必须从手工 `workflow_dispatch` 的 `upstream-audit` 开始，经完整差异、安全边界、依赖、许可证和网络来源审查后选择性进入 V4；禁止自动 merge。

## License

本 Fork 依据仓库中的 [MIT License](LICENSE) 使用和分发。上游及传递依赖 notices 必须随源代码和发布文档保留。

---

## English summary

This repository is the owned, audited V4 Manager fork for installing and recovering the official ChatGPT Desktop payload. It is independent software and is not affiliated with OpenAI. The fork retains the useful cross-platform lifecycle engines while removing the Codex skin marketplace, CDP/WebView injection and unrelated marketing/motion surfaces. Production release is blocked until the 147-capability, supply-chain, signing, real-device, business-E2E, diagnostics and rollback gates pass.
