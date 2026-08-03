# V4 G2 验收证据

结论：`PASS`。

- 冻结提交：`ee7067785b5be8640a9f017b680a2e49ddcf08e4`
- 云端检查：12/12 成功，0 失败
- 四架构：Windows x64、Windows ARM64、macOS Intel、macOS Apple Silicon 全部成功
- 打包烟测：Windows NSIS、macOS Intel/Apple 全部成功
- 本地回归：Windows engine 100、macOS engine 20、Manager 126、前端 282，全部通过
- 依赖门：npm audit 0 漏洞；三套 Rust clippy `-D warnings` 通过
- 生产状态：未改变 V2 下载入口、manifest、对象或客户流量

完整 run、job、artifact ID 与 SHA-256 digest 见 `g2-acceptance-2026-08-04.json`。此门只证明 P2 平台安装内核和 unsigned CI/packaged smoke；真实签名、公证、Gatekeeper 与四台真机仍由 G6 阻塞，未用模拟结果冒充。
