# V4 G3 验收证据

结论：`PASS`。

- 冻结提交：`4ea91c2001ab2c4c5c42af2e2b61a99a1cf41453`
- 云端工作流：5/5 成功；作业：17/17 成功，0 失败
- 业务交付：领取幂等/并发、配置事务、旧 V2 迁移、语言隔离、真实协议 verifier 在 Windows x64/ARM64、macOS Intel/Apple Silicon 原生目标全部通过
- 配置安全：Windows owner-only DACL 读回；macOS `0600/0700` 原生权限测试；任何故障点恢复旧 bytes、hash 与 vault 状态
- 本地回归：delivery engine 49、Tauri adapter 5、Portal 107，全部通过；delivery clippy 0 warnings
- 供应合同：完整模型目录、Portal claim SQL/fixture、语言 Worker 均绑定规范化 SHA-256
- 生产状态：未改变 V2 下载入口、manifest、对象或客户流量

完整 run、job、artifact ID、SHA-256 digest 和合同 hash 见 `g3-acceptance-2026-08-04.json`。G3 不替代 G6 的真实发布签名、公证、Gatekeeper 与四设备候选验收。
