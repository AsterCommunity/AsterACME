# 更新日志

[English](CHANGELOG.md)

## [Unreleased]

### 新增

- **单次续期**：新增 cert renew 到期检查与 --now 提前执行，复用稳定定义，持久化 predecessor/replaces、恢复未完成续期，完整产物提交后才切 in_use，失败保留旧版本。DNS旁路统一为 --skip-dns-check，不保留 --force/-f。对象锁外置，删除时清空无用户内容的账户/证书目录；输出由结果枚举驱动，查询证据按资源区分。workspace 各包独立设为0.1.0-alpha.1，尚不启动daemon。

- **证书密钥与吊销原因**：公共八选项枚举及 -k/--key-type，默认 ECDSA P-256，支持 P-384/P-521、Ed25519、RSA 2048/3072/4096/8192。持久化选择，恢复及续期准备校验实际算法，进度与证书视图展示类型。吊销原因使用 RFC 5280 具名代码，移除客户端 CA 政策白名单，保留 CA 拒绝细节；账户签名保持 ES256。明确 badCSR 持久化，其他申请完成共享 CA 订单后恢复仍保留原拒绝；本地失败标红并与 CA 订单状态分列；RFC8555 问题类型统一枚举并无损保留未知扩展，共享 CLI 行动建议、限流提示和标识符子问题展示。

- **续期计划与证书吊销**：签发后获取 RFC 9773 ARI，持久化窗口内均匀随机选时和 Retry-After 重查期限；失败保留有效计划，缺省按原证书有效期三分之二回退。新增账户签名 `cert revoke`，支持精确版本选择、可选原因、显式确认、持久化未确认/已确认状态及保留本地文件。周期唤醒和自动续期留给后续 daemon。

- **ACME 账户管理**：注册和找回具名账户、离线查看或显式查询 CA、更新联系人、可持久化对账的密钥轮换、停用 CA 账户及移除本地托管文件。支持公开 CA 预设、自定义 directory、明确条款同意、EAB、账户级 User-Agent 和不覆盖并发修改的默认账户选择。
- **手动 DNS 证书签发**：`cert issue` 完成订单、SAN/通配符授权、手动 TXT 待办、可选 DNS 可见性检查、固定证书密钥/CSR、finalize、下载和产物校验。按证书名称恢复，多申请时显式选择。`-y/--yes` 在恢复时跳过 TXT 发布确认，仍检查 DNS；`--skip-dns-check` 只跳过本地 DNS 检查。首次自动化申请先返回 TXT 指令。`cert list/show` 为只读入口，只有显式 `--verify` 才刷新 CA 观察。
- **可恢复的私有存储**：版本化 TOML、AsterFs 锁、有界读取、原子写入和固定密钥/CSR 绑定。可读时间版本目录保存完整链、叶子、CA 链和私钥 PEM，通过原子 `in_use` 链接选择版本。校验或写入失败不替换当前证书，保留无关用户文件。托管名称独立于主域名，自动随机后缀碰撞重试，显式已有名称拒绝；稳定定义拥有续期版本。list/show 默认 in_use，显式历史保留完整 SAN 且不参与活跃调度。cert remove 默认单次申请，批量范围为 history/revoked/all；保留无关版本及用户内容，清空 in_use 不回退历史，清理标记阻止复用中断残留。
- **CLI 交互与自动化**：共享存储/HTTP 参数组、明确短参数、缺省输入引导、默认否确认、简短申请选择、对齐彩色详情与表格、统一 UTC 时间、按账户/订单/授权区分的查询标记和独立吊销依据、类型化进度、JSON 输出及构建版本信息。[CLI 参数契约](docs/cli-contract.md) 定义确认、强制、条款及命令适用范围。
- **可嵌入的协议分层**：纯状态决策、类型化 ACME 资源/JWS/Problem、精确发现 URL、ES256/HS256、有界 nonce 重试、超时/取消处理，以及对象安全的 signer/store/readiness/observer 契约。未知 challenge 扩展会保留，不强加 DNS-01 专用 token 字段。验证实现按方法组织于 `aster_acme_validation`。

### 变更

- **依赖与 TLS 归属**：Forge HTTP 使用已发布的 `=0.1.0-alpha.2`，仅启用 JSON、rustls/AWS-LC 和系统代理；utils/macros 保持 `=0.1.0-alpha.1`，AsterFs 使用 `=0.1.0`，base64 使用 0.23.1。rustls 与共用 AWS-LC 后端减少重复 P-256 依赖，客户端显式选择 rustls，嵌入应用合并其他后端时也不会改变选择；CI 拒绝 native-tls/OpenSSL 传输依赖。各 crate 独立维护自身版本，依赖版本、来源和 features 仍集中在 workspace 定义。
- **Release 构建**：CLI 及其依赖使用 `opt-level="z"`、LTO、单 codegen unit 优化体积。保留 unwind panic 和函数符号，不携带源码级调试信息。panic hook 接入由 [#1](https://github.com/AsterCommunity/AsterACME/issues/1) 跟踪，等待上游能力。
- **文档**：新增中英文 README/更新日志、官网入口、crate 指南、RFC 索引、架构与 CLI 契约，并分开记录本地/staging 验证证据。自动 DNS 发布、HTTP/TLS solver、自动续期、daemon 调度和部署尚未实现。

[Unreleased]: https://github.com/AsterCommunity/AsterACME/commits/main/
