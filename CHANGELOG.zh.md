# 更新日志

[English](CHANGELOG.md)

## [Unreleased]

### 新增

- **验证失败诊断**：展示CA订单/challenge problem及域名子问题，invalid订单保留检查并拒绝恢复，不再给resume建议。Webroot INFO记录实际发布/复用/保留/删除路径，DEBUG解释服务器URL到本地文件的映射。确认invalid后共用终态清理机制删除本次拥有且未变的文件；清理失败保留待办和原CA problem，取消及不确定结果保留验证材料。

- **可配置轮询间隔**：本地CA轮询默认5秒，config poll_interval与--poll-interval可覆盖，有效CA Retry-After仍优先。

- **HTTP跳转预检与等待来源**：HTTP-01建议性预检支持有界HTTP/HTTPS跳转，ACME签名请求仍禁跳转；每次轮询等待展示来源，安全debug增加解析后的Retry-After。

- **明确执行限制默认值**：config.toml支持request_timeout/operation_timeout/max_polls，CLI使用--request-timeout/--operation-timeout/--max-polls独立覆盖；移除含糊的timeout/wait-timeout旧名称，无别名或迁移。

- **有界CA轮询**：新增--max-polls与逐轮计数，持久化Retry-After/本地间隔来源，达到上限保留记录供恢复；跳过仍有效的授权刷新。HTTP发布复用共享池做限时建议性内容检查。

- **方法驱动HTTP验证**：同一ACME协议流程注入CLI的manual_dns/manual_http/webroot实现，方法/配置/材料在恢复和续期中保持不变。Webroot以文件身份持久化所有权、发布精确HTTP-01内容，保留已有/修改文件，清理失败不抹掉已签发结果。完整定义匹配未完成申请，终端选择恢复，--if-similar-order供脚本唯一匹配恢复；创建结果未确认也给提示但不重发newOrder。DNS预检变为限时建议性检查并移除skip/force参数；日志显示托管名称、实现和协议，新增--debug安全检查点/请求元数据诊断，本地确定的恢复失败在CA发现前报告。未发布存储/JSON格式直接更新，无兼容读取。

- **账户密钥算法**：账户与证书共用八种密钥选择及生成，account register/rotate-key 新增 -k/--key-type；类型化 ES256/ES384/ES512/EdDSA/RS256、EC/RSA/OKP 规范 JWK，以及账户类型元数据和展示。新账户默认 P256，跨算法轮换恢复仍保留暂存钥，显式冲突拒绝。未发布账户格式新增必需 key_algorithm，不保留旧读取。标准帮助入口统一格式，不重解释位置参数。

- **单次与批量续期**：新增 cert renew --all 顺序批量、逐项结果与一次结构化汇总及去除重复计划/逐项检查日志的人类输出、部分失败/取消退出状态、人工TXT待办不阻塞后续项；到期检查与 --now 提前执行，复用稳定定义，持久化 predecessor/replaces、恢复未完成续期，完整产物提交后才切 in_use，失败保留旧版本。DNS 采用有界建议性预检，不提供DNS跳过/force参数。对象锁外置，删除时清空无用户内容的账户/证书目录；输出由结果枚举驱动，查询证据按资源区分。workspace 各包独立设为0.1.0-alpha.1，尚不启动daemon。

- **证书密钥与吊销原因**：公共八选项枚举及 -k/--key-type，默认 ECDSA P-256，支持 P-384/P-521、Ed25519、RSA 2048/3072/4096/8192。持久化选择，恢复及续期准备校验实际算法，进度与证书视图展示类型。吊销原因使用 RFC 5280 具名代码，移除客户端 CA 政策白名单，保留 CA 拒绝细节。明确 badCSR 持久化，其他申请完成共享 CA 订单后恢复仍保留原拒绝；本地失败标红并与 CA 订单状态分列；RFC8555 问题类型统一枚举并无损保留未知扩展，共享 CLI 行动建议、限流提示和标识符子问题展示。

- **续期计划与证书吊销**：签发后获取 RFC 9773 ARI，持久化窗口内均匀随机选时和 Retry-After 重查期限；失败保留有效计划，缺省按原证书有效期三分之二回退。新增账户签名 `cert revoke`，支持精确版本选择、可选原因、显式确认、持久化未确认/已确认状态及保留本地文件。周期唤醒和自动续期留给后续 daemon。

- **ACME 账户管理**：注册和找回具名账户、离线查看或显式查询 CA、更新联系人、可持久化对账的密钥轮换、停用 CA 账户及移除本地托管文件。支持公开 CA 预设、自定义 directory、明确条款同意、EAB、账户级 User-Agent 和不覆盖并发修改的默认账户选择。
- **手动 DNS 证书签发**：`cert issue` 完成订单、SAN/通配符授权、手动 TXT 待办、可选 DNS 可见性检查、固定证书密钥/CSR、finalize、下载和产物校验。按证书名称恢复，多申请时显式选择。`-y/--yes` 在恢复时跳过 TXT 发布确认，仍检查 DNS；本地 DNS 预检最多2秒，错误/未就绪只警告后继续 CA 验证。首次自动化申请先返回 TXT 指令。`cert list/show` 为只读入口，只有显式 `--verify` 才刷新 CA 观察。
- **可恢复的私有存储**：版本化 TOML、标准库文件锁、有界读取、原子写入和固定密钥/CSR 绑定。可读时间版本目录保存完整链、叶子、CA 链和私钥 PEM，通过原子 `in_use` 链接选择版本。校验或写入失败不替换当前证书，保留无关用户文件。托管名称独立于主域名，自动随机后缀碰撞重试，显式已有名称拒绝；稳定定义拥有续期版本。list/show 默认 in_use，显式历史保留完整 SAN 且不参与活跃调度。cert remove 默认单次申请，批量范围为 history/revoked/all；保留无关版本及用户内容，清空 in_use 不回退历史，清理标记阻止复用中断残留。
- **CLI 交互与自动化**：共享存储/HTTP 参数组、明确短参数、新申请显式指定验证方式及通用--yes操作确认、缺省输入引导（含无名称的 cert issue --resume 选择未完成申请）、有界建议性DNS预检及异常警告、默认否确认、简短申请选择、对齐彩色详情与表格、统一 UTC 时间、按账户/订单/授权区分的查询标记和独立吊销依据、类型化进度、JSON 输出及构建版本信息。[CLI 参数契约](docs/cli-contract.md) 定义确认、强制、条款及命令适用范围。
- **可嵌入的协议分层**：纯状态决策、类型化 ACME 资源/JWS/Problem、精确发现 URL、ES256/HS256、有界 nonce 重试、超时/取消处理，以及对象安全的 signer/store/readiness/observer 契约。未知 challenge 扩展会保留，不强加 DNS-01 专用 token 字段。验证实现按方法组织于 `aster_acme_validation`。

### 变更

- **标准库锁与平台存储**：使用 Rust 标准库文件锁并移除仅用于锁的 AsterFs 依赖，文件策略集中到平台适配层；Windows 沿用继承权限、不要求 ACL 管理，in_use 保存完整 PEM 副本并支持 staging/previous 目录恢复。保留 Unix 链接与权限检查，使用可移植托管名称并增加原生 OS CI 目标。缺失底层机制关联 AsterFs #3/#4；目录切换可恢复，不宣称原子交换。

- **命令输出与 HTTP 生命周期**：账户、证书、version 共用命令级输出会话，集中进度、交互和最终结果，分别控制输出流配色，按实际输出添加分隔，部分失败也仅输出一份 JSON 报告。ACME 客户端在批量操作中持有同一惰性 HTTP 连接池，账户 User-Agent、请求期限及 nonce 独立。
- **依赖与 TLS 归属**：Forge HTTP 使用已发布的 `=0.1.0-alpha.2`，仅启用 JSON、rustls/AWS-LC 和系统代理；utils/macros 保持 `=0.1.0-alpha.1`，文件锁使用 Rust 标准库且移除 AsterFs 依赖，base64 使用 0.23.1。rustls 与共用 AWS-LC 后端减少重复 P-256 依赖，客户端显式选择 rustls，嵌入应用合并其他后端时也不会改变选择；CI 拒绝 native-tls/OpenSSL 传输依赖。各 crate 独立维护自身版本，依赖版本、来源和 features 仍集中在 workspace 定义。 CI 按 Cargo 合并后的生产依赖 feature 白名单检查，禁止额外 TLS/密码后端及未用 HTTP/UI/日志功能；交互只启用 crossterm/fuzzy，日志只启用 fmt/ANSI/env-filter。
- **Release 构建**：CLI 及其依赖使用 `opt-level="z"`、LTO、单 codegen unit 优化体积。保留 unwind panic 和函数符号，不携带源码级调试信息。可执行入口在 Tokio 启动前安装已发布 Forge panic `=0.1.0-alpha.2`；私有报告位于 `<data-dir>/crash.log`，移除 panic payload，屏幕人类/JSON 错误不含 payload 或回溯。库不安装 hook，报告拒绝不安全文件，使用非阻塞锁及 1 MiB 上限；失败保留密钥/checkpoint，不触发操作重试。
- **文档**：新增中英文 README/更新日志、官网入口、crate 指南、RFC 索引、架构与 CLI 契约，并分开记录本地/staging 验证证据。自动 DNS 发布、HTTP standalone/TLS solver、自动续期、daemon 调度和部署尚未实现。

[Unreleased]: https://github.com/AsterCommunity/AsterACME/commits/main/
