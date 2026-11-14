# 更新日志

[English](CHANGELOG.md)

## [Unreleased]

首次预发布。ACME 包尚未发布，Rust API 与本地格式仍可能直接变化，不提供旧格式兼容读取或自动迁移。

### 新增

- **外部 DNS Provider（ADPP）** — `provider add/list/show/update/remove`管理私有独立Profile，`-c dns_external --provider NAME`支持签发与续期，`provider cleanup NAME`重试终态清理。默认允许全部合法发布域，可用`--allow-zone`增强限制并用`--clear-zones`清除；变更前固定CNAME路由，CA ack前保存逐记录回执与限流下限；保留预存TXT、部分成功和未知结果。custom值全量敏感，仅经stdin传递并从报告隐藏；子进程不继承环境。部署reload与ADPP共用独立进程crate的进程树/有界IO机制。内置厂商客户端和真实DNS/staging验收另计。

- **DNS Persist（实验性）**：通过 `-c dns_persist` 支持 `draft-ietf-acme-dns-persist-02`，校验issuer元数据，以签名POST-as-GET证明账户控制权，派生绑定域名/账户密钥/账户URL的SHA-256哈希TXT，支持通配符范围与多字符串展示。首次人工发布，验证后长期保留；重启、续期、账户换钥及无人值守维护只复用确认过且未改变的记录，新值仍需人工发布。旧草案拼写仅保留不执行；DNS provider自动写入和公网CA验收仍独立。

- **账户管理**：具名 CA 账户的注册、按密钥找回、联系人更新、换钥、停用及本地删除。支持 Let's Encrypt、ZeroSSL、Google、自定义 directory、明确条款同意、EAB，以及账户／证书独立密钥选择。
- **证书签发**：单域名、SAN、通配符申请，支持人工 DNS-01、人工／webroot／standalone HTTP-01 与 standalone TLS-ALPN-01。持久化固定密钥、CSR、挑战材料和 CA 提交证据，恢复时不静默另建订单。
- **签发 journal 格式**：NewOrder意图字段改为 `new_order_intent_saved`，授权中的发布材料改为 `validation_requirement`，叶子证书到期时间从续期计划读取并移除重复字段。预发布格式继续使用journal version 1，不读取或迁移旧字段布局。
- **续期与吊销**：前台单次／批量续期、保存定义复用、ARI 窗口随机选时与 Retry-After，以及按有效期随机提前的回退计划（不足十天按一半，其余按三分之二）。查询失败保留计划，支持过期前任续期，过期后停止 ARI 查询；吊销显式选择`--sign-with account|certificate-key`，证书密钥模式无需原账户，账户模式无需证书私钥或CSR；过期证书仍可交由CA决定。发送边界保存精确DER指纹、CA、原因和实际签名身份，区分明确未发送与结果未知，保留本地文件。吊销使用独立session契约；公共签名API正名为`JwsSigner`和`SoftwareSigningKey`，无旧名转发兼容层。
- **周期证书维护**：`daemon run-once`执行一次周期；`daemon run`以前台常驻方式按可配置间隔（默认60秒）循环。每个data-dir使用独占跨进程租约，人类输出使用带时间戳的级别日志，JSON逐行输出事件；周期串行不重叠，Ctrl-C/SIGTERM协作退出并保留已启动工作的结果。两种模式均刷新到期ARI建议、续期符合准入条件的`webroot`、`standalone`、`tls_alpn`、`dns_external`及已配置`dns_persist`证书，并重试已配置部署。续期失败按1分钟、10分钟、100分钟、之后每天退避，遵守CA `Retry-After`且保留旧`in_use`证书；newOrder结果不确定时阻止自动新建订单。部署失败独立保存重试期限，到期后只重试已知发布／reload失败，不重新续期；执行租约内重新核验绑定快照、generation和期限，reload结果不确定时禁止自动重放。续期准备失败与操作期限耗尽纳入退避，用户取消和锁竞争不增加失败次数；旧快照不能覆盖新重试状态。管理员可通过`cert renew --now`或`--all --now`提前重试本地退避；人工验证明确跳过，cron仍可调用run-once。
- **部署**：每张证书可绑定多个标准 PEM 目录或独立产物路径，支持 Unix 文件／私钥权限、签发／续期后自动部署及离线 list/show/update/remove。全部选定文件暂存并同步后逐一替换，Unix 在打开的父目录句柄下完成发布与清理，全部发布成功才 reload。手动／自动取消均等待已启动发布，部署前校验证书与私钥身份；reload 结果未知时跨配置和版本保留状态且不重放，取消显式重试不解除该屏障；区分进程启动前中断，取消后仍保留部署报告。执行次数、期限、进程清理及 stdout/stderr 收集均有界；单目标失败继续其他目标，保留已签发证书。
- **命令行**：`cert remove NAME --failed`清理明确失败且不可恢复的未签发申请，保留已签发、可恢复和结果未知的记录。交互式输入、按命令限定参数、离线库存、缺钥时的账户元数据查看、显式 CA 核验、统一 UTC 进度与表格、JSON 报告、构建信息和安全 debug 阶段日志。独立配置请求超时、操作期限、轮询间隔与轮数上限，展示轮询计数及 Retry-After 来源。状态根依次由 `--data-dir`、`ASTER_ACME_DATA_DIR` 或平台默认目录确定。
- **CAA 预检**：issue/renew 在新订单前按 CA 广告身份、父域 CAA、通配符及账户／验证方式约束给出建议。不匹配、未知扩展、DNS 失败和超时不阻断 CA 验证。CAA／TXT／HTTP 以feature按需启用，由可嵌入Runner显式执行，共用默认5秒阶段预算与取消策略，结构化报告保留部分观察，并在CAA/TXT诊断中保留系统解析器初始化阶段和底层原因，区分CA身份缺失与本地初始化失败。不修改系统DNS或Hickory，不增加回退解析器。库默认关闭预检，CLI默认启用。
- **协议诊断**：类型化 ACME 资源与 IANA 全部 32 种错误类型，附 RFC／草案出处；保留未知扩展、标识符子问题、ARI explanationURL 精确映射、跨到期时刻窗口截断及拒绝／不确定证据，每周在线核对 IANA 注册表。
- **嵌入与文档**：对象安全的 signer/store/solver/observer 契约、按方法划分的具名材料模块、集中方法准入与发布策略、类型化长期验证快照，项目及 CLI 契约、任务路由、模块设计、RFC 索引，以及分开的本地／staging 验证记录。
- **仓库治理自动化**：采用组织共享、固定 SHA 的 `AsterCommunity/aster-automation` Action 与仓库自有的 `.github/aster-automation.json`：按变更文件确定性维护路径标签（`Rust`、`Python`、`Documentation`、`Dependencies`、`Scope: Core|Protocol|Client|Crypto|Challenges|Storage|CLI|Deployment`、`Risk: High`），维护关联 Issue 生命周期（`Priority:*`、`Status:*`、`Wait For PR`、`Merged`），聚合 `PR Gate` 与 CI 生命周期标签并原地更新诊断评论，为默认分支及定时任务失败维护带 fingerprint 的故障 Issue（含 flaky 与基础设施分类），每小时 reconcile 并同步标签定义，issue 模板预置新报告标签，维护 release readiness dashboard。自动化配置或 workflow 变更由 `Repository Automation` 校验配置 schema 与仓库静态契约。

### 变更

- **恢复与并发**：账户写入显式携带共享租约到阻塞任务结束，换钥 IO 串行，提交任务保留租约并完成取消后的结果分类，确认绑定已检查身份；Confirmed 换钥仅本地提交。账户换钥保留旧挑战材料，证书视图按持久化 catalog 恢复，拒绝过时提升。ARI、到期续期和部署重试由库级维护协调器按阶段运行；文件租约留在 storage，reload 执行留在宿主。CA 发现与自动部署共用取消／期限，批次保留已提交结果。
- **发布与清理**：部署直接使用普通文件和稳定目录路径，不使用链接、目录交换或承诺整组原子事务。Webroot 固定目录身份，Windows 使用参与重命名共享检查的目录访问权，新目录权限同步后发布；shutdown 回收阻塞 worker；HTTP 建议性预检复用连接池，遵循用户代理并允许内网目标，DNS/HTTP共用专用预检时限，固定最多5秒，并接受HTTP-01响应末尾ASCII空白。Webroot 核验实际隔离的对象后再清理，保留用户替换文件。人工验证确认恢复原生inquire，支持可见输入/编辑与默认否；提示线程结束后复核取消／期限，由库恢复终端模式；诊断写入或 flush 失败不会报告成功。
- **存储与跨平台**：版本化 TOML、有界类型化查询、标准库锁及平台文件校验。Unix 使用私有权限和内部 in_use 相对链接；Windows 使用继承权限及可恢复完整目录副本。Unix 新建目录项在远端操作前同步，metadata 保存不能重建已删除账户。Windows 进程重启恢复不等同掉电后 rename 目录项持久性；无关用户文件保留。
- **运行时与依赖**：复用惰性 HTTP 连接池，隔离账户策略与 nonce；依赖版本／features 归根 workspace，限定 rustls/AWS-LC。优化 release 体积，仅可执行入口安装 Forge panic hook，私有报告脱敏且不重放 mutation。
- **构建与 CI**：覆盖 Linux、macOS、Windows，检查导入归属、依赖 features、本地文档链接及独立预检feature组合，并验证库关闭预检时不引入DNS解析器；CLI的external DNS使用独立resolver。源码、清单和 Cargo 输出显式按 UTF-8 解码，不依赖 Windows 默认编码。构建信息不借用无关父仓库 revision，也不监视不存在的压缩分支引用；dirty 只包含已跟踪变更。Linux CI 追加覆盖率任务，收集 `cargo-llvm-cov` 的 LCOV 输出，发布运行摘要并上传 Codecov。

交叉编译及本地 mock 不代表原生平台或公网 CA 验收。

[Unreleased]: https://github.com/AsterCommunity/AsterACME/commits/main/
