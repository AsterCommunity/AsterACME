# 更新日志

[English](CHANGELOG.md)

## [Unreleased]

### 新增

- **候选证书链（#13）** — 从证书下载响应的 `Link; rel="alternate"` 发现并验证同叶子备用链。`cert issue --chain CHAIN` 仅选择本次链，`--preferred-chain CHAIN` 选择并保存后续软偏好，`--default-chain` 跟随 CA 当次默认且不改变已保存偏好。交互把本次选链与默认否的软偏好确认分开。未来软偏好链不可用时告警并回退 CA 默认；一次性链不可用时保留已签发 operation 供恢复，不重新下单。每个世代记录实际发布链身份，alternate URL 不落盘。

- **PKCS#12 部署（#55）** — `cert deploy add/update --p12-path` 发布证书链与私钥 bundle，沿用密钥权限与完整准备后发布管线。绑定只存互斥的 env/密码文件引用；daemon 推荐 0600 密码文件，只有交互式显式 run 可使用不落盘的密码。无来源的自动执行失败、不自动重试，JSON 不包含密码值，目录仍保持 PEM 四件套。

- **库嵌入签发适配器（#48）** — `aster_acme` 示例使用库内自带的账户与签发适配器，并增加针对内存存储边界的测试。
- **注册后修改未来条款授权** — `account update --auto-accept-new-terms` 接受 CA 当前条款并持久化自动接受未来条款 URL 更新；`--clear-auto-accept-new-terms` 在本地撤销授权并保留已接受 URL。开启前读取在线 directory，无法确认当前条款时失败关闭（CA 未公布条款时仍保存授权并在报告中明确说明）；撤销不发送任何请求。两者都不向 CA 发送账户更新，`--yes`/JSON 不会隐含同意。`account show` 继续展示授权状态与精确已接受 URL。

### 变更

- **`account update` 组合 scope 报告（#58）** — `account update` 逐 scope 报告结果：CA 已提交的联系人证据与 profile、条款变更保留在同一次结果里，本地保存失败时错误列明已生效的 scope；联系人失败区分未提交、明确拒绝、远端结果未知，以及 CA 已接受但本地保存未确认（嵌入者使用 `ContactUpdateError`）。条款授权可与联系人/profile 同次组合；全部 directory 校验（profile 广告、当前条款值）仍先于第一个 mutation，CA 不一致时整个调用零副作用。update 的 JSON 输出形状随之调整：单个 `{name, contacts, profile, terms}` 对象按已应用 scope 分段，替代原先的扁平单 scope 对象。`--auto-accept-new-terms` 与 `--clear-auto-accept-new-terms` 彼此仍互斥，只有显式条款 flag 与 `--yes` 同时给出才跳过独立条款确认。交互组合调用逐 scope 确认，文本 `account show` 显示已保存默认 profile 或未设置状态；badNonce 拒绝后重签准备失败保留拒绝与失败原因。组合撤销仍保留原已接受 URL，清除 profile 与撤销授权可纯离线完成；profile 菜单复用预检广告，并发条款同意冲突时停止覆盖，持久化失败明确报告保存结果未确认；拒绝或取消确认退出 130，并保留此前已生效 scope 的说明。

- **AsterForge 依赖** — 升级共享的 HTTP、进程、panic hook 和工具库。panic hook 的默认时间戳改用 `time`，AsterACME 的依赖树移除了 `chrono`。macOS 并发创建锁文件遇到瞬态 `ENOENT` 时，改由 `aster_forge_utils` 重试一次。

## [0.1.0-alpha.3] - 2026-11-20

### 破坏性

- **默认 data-dir 统一为反向域名路径** — 修复 Linux 默认目录回落为 `~/.config/acme` 的缺陷：三平台统一使用 `com.astercosm.acme`（macOS `~/Library/Application Support/com.astercosm.acme`，Linux `~/.config/com.astercosm.acme`，Windows `%APPDATA%\com.astercosm.acme\config`）。不做自动迁移；Linux 默认路径从 `~/.config/acme` 变为 `~/.config/com.astercosm.acme`，迁移步骤（含目标已存在、`XDG_CONFIG_HOME` 与非空目录的处理）见[数据目录文档](docs/src/content/docs/admin/data-dir.mdx)。macOS 路径不变。


### 新增

- **双语文档站点** — 发布中英文双语 Starlight 文档站点 [acme.docs.astercosm.com](https://acme.docs.astercosm.com/)，覆盖安装、快速开始、账户、challenge 方法、签发与续期、部署、DNS provider、守护进程和 CLI 参考，由 CI 链接检查并自动部署；开发者契约文档迁移至 `developer-docs/`。新增 `CODE_OF_CONDUCT.md`、`CONTRIBUTING.md` 与 `SECURITY.md`。

- **容器镜像 shim 与构建元数据** — Release 镜像以 tag commit 作为 CLI 构建修订号，六个顶层子命令（`account`、`cert`、`daemon`、`provider`、`version`、`help`）可在 `docker exec` 下直接执行，不再需要 entrypoint 前缀。附带挂载 `data/` 与 `ssl/` 卷的 compose 示例，Dockerfile、entrypoint 和 compose 文件迁移至 `docker/`。

- **RFC 8738 IP 标识符证书** — 以 HTTP-01 和 TLS-ALPN-01 为 IPv4/IPv6 地址签发证书：类型化 `Identifier` 贯穿订单、授权、CSR（DNS/IP 混合 SAN）、返回证书校验、恢复、续期与吊销。`-d/--domain` 仅收 DNS 名，新增可重复的 `--ip ADDRESS` 收 IP 字面量（首个 `-d`，否则首个 `--ip` 为主标识符；交互提示同时接受两种）。DNS-01/DNS-PERSIST-01 在任何副作用之前拒绝 IP 标识符且零 ack。TLS-ALPN-01 按 RFC 8738 反向名 SNI 路由 iPAddress SAN 证书；HTTP-01 材料使用 IPv6 括号 Host 形式并跳过 DNS 解析；CAA 预检将 IP 标识符报告为不适用（RFC 8659 只覆盖 DNS 名）。IP 主标识符的默认证书名加 `ip-` 前缀（冒号替换为连字符，如 `ip-2001-db8--1`）。签发报告与 JSON 改用 "Identifiers"。真实 CA 的 IP 签发验收与 loopback 证据分开记录。

- **ACME 证书 profile（draft-ietf-acme-profiles）** — 从 directory metadata 发现 CA 广告的 profiles，`cert issue --profile` 按单选择（newOrder 前按广告校验；未广告名称直接失败并列出可用项，零副作用），选择作为证书身份的一部分在恢复/续期中固定——元数据漂移不会隐式替换。账户支持默认 profile：`account register --profile`、`account update --profile/--clear-profile`（对照在线 directory 建议性校验）以及 `account show --profiles`；`cert issue --profile` 优先于账户默认，已保存证书不隐式迁移。订单对象回显 CA 选择，与请求不一致按身份变化拒绝。终端上的交互式 `cert issue` 列出广告 profiles 并预选账户默认（Esc 取消）。规范：draft-ietf-acme-profiles（https://datatracker.ietf.org/doc/html/draft-ietf-acme-profiles）。
- **华为云 DNS** — CLI 默认构建包含该后端，嵌入式宿主使用 `huawei_cloud` 显式启用。`project_id` 可省略并按所选 region 通过 IAM 自动发现；`region` 可省略，默认 `cn-north-4`。公网 zone 发现、HWS 签名和持久 RRset 恢复采用尽力所有权：读取与 PUT/DELETE 之间的外部并发修改可能被覆盖或误删，不保证原子隔离（#41）。

- **阿里云云解析 DNS 与腾讯云 DNSPod** — CLI 默认包含这两个后端，精简构建可分别选择 `dns-aliyun` 和 `dns-tencent-cloud`。四家内置 provider 共用备注契约但允许 provider 覆盖格式；默认使用 `asteracme-<publication_id>`，阿里云因 50 字符上限使用 `acme-<publication_id>`。阿里云在创建成功后通过 `UpdateDomainRecordRemark` 写入，并在备注失败时只重试备注阶段，不重复创建 TXT。两者发现并保存最终发布目标的 zone，在回执中记录实际 TXT TTL，并在清理前核验记录。DNSPod 用发布备注对账丢失的创建响应。阿里云显式请求域名详细属性以发现最小 TTL，识别文档定义的记录状态，须保存创建响应中的 `RecordId`，并拒绝借用已有同值记录。（#40、#39）

- **库嵌入签发示例** — `cargo run -p aster_acme --example embedded_issuance` 走完完整嵌入路径：CA 发现、经 `AccountService` 注册或复用账户、嵌入方实现的 HTTP-01 webroot `ChallengeSolver`、按 `IssueStore` 契约恢复已保存请求，以及产物提升。示例默认指向 Let's Encrypt staging 并使用临时 data-dir，随 workspace CI 编译；双语 README 快速开始将其作为 library-first 入口链接（#33）。
- **DNS 发布 TTL** — 通过 `provider add/update --ttl-seconds` 配置 TXT 请求 TTL（默认 120，RFC 2181 范围 0–2147483647），恢复和 Profile 修改不改变已有发布计划中的 TTL。厂商限制仍归各 backend，本地传播观察保留现有建议性行为。
- **自动接受 CA 条款更新** — `account register --auto-accept-new-terms` 同意当前 directory 条款，并持久化授权未来条款 URL 更新，供无人值守账户 ensure 和续期使用。`account show` 展示精确已接受 URL 及授权状态；`--yes`、JSON 模式和隐式 ensure 不会开启授权。

### 变更

- **账户子命令重构（8 个）** — `switch`→`default`，`update-contact` 与 `set-profile` 合并为 `update`（联系人 + 默认 profile 一处），`profiles` 并入 `show --profiles`，`deactivate` 并入 `remove --deactivate`（先 CA 停用、后本地删除）。终端上无参数的 `account update` 打开 scope 菜单，用方向键在 CA 广告 profiles 中选择。

- **ACME wire 与检查契约** — 账户、标识符、订单、授权、directory metadata 和 ARI 资源保留未知扩展成员，同时保留 `keyChange`、`newOrder`、`revokeCert` 等 directory 能力 URL 的可选语义。日志使用 JSON 快照保留订单与授权扩展中的 null 值。`IssueService::inspect` 改为接收调用方的取消/截止时间上下文，签发结果区分调用方取消与操作预算耗尽，包括 provider 和宿主进程超时。

- **DNS Provider 错误诊断** — 内置后端失败时尽可能显示 API action、HTTP 状态、通过校验的厂商错误码及安全 request ID；原始响应正文和厂商 message 仍不输出，外部后端的安全 provider code 也由同一 CLI 路径展示。

- **DNS 读回对账** — 内置 provider 共用有界只读重试预算，保留厂商各自的可见性及所有权检查；不重放不确定创建，不把响应格式错误或身份冲突视为可见性延迟。

- **DNS HTTP 动作** — `HttpRequest.method` 改用公共 `HttpMethod` 枚举，可选操作名由 provider 提供给宿主诊断。内置厂商模块移至 `provider::vendors`，共享实现置于内部 `provider::common`。供应商 Cargo feature 自动启用所需共享实现能力，HTTP 动词枚举成员不再依赖供应商开关。

- **部署核验** — reload 前对整组发布文件核验暂存内容、身份和适用权限；失败报告已完成替换的路径，继续保留部分文件集和整组重试契约，不承诺整组原子性或自动回滚。已有目的路径无法规范化、不能证明所有权无冲突时，拒绝配置及部署；恢复访问或移除失效绑定后再重试。
- **可选验证依赖** — `aster_acme_validation` 空 feature 不再引入生产 Tokio 依赖，独立检查并测试可选 feature 组合。

- **签发与发布核验** — 增加 loopback HTTP 的 finalize、证书下载和 storage completion 闭环测试，并直接覆盖发布回执身份、重复 ID、控制字符和批次原子性边界。

### 修复

- **已保存请求选择** — issue 恢复、show、remove 和 revoke 接受以 `-` 开头的合法 operation ID，不再误作命令行选项。
- **ACME mutation 恢复** — 408/429 保留吊销 Pending、challenge/finalize Submitted 证据，不作为明确拒绝；保留 ack/finalize 等待下限、已有不确定吊销状态和显式重试边界。
- **维护诊断** — 单证书 refresh 失败后持久状态读回也失败时，同时保留两个错误，将最新调度时间标为不可用，并继续处理其余证书。
- **Release 符号归档** — Windows 符号归档保留链接器输出的 crate 词干 PDB 名（`aster_acme.pdb`），使调试器与可执行文件中记录的 basename 匹配；macOS 归档改用 `lldb` 反推 v0 mangled 回溯，替代无法解析 Rust 符号的 `atos`。

## [0.1.0-alpha.2] - 2026-11-18

### 新增

- **发布流水线** — 版本 tag 自动发布：带变更日志摘录的 draft GitHub release，linux amd64+arm64（musl 静态）、macos amd64+arm64 与 windows amd64+arm64 的 `aster-acme` 二进制，各自附按版本归档的符号文件（macOS `dwarfdump` UUID 配对、Linux GNU build-id 调试文件、Windows PDB sidecar），支持离线 backtrace 反推（#9）；GHCR 与 Docker Hub 的 Alpine 多架构签名镜像，`latest` 仅跟随正式版 tag；每个 release 同步更新 Homebrew tap formula。附带 cargo-binstall 元数据按 target 映射 release 资产。

- **内置 DNS 后端** — 通过同一校验注册表发现后端配置与工厂。新增按厂商 feature 选择的 Cloudflare（嵌入式 `cloudflare`，CLI `dns-cloudflare`），可选固定 zone 或按 CNAME 最终目标自动发现并持久化 zone 身份、publication comment 对账、私有 token 文件与精确所有权清理。Provider 产生版本化 HTTP/checkpoint 动作，由宿主通过有界 Forge 传输和持久化 publication/RRset 租约执行。提供条件 RRset 状态机，保留无关值与字段，只对明确版本冲突重新合并，不确定所有权时保留记录；真实 DNS/公网 CA 验收另计。

### 变更

- **DNS 配置** — 内置与 ADPP 共用 `dns_provider`，新增 `provider backends` 和私有 `--settings-file` 输入，Profile 列表展示后端 ID，交互验证菜单优先列出 `dns_provider`，并支持按申请域名显式指定 DNS 发布目标。Profile 要求 `backend_id` 与 `backend_config_version`，证书定义固定后端/配置版本及非秘密远端 binding。旧 `dns_external` 定义与旧 Profile 布局保留但不自动读取或迁移；ADPP v1 请求仅传最终记录名，不再传 CNAME 路由字段；外部 provider 需适配此预发布协议变更。

- **CI 触发范围** — 仅在 `main` 的 push 和目标为 `main` 的 PR 上运行检查，同一 PR 或分支的新运行取消旧运行，避免功能分支重复执行 push/PR 两套检查。

- **Forge 进程执行** — 使用已发布的 `aster_forge_process = 0.1.0-alpha.3` 替换退役的 `aster_acme_process`，承载有界子进程生命周期机制；ADPP 与部署仍各自拥有协议和副作用策略。进程树清理未完成时覆盖直接 child 的成功结果，保留副作用不确定状态并禁止自动重放。

## [0.1.0-alpha.1] - 2026-11-16

首次预发布。Rust API 与本地格式仍可能直接变化，不提供旧格式兼容读取或自动迁移。

### 新增

- **Cloudflare ADPP 示例 Provider** — 新增`examples/dns-providers/cloudflare_adpp.py`：仅用标准库的 Python 3.9 外部 provider，实现 ADPP v1 `present`/`cleanup` 对接 Cloudflare。按最长后缀发现 zone（可用`zone_id`固定）；record `comment`记录`publication_id`实现幂等重发布；同值预存记录标为`preexisting`且永不删除；清理按 record ID 与精确值核对后才删除，不一致时失败关闭保留记录；错误映射`authentication_failed`/`authorization_denied`/`rate_limited`/`provider_unavailable`。凭据经`provider_custom`传入（`api_token`或`token_file`，可选`zone_id`与仅测试用的`api_base`）；本地 mock 测试不联网，已接入 CI。

- **外部 DNS Provider（ADPP）** — `provider add/list/show/update/remove`管理私有独立Profile，`-c dns_external --provider NAME`支持签发与续期，`provider cleanup NAME`重试终态清理。默认允许全部合法发布域，可用`--allow-zone`增强限制并用`--clear-zones`清除；变更前固定CNAME路由，CA ack前保存逐记录回执与限流下限；保留预存TXT、部分成功和未知结果。custom值全量敏感，仅经stdin传递并从报告隐藏；子进程不继承环境。部署reload与ADPP共用独立进程crate的进程树/有界IO机制。内置厂商客户端和真实DNS/staging验收另计。

- **DNS Persist（实验性）**：通过 `-c dns_persist` 支持 `draft-ietf-acme-dns-persist-02`，校验issuer元数据，按无序集合比较`issuerDomainNames`，以签名POST-as-GET证明账户控制权，派生绑定域名/账户密钥/账户URL的SHA-256哈希TXT，支持通配符范围与多字符串展示。首次人工发布，验证后长期保留；重启、续期、账户换钥及无人值守维护只复用确认过且未改变的记录，新值仍需人工发布。旧草案拼写仅保留不执行；DNS provider自动写入和公网CA验收仍独立。

- **账户管理**：具名 CA 账户的注册、按密钥找回、联系人更新、换钥、停用及本地删除。支持 Let's Encrypt、ZeroSSL、Google、自定义 directory、明确条款同意、EAB，以及账户／证书独立密钥选择。
- **证书签发**：单域名、SAN、通配符申请，支持人工 DNS-01、人工／webroot／standalone HTTP-01 与 standalone TLS-ALPN-01。持久化固定密钥、CSR、挑战材料和 CA 提交证据，恢复时不静默另建订单。
- **签发 journal 格式**：NewOrder意图字段改为 `new_order_intent_saved`，授权中的发布材料改为 `validation_requirement`，叶子证书到期时间从续期计划读取并移除重复字段。预发布格式继续使用journal version 1，不读取或迁移旧字段布局。
- **续期与吊销**：前台单次／批量续期、保存定义复用、ARI 窗口随机选时与 Retry-After，以及按有效期随机提前的回退计划（不足十天按一半，其余按三分之二）。查询失败保留计划，支持过期前任续期，过期后停止 ARI 查询；吊销显式选择`--sign-with account|certificate-key`，证书密钥模式无需原账户，账户模式无需证书私钥或CSR；过期证书仍可交由CA决定。发送边界保存精确DER指纹、CA、原因和实际签名身份，区分明确未发送与结果未知，保留本地文件。吊销使用独立session契约；公共签名API正名为`JwsSigner`和`SoftwareSigningKey`，无旧名转发兼容层。
- **周期证书维护**：`daemon run-once`执行一次周期；`daemon run`以前台常驻方式按可配置间隔（默认60秒）循环。每个data-dir使用独占跨进程租约，人类输出使用带时间戳的级别日志，JSON逐行输出事件；周期串行不重叠，Ctrl-C/SIGTERM协作退出并保留已启动工作的结果。两种模式均刷新到期ARI建议、续期符合准入条件的`webroot`、`standalone`、`tls_alpn`、`dns_external`及已配置`dns_persist`证书，并重试已配置部署。续期失败按1分钟、10分钟、100分钟、之后每天退避，遵守CA `Retry-After`且保留旧`in_use`证书；newOrder结果不确定时阻止自动新建订单。部署失败独立保存重试期限，到期后只重试已知发布／reload失败，不重新续期；执行租约内重新核验绑定快照、generation和期限，reload结果不确定时禁止自动重放。续期准备失败与操作期限耗尽纳入退避，用户取消和锁竞争不增加失败次数；旧快照不能覆盖新重试状态。管理员可通过`cert renew --now`或`--all --now`提前重试本地退避；人工验证明确跳过，cron仍可调用run-once。
- **部署**：每张证书可绑定多个标准 PEM 目录或独立产物路径，支持 Unix 文件／私钥权限、签发／续期后自动部署及离线 list/show/update/remove。全部选定文件暂存并同步后逐一替换，Unix 在打开的父目录句柄下完成发布与清理，全部发布成功才 reload。自动发布前单独持久化待部署 generation 意图，取消或重启后 daemon 可继续，且不会把旧 generation 误标为已部署。手动／自动取消均等待已启动发布，部署前校验证书与私钥身份；reload 结果未知时跨配置和版本保留状态且不重放，副作用开始前取消时完整还原原代次及重试检查点，取消后仍保留部署报告。执行次数、期限、进程清理及 stdout/stderr 收集均有界；单目标失败继续其他目标，保留已签发证书。
- **命令行**：签发及 `provider show/cleanup/remove` 支持交互选择 Profile，终端中的 `provider add` 补齐缺失输入，`update` 未带变更参数时通过草稿菜单编辑 executable、argv 和 zone，子菜单返回保留草稿，保存时复核完整快照，取消不写入，显式参数仍直接执行；Provider list 复用带颜色的表格，show 展示 TOML 路径；JSON/非终端要求明确输入。`cert remove NAME --failed`清理明确失败且不可恢复的未签发申请，保留已签发、可恢复和结果未知的记录。交互式输入、按命令限定参数、离线库存、缺钥时的账户元数据查看、显式 CA 核验、统一 UTC 进度与表格、JSON 报告、构建信息和安全 debug 阶段日志。人工验证待办的文本与 JSON 恢复命令均携带精确 operation ID。独立配置请求超时、操作期限、轮询间隔与轮数上限，展示轮询计数及 Retry-After 来源。状态根依次由 `--data-dir`、`ASTER_ACME_DATA_DIR` 或平台默认目录确定。
- **CAA 预检**：issue/renew 在新订单前按 CA 广告身份、父域 CAA、通配符及账户／验证方式约束给出建议。不匹配、未知扩展、DNS 失败和超时不阻断 CA 验证。CAA／TXT／HTTP 以feature按需启用，由可嵌入Runner显式执行，共用默认5秒阶段预算与取消策略，结构化报告保留部分观察，并在CAA/TXT诊断中保留系统解析器初始化阶段和底层原因，区分CA身份缺失与本地初始化失败。不修改系统DNS或Hickory，不增加回退解析器。库默认关闭预检，CLI默认启用。
- **协议诊断**：类型化 ACME 资源与 IANA 全部 32 种错误类型，附 RFC／草案出处；保留未知扩展、标识符子问题、ARI explanationURL 精确映射、跨到期时刻窗口截断及拒绝／不确定证据，每周在线核对 IANA 注册表。
- **嵌入与文档**：对象安全的 signer/store/solver/observer 契约、按方法划分的具名材料模块、集中方法准入与发布策略、类型化长期验证快照，项目及 CLI 契约、任务路由、模块设计、RFC 索引，以及分开的本地／staging 验证记录。
- **仓库治理自动化**：采用组织共享、固定 SHA 的 `AsterCommunity/aster-automation` Action 与仓库自有的 `.github/aster-automation.json`：按变更文件确定性维护路径标签（`Rust`、`Python`、`Documentation`、`Dependencies`、`Scope: Core|Protocol|Client|Crypto|Challenges|Storage|CLI|Deployment`、`Risk: High`覆盖`crypto.rs`、`transport.rs`、`storage.rs`入口及对应目录），维护关联 Issue 生命周期（`Priority:*`、`Status:*`、`Wait For PR`、`Merged`），聚合 `PR Gate` 与 CI 生命周期标签并原地更新诊断评论，为默认分支及定时任务失败维护带 fingerprint 的故障 Issue（含 flaky 与基础设施分类），每小时 reconcile 并同步标签定义，issue 模板预置新报告标签，维护 release readiness dashboard。多个全量写入标签的 workflow 共享 FIFO 队列；同 SHA 的不同CI workflow run分别处理。`Repository Automation`校验配置、路径规则和并发契约。

### 变更

- **DNS 清理与传播**：保存 Provider 回执后等 5 秒，对每个 TXT owner 做一次本地建议性检查（默认预算 5 秒），同名的全部预期值须在同一应答中匹配；匹配立即请求 CA，缺值、解析错误或检查超时额外等 10 秒后交给 CA。显示 DNS 清理进度，清理失败不将已签发证书判为失败。Profile 传播配置现在分别控制检查前等待和单次检查预算，显式旧值保留。外部 Provider 清理保留逐条成功结果；receipt 恢复后仍遵守持久化重试下限。仅在 CA 结果已确定终结，或已过期且从未提交 finalize 的 pending/ready 订单下清理；确定性 CSR 拒绝也可清理。finalize 结果未知时继续禁止 DNS 清理和 journal 删除。
- **恢复与并发**：账户写入显式携带共享租约到阻塞任务结束，signer阶段和执行阶段的账户锁竞争采用相同分类，不增加续期失败退避；换钥 IO 串行，提交任务保留租约并完成取消后的结果分类，确认绑定已检查身份；Confirmed 换钥恢复统一由账户服务本地提交。账户换钥保留旧挑战材料，证书视图按持久化 catalog 恢复，拒绝过时提升。稳定账户 ID 由库生成，provider profile zone 与 DNS routing 共用 owner 语法。可选下单前预检受取消信号和操作期限约束。保留finalize结果未确认的过期请求，创建与finalize拒绝的较晚Retry-After同步保留到前任的重试报告，创建新续期世代前仍须遵守该下限。前台续期准入、历史子请求提交屏障、pending-generation部署准入、检查点转换和重试期限统一归库策略，保留时间精度；storage在租约内比较完整绑定后条件写入，续期准入拒绝与文件故障分开诊断。ARI、到期续期和部署重试由库级维护协调器按阶段运行；文件租约留在storage，reload执行留在宿主。CA发现与自动部署共用取消／期限；两次reload之间取消仍保存已知失败的重试退避；批次保留已提交结果。
- **发布与清理**：部署直接使用普通文件和稳定目录路径，不使用链接、目录交换或承诺整组原子事务。Webroot 固定目录身份，Windows 使用参与重命名共享检查的目录访问权，新目录权限同步后发布；shutdown 回收阻塞 worker；HTTP 建议性预检复用连接池，遵循用户代理并允许内网目标，DNS/HTTP共用专用预检时限，固定最多5秒，并接受HTTP-01响应末尾ASCII空白。Webroot 核验实际隔离的对象后再清理，保留用户替换文件。人工验证确认支持可见输入/编辑与默认否；独立读取线程在终端空闲时仍轮询取消、shutdown与操作期限，自行恢复终端模式后回收；诊断写入或 flush 失败不会报告成功。
- **存储与跨平台**：版本化 TOML、有界类型化查询、标准库锁及平台文件校验。Unix 使用私有权限和内部 in_use 相对链接；Windows 使用继承权限及可恢复完整目录副本。Unix 新建目录项在远端操作前同步，metadata 保存不能重建已删除账户。Windows 进程重启恢复不等同掉电后 rename 目录项持久性；无关用户文件保留。
- **运行时与依赖**：复用惰性 HTTP 连接池，隔离账户策略与 nonce；依赖版本／features 归根 workspace，限定 rustls/AWS-LC。优化 release 体积，仅可执行入口安装 Forge panic hook，私有报告脱敏且不重放 mutation。
- **构建与 CI**：新解析的 registry 版本须满足七天发布冷却期，已有 lockfile 版本继续可用。覆盖 Linux、macOS、Windows，检查导入归属、依赖 features、本地文档链接及独立预检feature组合，并验证库关闭预检时不引入DNS解析器；CLI的external DNS使用独立resolver。源码、清单和 Cargo 输出显式按 UTF-8 解码，不依赖 Windows 默认编码。构建信息不借用无关父仓库 revision，也不监视不存在的压缩分支引用；dirty 只包含已跟踪变更。Linux CI 追加覆盖率任务，收集 `cargo-llvm-cov` 的 LCOV 输出，发布运行摘要并上传 Codecov。

交叉编译及本地 mock 不代表原生平台或公网 CA 验收。

[Unreleased]: https://github.com/AsterCommunity/AsterACME/compare/v0.1.0-alpha.3...HEAD
[0.1.0-alpha.3]: https://github.com/AsterCommunity/AsterACME/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
[0.1.0-alpha.2]: https://github.com/AsterCommunity/AsterACME/compare/375db2cc0a355a706a33e0b9aec1f9aa5cfbbd71...v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/AsterCommunity/AsterACME/tree/375db2cc0a355a706a33e0b9aec1f9aa5cfbbd71
