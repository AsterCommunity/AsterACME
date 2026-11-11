# aster_acme_cli

账户注册、列表、找回、本地查看、显式远端验证、停用及本地移除 CLI。默认使用 Let's Encrypt 公开生产服务。manual DNS-01 证书申请、恢复和只读订单查看已实现；ARI 续期计划和账户签名吊销已实现；自动续期及 daemon 尚未实现。

```sh
cargo run -p aster_acme_cli -- account register \
  --data-dir ./data \
  --accept-terms \
  --contact admin@example.org --json
cargo run -p aster_acme_cli -- account recover --data-dir ./data --json
cargo run -p aster_acme_cli -- account show --data-dir ./data --json
cargo run -p aster_acme_cli -- account show --verify --data-dir ./data --json
```

`--accept-terms` 是布尔开关，表示明确接受所选 CA 当前公布的条款；客户端将实际发现的 URL 保存用于审计。第一次注册需要先查看 CA directory 的 `meta.termsOfService`；不内置固定条款地址，不自动接受新条款。没有显式接受且当前条款尚未接受时，交互终端展示 URL 并询问是否同意，默认否；JSON/非交互模式显示所需地址并要求 --accept-terms。本地密钥可能已持久化以便重试。

- `register`：保存/加载具名密钥，先查已有账户；仅在 CA 明确 `accountDoesNotExist` 后创建。已注册身份通过 POST-as-GET 复用。
- `recover`：通过 `onlyReturnExisting=true` 找回账户 URL，不生成密钥或远端账户。
- `show`：默认只查看本地密钥指纹、注册阶段、已保存账户 URL、联系人及条款 URL；pending 意图也不访问 CA；孤立密钥或丢失密钥报错，不猜测身份。
- `show --verify`：显式访问 CA，已有 URL 时使用 kid + 空 payload 查询；URL 缺失时只读找回。验证失败报错，保留原本地记录。
- 本地输出标记 `source=local`、`verified=false`、`status=null`，`local_state` 为 `registration_pending` / `registered`；远端响应标记 `source=remote`、`verified=true`。本地 registered 不代表 CA 当前仍 valid。
- 账户选择优先级：`--name` > 配置 `default_account` > `default`。
- `account switch work` 仅切换本地默认账户，要求目标密钥和已注册元数据存在，不访问 CA，用 `toml_edit` 更新配置的 `default_account` 并保留注释和格式。
- `--ca letsencrypt|zerossl|google` 选择公开提供商，或 `--ca-directory URL` 指定完整 ACME directory URL；两者互斥。注册时显式 `--user-agent` 保存到该账户 TOML 的 `user_agent`；后续本次参数覆盖账户设置，否则用内置默认值。默认值不写入文件，config 不保存 User-Agent。
- `--timeout` 为单次请求期限，1–300 秒，默认 30 秒。只有 badNonce 自动限次重签；网络超时和 429/5xx 均不自动重放注册。
- `--contact you@example.com` 可在注册时设置联系人，参数覆盖配置 `contact`，显式参数验证后回写配置 `contact`（普通邮箱格式）。编辑配置只改变未来注册的默认值，不更新 CA 上已有账户；`account update-contact work --contact admin@example.org --yes` 更新已有 CA 账户，`--clear-contacts` 显式清空；不改全局注册默认联系人。
- `--eab-kid ID --eab-key-file FILE` 提供 HS256 EAB，不把秘密放在命令行参数或账户元数据里。仅 register 接受注册选项。
- 普通终端显示彩色状态和可操作诊断；重定向、`NO_COLOR`、`TERM=dumb` 禁用颜色。CA 返回的控制字符会转义。
- `--json` 输出公有账户元数据，错误也以 JSON 写 stderr；失败退出码 1，参数错误由 clap 返回 2。

默认统一目录使用与 gcop-rs 相同的 `directories::ProjectDirs` 机制，身份为 `com.astercosm.acme`：macOS 为 `~/Library/Application Support/com.astercosm.acme`，Linux 为 `$XDG_CONFIG_HOME/acme` 或 `~/.config/acme`。Windows 路径按系统约定解析，但文件存储当前尚不支持 Windows ACL。配置、账户和未来证书输出共用该目录。

首次执行账户命令时自动生成带注释的 `config.toml`，使用 `toml_edit` 构造并解析文档。读取时已有文件按原始字节保留，定点编辑保留注释、格式和无关设置；损坏配置直接报错。生成文件不包含条款同意或 EAB 秘密，显式注册邮箱会保存为以后注册的默认值，其余单次 CLI 覆盖保持临时性。`--help` / `--version` 不创建配置。

只使用统一 `--data-dir`，未指定时使用平台默认目录。配置固定读取 `<data-dir>/config.toml`，账户存于同一根目录。不提供 `--config` 或配置内 `data_dir`，不读取其他目录配置。

`<data-dir>/config.toml` 示例（参数覆盖配置）：

```toml
# Managed by aster-acme. DO NOT EDIT version.
version = 1

[config]
# Public CA preset: letsencrypt, zerossl or google.
ca = "letsencrypt"
# 自定义 CA 时删除 ca 并使用 ca_directory = "https://ca.example/directory"。
default_account = "default"
contact = ["admin@example.org"]
timeout = 30
```

配置不接受持久化自动条款同意或 EAB 私密字段。相对路径以当前工作目录解析。配置上限 64 KiB，EAB 文件上限 8 KiB。文件存储当前仅支持 Unix；其他平台可通过库注入自有存储。

CLI 只组装 `dyn` 存储、密钥接口及账户服务，不处理 nonce、签名和注册恢复算法。文件行为详见 [cli-storage](../aster_acme_cli_storage/README.md)。

```sh
cargo test -p aster_acme_cli --locked
```

MIT OR Apache-2.0.

## 代码组织

参考 AsterDrive CLI，入口、分发、命令、公共能力分别归属：

```text
src/
  main.rs                  # Tokio、tracing、退出码
  app.rs                   # 根参数树
  dispatch.rs              # 命令分发、报告渲染与退出状态
  config.rs                # 配置 schema、注释模板、默认路径
  common/
    context.rs             # 命令输出会话、惰性 HTTP 池、配置与存储上下文
    session.rs             # 输出流、显式 Format、分隔与一次最终写入
    output.rs              # 标签、样式、字段及提示
    log.rs                 # 纯进度格式化
    error.rs               # 统一错误诊断
    help.rs                # clap 配色
    terminal.rs            # 交互选择、确认和取消
  commands/account/
    args.rs                # 子命令参数
    execute.rs             # 命令执行及库适配
    report.rs              # 本地/远端/切换的结构化结果
    render.rs              # 文本和 JSON 呈现
    tests.rs               # 参数、离线和网络边界测试
```

执行层返回报告，渲染层不发 HTTP 或读写账户。协议、签名和注册恢复继续归 `aster_acme`，文件锁和持久化归 `cli-storage`。

CLI 和配置 `contact` 接受普通邮箱，例如 `you@example.com`，发送 ACME 请求时自动转换为 `mailto:you@example.com`；显式 `mailto:` 也支持。库层继续接收 RFC 定义的 contact URI，CA 返回的联系人保留原始协议格式。

一个本地名称绑定一套 CA 和密钥，文件位于 `accounts/<name>/`。已有账户优先读取自身 CA，显式指定不同 CA 会报错；不同 CA 使用不同名称。`contacts` 保存本地配置，`server_contacts` 保存 CA 响应：省略表示 CA 未提供，空数组表示明确返回空列表。RFC 8555 §7.1.2 允许响应省略 contact；本地值不能冒充服务端值。

已有同名本地账户时，`register` 明确提示将复用原密钥和账户（包括 pending 身份），交互确认默认否。JSON/非交互运行不提示输入，必须用 `--yes` 显式确认；`--yes` 只跳过复用确认，不替代 `--accept-terms`。拒绝、取消或缺少复用确认时，不发 HTTP、不改联系人或账户，取消退出码为 130。成功复用会在文本说明，并在 JSON 中返回 `reused=true`；它与 `recovered`（从 CA 找回 URL）含义不同。新账户不需要复用确认；要独立注册使用不同 `--name`。

```sh
aster-acme account register --name personal --yes --accept-terms --contact you@example.com
```

## 交互式注册

直接运行 `aster-acme account register`：有可用本地账户时先问新建还是继续已有账户，默认新建；选择继续后再选账户并确认复用。没有本地账户时直接收集新账户名称和 CA；没有参数、配置或本地联系人时，询问是否添加邮箱（默认否，可跳过），输入时校验单个邮箱；获取 CA directory 后展示实际条款 URL 并询问是否同意（默认否）。已通过 --contact / --accept-terms 明确输入的内容不重复询问，已接受同一 URL 的条款也不重复询问，条款变化需重新接受。

只有 stdin 和 stderr 都是终端且未选择 JSON 才交互。--yes 仅用于已有账户复用，不跳过邮箱选择或条款问题；--accept-terms 才显式接受条款。拒绝条款或 Ctrl-C 退出 130，不发送 newAccount 或账户查询 POST；directory GET 可能已完成，本地密钥及已保存的联系人保留供重试。选择不添加邮箱会继续，不等于取消。

自动化仍使用显式参数，例如 `aster-acme account register --name personal --yes --accept-terms --contact you@example.com --json`。不提供联系人时可无联系人注册，具体仍受 CA 策略限制。

## 参数与交互边界

| 命令 | 接受的选项 | 无名称时的交互 |
| --- | --- | --- |
| list | --data-dir、--json、--verify；网络选项要求 --verify | 默认本地列举；--verify 逐个查询 CA |
| register | --data-dir、--json、--name、--ca/--ca-directory、--user-agent、--timeout、--yes、--contact、--accept-terms、EAB | 先选新建/继续（默认新建）；继续才列已有账户，新建输入名称和 CA |
| recover | --data-dir、--json、--name、--ca/--ca-directory、--user-agent、--timeout | 选择已有本地账户 |
| show | --data-dir、--json、--name、--ca/--ca-directory、--verify；网络选项要求 --verify | 选择已有账户，默认离线 |
| deactivate | --name、--ca/--ca-directory、--user-agent、--timeout、--yes、--data-dir、--json | 选择可用账户，再确认不可恢复的停用操作 |
| switch [NAME] | --name、--data-dir、--json | 只选择本地已注册账户 |

四个命令共用 selection 组件及存储层账户枚举。显式名称/目标不提示选择；JSON 和非终端不交互，使用配置默认账户，switch 必须给目标。默认账户在交互列表中预选，条目显示绑定 CA。

EAB 是 CA 外部账户绑定，Let’s Encrypt 通常不需要；ZeroSSL 和 Google Trust Services 可能要求预先申请 ID 与 HMAC 密钥。两个参数只出现在 register 的 Advanced registration (EAB) 帮助分组。始终以实际 directory 的 externalAccountRequired 为准。

公开 URL：Let’s Encrypt `https://acme-v02.api.letsencrypt.org/directory`；ZeroSSL `https://acme.zerossl.com/v2/DV90`；Google `https://dv.acme-v02.api.pki.goog/directory`（[官方说明](https://cloud.google.com/certificate-manager/docs/public-ca-tutorial)）。代码不内置测试环境或 debug/release 默认切换；互操作测试手动指定测试 CA 的 --ca-directory。

## 版本与构建信息

根命令帮助按 `account`、`cert`、`version` 排列。`aster-acme version` 显示产品版本、Git revision、dirty 状态、target、profile、features 和构建时间，`aster-acme version --json` 返回同一份结构化信息。保留 `--version` 的简短版本输出。版本命令不加载配置、不创建数据文件、不发 HTTP，运行时无需 Git。

构建脚本在编译时捕获元数据，源码归档缺少 Git 时输出 unknown。可用 `ASTER_BUILD_REVISION`（unknown 或 7–64 位十六进制）、`ASTER_BUILD_TIME`（RFC 3339）显式注入；否则使用 Git revision 和当前构建 UTC 时间，`SOURCE_DATE_EPOCH` 可提供可复现时间戳。dirty 状态来自构建时工作树，不能作为代码已提交的证明。

注册帮助按参数组声明顺序排列 name、contact、ca、ca-directory、accept-terms、user-agent、timeout、yes，不使用 display_order；存储/输出与 EAB 分组保持独立。

## 账户列表与停用

```sh
aster-acme account list
aster-acme account list --json
aster-acme account deactivate --name personal
# 自动化必须显式确认不可恢复的操作
aster-acme account deactivate --name personal --yes --json
```

list 按名称列出本地记录，标记默认账户，显示 CA、注册阶段、最后观察到的远端状态和停用状态；没有账户时给出注册提示。默认所有状态均来自本地，远端当前状态未验证。默认列表不加载私钥，因此丢失密钥的记录也可查看。列表按可见字符宽度对齐；NAME 表头为默认标记预留两列，* 表示配置默认账户，终端中该行加粗绿色。星号不表示当前 CA 有效。

deactivate 在 HTTP 前展示名称、CA、账户 URL 和不可恢复说明，默认否。--yes 只确认停用；不接受注册/联系人/EAB 参数。协议按 RFC 8555 §7.3.6 向账户 URL 发送 kid 签名的 `{"status":"deactivated"}`，要求 HTTP 200 且返回 deactivated 才确认成功。本地密钥和记录不删除，默认配置不会被悄悄切换；list 仍显示旧默认，但 switch 不允许选择已停用、撤销或有停用待对账意图的账户。

账户 TOML 增加 last_status（CA 最后一次实际返回值）和 deactivation（not_requested / pending / confirmed）。发送停用 POST 前持久化 pending，超时、取消、错误响应或确认写入失败均保留待对账状态，不自动重复。明确的 badNonce 仍遵守 transport 的有限重签规则。再次 deactivate 遇到 pending 会报错；已 confirmed 则返回本地确认结果 verified=false，不再联网。

停用后不能重新激活。RFC 要求 CA 拒绝这把账户密钥的后续请求，所以 show --verify 可能只返回 401；不能将 401 推断为停用成功。若返回有效账户对象，才更新 last_status 并处理 pending；无法确认时需要联系 CA。此命令不请求吊销已签发证书，CA 的其他清理行为由其策略决定。

CLI JSON 输出由 commands/account/output 中的具名序列化结构定义，渲染和错误输出均不使用 json! 拼对象。CLI 展示 DTO 与 CA 线上模型分开，后者统一从独立 aster_acme_protocol 领取。

CA 生产预设定义及入口 URL 统一来自 aster_acme_protocol::directory::Provider。CLI 的 ca 模块只适配输入解析/互斥策略，无独立提供商枚举或地址表。账户子命令帮助按声明顺序显示 list、show、switch、register、recover、deactivate。

## 自动化、列表验证与本地移除

所有单账户命令 show/switch/register/recover/deactivate/remove 共用 `[NAME]` 与 `--name NAME`，只能二选一；参数齐全不再出现账户选择。JSON 和非终端绝不交互：读取/找回使用配置默认，switch 必须显式给名称，register 的复用与 deactivate/remove 的写操作分别需要 --yes。--yes 从不替代条款同意。list/version 不接受账户名称。

```sh
cargo run -p aster_acme_cli -- account show personal --json
aster-acme account switch personal --json
aster-acme account register personal --yes --accept-terms --contact you@example.com --json
aster-acme account recover personal --json
aster-acme account deactivate personal --yes --json
aster-acme account list --verify --timeout 10 --json
aster-acme account remove personal --yes --json
```

list --verify 逐个读取密钥、按绑定 CA 查询并保存真实状态；单个失败仍继续后续账户。输出保留完整清单和 verification 数组（每项 name/status/error），全部成功才 verified=true；部分失败时先输出报告再以非零退出码和 stderr 诊断结束。默认 list 零 HTTP。已停用账户验证可能返回 401/403，该错误不伪装成验证成功。

remove 仅删除本地托管账户元数据与密钥；有用户内容时保留其目录，无额外内容时清空对象目录；对象锁在根.locks维护，不停用 CA、不吊销证书。先多行展示名称、CA、目录及丢失密钥意味着无法访问 CA 账户的说明，再默认否确认。无需解码私钥，损坏密钥也可移除；额外用户文件会保留；不安全的托管文件会阻止删除。删除与账户操作共用锁，先原子移动到隐藏 .<name>.removing 目录再清理；异常清理保留该目录供检查，不静默删除未知文件。当前默认被移除时条件清理配置，保留并发切换到其他账户的选择。

修改命令的成功文本只给摘要，例如 [OK] Deactivated account personal.；完整账户信息留给 show，JSON 保留完整结果。确认说明在短问题上方逐行展示，脚本无确认时仍能得到完整对象信息。

workspace 的包名及 crates 目录统一使用下划线；可执行文件仍是 aster-acme。旧包名不保留别名。

列表新增 REGISTERED AT (UTC)、STATUS AT (UTC)、LAST USED (UTC)，全部人类时间统一为 YYYY-MM-DD HH:MM:SS UTC 并对齐；JSON 保留 RFC 3339 原始精度。registered_at 表示本地首次确认账户已注册，找回旧账户也记录首次本地确认，并非 CA 原始创建时间。last_status_at 与 last_used_at 只随成功的权威认证响应更新；离线查看、失败、默认切换/本地移除不算账户使用。未知文本为 —，JSON 为 null，TOML 不伪造日期。

## 更新联系人与轮换账户密钥

```sh
aster-acme account update-contact work --contact admin@example.org --yes
aster-acme account update-contact work --clear-contacts --yes
aster-acme account rotate-key work --yes
```

支持 NAME / --name、--data-dir、--json 和网络参数，交互终端可选账户并默认否确认；无输入不隐式清空邮箱。`rotate-key` 重复调用会继续同一保存的事务。超时或取消后不删除两个密钥；401/403 不能证明远端换钥失败。list/show 显示待对账或待提交状态，详细契约见架构。当前新钥为 ES256/P-256。

注册显式值保存示例：`account.toml` 的 `[account]` 中 `user_agent = "AsterDrive/0.3.7"`。不指定时不写默认值；其他网络命令的同名参数仅覆盖当前请求。已注册的本地账户重用仍要求确认，不能把再次 register 当作新账户创建。

CLI bin 的 `doc = false` 避免 `aster-acme` 与库 `aster_acme` 生成相同 rustdoc 目录；可执行文件名不变，CLI 参考以本 README / --help 为准。`cargo doc --workspace --no-deps` 生成库 API。

## 手动 DNS 签发与订单查看

```sh
aster-acme cert issue -a default -d example.com -d '*.example.com' -c manual_dns
aster-acme cert issue --resume example.com
aster-acme cert issue --resume example.com --operation <ID> --skip-dns-check
aster-acme cert list
aster-acme cert show example.com
aster-acme cert show example.com --operation <ID> --verify
```

`-n/--name` 指定证书名称，不指定使用主域名加随机后缀，自动碰撞重试；显式名称已存在则拒绝；`-a` 账户、`-d` 域名可重复、`-c` 验证实现、`-f` 跳过本地 DNS 检查。账户命令支持 `-n` 名称、`-m` 邮箱、`-y` 确认；-y 不代表同意条款或 DNS 已发布。--data-dir/--json 等保留长参数。

只有 cert issue 推进签发；cert list/show 是只读/显式远端刷新入口，根 order 命令已删除。正常 issue 明确新建一个世代，--resume 只继续已存操作；只有一条未完成申请自动选择，多条时交互只显示主域名、UTC 申请时间和状态，脚本/JSON 必须用 --operation 指定，不猜最新记录。过期记录仍可查看，但 --skip-dns-check 不允许绕过过期/失效状态或重新下单。

手动模式展示所有 TXT 值，同名记录必须共存；交互确认后用 Hickory 检查本地 DNS 可见性再通知 CA。--skip-dns-check 仅跳过本地可见性检查，CA 必须照常验证。首次 JSON/非交互执行返回 status=action_required 和记录/恢复命令，不因 -f 直接通知 CA；添加记录后再 --resume。action_required 正常退出 0，脚本应检查 status，不能将它当作已签出。完成后明确提示删除本次具体 TXT，客户端不自动改动用户 DNS。

--timeout 是单次 HTTP 限制，--wait-timeout 是本次前台执行预算（默认 600 秒），与 CA 的 expires 无关。轮询遵守 Retry-After，没有时默认 2 秒，有取消与总 deadline；不启动后台服务。中断保留状态，用名称恢复，域名相同不意味着自动继续上一单。当前仅 manual_dns 可执行（内部使用 DNS-01）；自动 DNS、HTTP/TLS、续期、吊销、部署命令未开放。

每个 crate 独立显式维护 package.version；依赖版本/feature/source 继续仅在根 workspace.dependencies 配置。版本命令展示 CLI 自身版本，非整个 workspace 的统一版本。


## 统一展示和产物

当前根命令为 account、cert、version；证书命令为 cert issue/list/show/revoke/remove，不提供旧 order 别名。只用 `-c manual_dns` 选择验证方案，删除 --solver 和 -c dns-01。无域名的 cert issue 在终端询问，脚本要求 -d/--resume；无名称的 cert show 在终端先选证书，多次申请再选主域名/时间/状态，--operation 可直接定位申请。相同显示标签通过独立行索引选中，不靠文本匹配。

common/output 统一字段、颜色、Tips 和转义；common/time 统一所有人类 UTC 时间（秒级），common/log 统一阶段日志/级别对齐，common/table 统一 Unicode 列宽。颜色遵守 TTY/NO_COLOR，JSON 无 ANSI/阶段日志。cert list 使用紧凑表格，蓝色 Tips: 指向 cert show；account/cert show 详情使用同样的标签宽度。account show 的离线/verify 使用同一完整快照模板；成功查询后末行 Remote status: verified with CA，离线 not verified。cert show 的 source/verified 与实际请求一致，不再输出固定的 unless --verify 文案。

人工待办使用 [WARN]，最终签发使用 [DONE]；恢复说明与命令分行便于复制。签发阶段事件通过库的 dyn IssueObserver 注入，CLI 翻译为阶段文字、限频等待，不将人类日志硬编码进协议层。账户选择项仅名称/状态；危险确认详情和字段使用共享样式，默认否的问题保持明确。

新产物布局为 `certs/<name>/<UTC-time>-<random8>/`，`in_use` 相对链接在完整文件落盘后原子切换。成功输出固定指向 in_use/fullchain.pem、cert.pem、ca.pem、private-key.pem。DER 私钥与固定 CSR 是内部恢复资料；PEM 私钥和 DER 是同一把钥。CA 文件只包含服务端返回的剩余链，不自行追加根证书；只有叶子时 ca.pem 为空。旧未发布目录格式不兼容或迁移。


账户写入前检查本地身份。注册成功后仅在最新配置没有 default_account 时补为本次名称；注册失败/取消不设默认，已有默认或并发切换不覆盖。remove 默认会清除同名选择，随后成功注册可补回；switch 对合法缺省字段安全插入，重复同一值不改变已有字符串格式。缺账户主错误与 Hint 分开显示，提示核对 --name / --data-dir。

--help 统一显示 AsterACME <CLI version>、描述和 usage，所有子命令使用相同布局；version 文本按共享表格对齐产品版本与 Revision 等值列。构建时间的人类显示也使用统一 UTC 秒级格式，JSON 保留构建时 RFC3339。


cert issue 支持 -y/--yes：恢复已有申请时仅跳过 TXT 人工确认，正常执行 DNS 检查；-f/--skip-dns-check 仅控制本地 DNS 查询。首次自动化申请即使同时带两个选项，也先返回 action_required 和新 TXT 值，发布后显式 resume。--yes 不关闭域名/证书名称选择、不接受条款，也不隐含 --json。公共存储与 HTTP 参数组位于 common/args.rs，各命令领取自己适用的组；完整范围和后续扩展约定见 [CLI 参数契约](../../docs/cli-contract.md)。

续期计划和证书吊销的职责、持久化及失败边界见 [生命周期契约](../../docs/certificate-lifecycle.md)。ARI 只提供计划及显式刷新，周期唤醒留给后续 daemon；吊销保留本地文件，与订单状态独立。

cert remove 默认选一次申请，--history 清理非当前已签发版本，--revoked 匹配已确认吊销，--all 删除整个名称；默认否确认、脚本 --yes，不访问 CA 或账户；保留用户额外内容，根目录 .locks 保持稳定锁 inode。清理中断通过 .removing 标记阻止复用残留，见生命周期契约。account/cert show 用 CA query 指明本次实际查询范围，已确认吊销依据单列为 saved CA response。

托管身份、稳定定义、默认 in_use 展示与历史版本的最终契约见生命周期文档。IssueStore::create 只新建身份，IssueStore::renew 为已有定义准备新版本；cert renew 已提供单次执行，后台调度仍未实现。

证书 key_algorithm 使用公共 CertificateKeyAlgorithm 枚举，CLI -k/--key-type 默认 ecdsa-p256；定义、版本、恢复和实际密钥保持一致。RevocationReason 统一 RFC 5280 已分配代码（无7），CA 自行决定接受范围；remove-from-crl 不代表 ACME 恢复。详见生命周期契约。

0.1.0-alpha.1 提供 cert renew 单次到期/--now 提前续期，使用稳定定义、持久化 predecessor/replaces、未完成恢复和成功后 in_use 切换；后台 daemon 未实现。DNS跳过参数统一 --skip-dns-check，删除 --force/-f。对象锁集中于根 .locks/accounts 与 .locks/certificates，完整移除对象后清空无额外用户内容的目录，外置锁 inode 保留。

cert renew --all 提供按托管身份顺序执行的批量入口，复用同一事务及类型化结果；失败继续、人工TXT待办保存、取消停止，JSON一次汇总。未扩展账户签名算法，也不启动daemon；见生命周期契约。

新申请必须显式 -c/--challenge，不默认选择验证方式；恢复及续期沿用保存方式，不允许覆盖。--yes自动接受全部操作确认，不补填输入或跳过验证，条款同意仍独立。

所有账户、证书和 version 命令返回类型化 CommandReport，main 通过 OutputSession 统一写入最终结果；命令执行层不直接打印。渲染接收显式 Format，stdout/stderr 独立控制配色，JSON 只有一个结果或错误文档。会话跟踪真实进度/交互，避免全未到期批次出现开头空行。CommandContext 为一次命令持有同一惰性 HttpPool；批量续期和账户列表核验复用连接池，局部调用无需传入底层 HTTP 客户端。
