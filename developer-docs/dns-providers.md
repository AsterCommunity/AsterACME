# DNS Provider 配置与自动发布

本页描述当前源码中的 DNS-01 自动化入口：内置 Cloudflare、阿里云云解析 DNS、腾讯云 DNSPod、华为云 DNS，以及用户安装的 ADPP 外部 executable。它们共用 `dns_provider` solver、路由、回执、传播和清理流程。ADPP wire 见 [RFC 0001](rfc/dns-provider-protocol/0001-asteracme-dns-provider-protocol.md)，后端注册与状态机见[实现契约](design/dns-backends.md)。Cloudflare 与 ADPP 自 `0.1.0-alpha.2` 起可用；内置 Cloudflare 已在真实 DNS 与 Let's Encrypt production/staging 环境完成验收，除 DNS-PERSIST-01 草案外的全部 challenge 方法已走真实 CA 签发，草案真实 CA 签发验收另行进行。

## 内置 Cloudflare

运行 `aster-acme provider backends` 查看本次构建实际支持的后端及配置字段。CLI 默认包含所有内置 provider：`dns-cloudflare`、`dns-aliyun`、`dns-tencent-cloud`、`dns-huawei-cloud`。如需精简 CLI，可用 `--no-default-features` 并显式选 feature；嵌入式 crate 默认不启用厂商，宿主按需选择 `cloudflare`、`aliyun`、`tencent_cloud` 或 `huawei_cloud`。

```sh
aster-acme provider add cf-prod --backend com.astercosm.acme.dns.cloudflare
aster-acme cert issue -a default -d example.com -d '*.example.com' -c dns_provider --provider cf-prod
```

终端按后端描述符提示配置，API token 使用隐藏输入。自动化可将以下内容写入私有 `cf-settings.toml`（Unix 0600），再执行 `provider add cf-prod --backend com.astercosm.acme.dns.cloudflare --settings-file /absolute/path/cf-settings.toml --json`；参数中不携带 token：

```toml
# 可选；省略时按最终发布域名自动发现 zone
# zone_id = "0123456789abcdef0123456789abcdef"
# 以下凭据来源二选一：
api_token = "your-cloudflare-api-token"
# token_file = "/absolute/path/private-cloudflare-token"
```

Zone ID 可选：省略时按 CNAME 最终发布目标的最长后缀发现 zone，在任何 DNS 写入前保存发现结果，恢复和清理始终使用同一 zone。显式指定时固定使用该 zone。Token 须覆盖目标 zone，并具备 Zone Read 和 DNS Edit；DNS API 列表逐页读取。API 入口固定为 Cloudflare 官方 HTTPS，不提供生产配置覆盖。`token_file` 由宿主有界读取，Unix 拒绝非私有或链接文件；文件仅允许末尾 CR/LF。

创建记录写入 `asteracme:<publication_id>` comment，重启以该标记对账。创建结果不确定且仍查不到本次标记时，不自动重放 POST；须核查远端状态。明确未写入的拒绝会保存证明，之后才允许新尝试。无标记的已有同值记录保留；属于另一个 AsterACME publication 的同值记录拒绝借用。删除前核对 record ID、TXT 类型、域名、值和 comment，并先保存删除意图。Cloudflare API 不提供本实现可用的条件删除：核验与删除之间的外部修改不具备原子隔离保证，操作者应避免并发修改托管记录。

`provider update cf-prod --settings-file /absolute/path/new-settings.toml` 原子替换配置；终端无变更参数时通过同一描述符编辑字段。Profile 中 `provider_custom` 全量脱敏，包含公开 zone ID 也不会单独回显。Token 可轮换；已保存证书定义的后端和 zone 选择模式不能被更换，自动发现的每次发布固定使用其已保存的 zone。

## 内置阿里云云解析 DNS 与腾讯云 DNSPod

CLI 默认已包含这两个后端；源码可用 `cargo run --locked -p aster_acme_cli -- provider backends` 检查。精简构建可用 `--no-default-features --features precheck,dns-aliyun,dns-tencent-cloud`。嵌入式 crate 对应 feature 为 `aliyun`、`tencent_cloud`。

| 厂商 | 后端 ID | 私有 settings 字段 |
| --- | --- | --- |
| 阿里云云解析 DNS | `com.astercosm.acme.dns.aliyun` | `access_key_id`、`access_key_secret` |
| 腾讯云 DNSPod | `com.astercosm.acme.dns.tencent-cloud` | `secret_id`、`secret_key` |

交互终端运行 `provider add NAME --backend BACKEND_ID`，两个凭据字段均隐藏输入。自动化把两项写入私有 TOML 文件，再传入 `--settings-file /absolute/path/settings.toml --json`。阿里云 RAM 权限覆盖 `DescribeDomains`、`DescribeDomainInfo`、`DescribeDomainRecords`、`DescribeDomainRecordInfo`、`AddDomainRecord` 和 `DeleteDomainRecord`。DNSPod CAM 权限覆盖 `DescribeDomainList`、`DescribeRecordList`、`DescribeRecord`、`CreateRecord` 和 `DeleteRecord`。请限制写权限到实际发布 zone。

两者按最终 TXT owner 逐页查找最长匹配 zone，并在写入前保存该 zone 身份。阿里云调用 `DescribeDomainInfo` 时显式传 `NeedDetailAttributes=true`，从返回的 `MinTtl` 取下限，最高为 86400 秒；缺失或非法下限在写入前拒绝。DNSPod 使用覆盖免费套餐的 600 秒下限和 604800 秒上限。Profile 展示请求值，签发 journal 的 `effective_ttl_seconds` 保存厂商读回值。

- **阿里云**保存写入前发现的同值 ID 并保留记录。若创建响应丢失，重启会重读同值记录并停在“所有权无法证明”。创建返回的 ID 落盘后才可签发和清理。记录级备注需要额外请求。
- **DNSPod**在创建请求中写入 `asteracme:<publication_id>` 备注。重启可据此恢复同一条记录的 ID。唯一一条已启用的默认线路用户同值记录可保留为 `preexisting`，其他 publication 的同值记录会触发冲突。
- 两者在删除前重读 ID 和记录元组。阿里云记录详情可省略 `DomainId`，仍按保存的记录 ID、域名、主机名、值和线路核验；返回 `DomainId` 时也必须匹配。核验与删除是两次 API 请求，应避免同时从其他工具修改托管记录。

四家内置 provider 共用有界只读重试预算，具体触发条件归厂商：阿里云与 DNSPod 的已保存 ID 暂不可见、DNSPod 与 Cloudflare 的创建对账标记暂不可见，以 5 秒间隔最多等待 6 次；华为云 pending RRset 保持 1 秒间隔最多等待 8 次。宿主取消、操作期限与 Profile timeout 仍优先生效。参数错误、响应格式错误和身份冲突不进入等待；重试耗尽保留原 checkpoint，不重发不确定创建。阿里云丢失创建响应且没有保存 ID 时，仍不能根据后来出现的记录推断所有权。

## 内置华为云 DNS（不保证并发安全）

CLI 默认已包含华为云；源码运行 `cargo run --locked -p aster_acme_cli -- provider backends` 可查看。精简构建可用 `--no-default-features --features precheck,dns-huawei-cloud`。嵌入式 feature 是 `huawei_cloud`。后端 ID 为 `com.astercosm.acme.dns.huawei-cloud`。`provider backends` 将 mutation model 显示为 `best_effort_rrsets`。

**华为云公开 DNS API 没有可验证的原子条件写入能力，本后端无法保证一定安全。** 读后 PUT/DELETE 期间若控制台、其他程序或另一个 data-dir 修改同一 RRset，这些修改可能被覆盖或误删。请协调全部写入者，尽量使用 ACME 专用的 CNAME 委派目标；本地锁和写后重读无法消除这个风险。

私有 `huawei-settings.toml`：

```toml
access_key_id = "YOUR_AK"
access_key_secret = "YOUR_SK"
region = "cn-north-4" # 国际站公网 DNS 通常使用 ap-southeast-3
# project_id 可省略；首次调用会按 region 查询 IAM 项目，唯一匹配才继续
```

运行 `provider add huawei --backend com.astercosm.acme.dns.huawei-cloud --settings-file /absolute/path/huawei-settings.toml --json`；交互终端也可隐藏输入 AK/SK。`project_id` 可显式填写，也可留空；留空时按 `region` 调 IAM `/v3/projects?name=<region>`，零个或多个匹配都会失败关闭，唯一项目 ID 会随 publication checkpoint 保存。需要目标公网 zone 的 `dns:zone:list`、`dns:recordset:list`、`dns:recordset:create`、`dns:recordset:update`、`dns:recordset:delete` 及 IAM 项目列表读取权限；以实际 IAM 授权契约为准并限制作用范围。已保存请求从 checkpoint 恢复项目 ID，不能在恢复途中换项目。

按最终发布 owner 分页发现最长 zone 并落盘，支持 CNAME 委派。新 RRset TTL 请求限制为 300–2147483647 秒，合并已有 RRset 保持厂商现有 TTL；回执记录实际 TTL，Profile 仍显示请求值。创建和清理读取完整集合，仅加入/减去本次值并保留其他值及用户描述。description 存储 publication 与值哈希标记，超过 255 字节时拒绝写入；同值属于其他 publication 时拒绝借用。结构化冲突最多重读合并四次。未知写入结果先对账，无法证明归属时暂停保留记录。详细所有权与非原子边界见[后端契约](design/dns-backends.md#华为云明确不保证原子性的-rrset-后端)。

## 创建和选择 Profile

```sh
aster-acme provider add dns-prod --exec /absolute/path/my-dns-provider
aster-acme provider list
aster-acme provider show dns-prod
aster-acme cert issue -a default -d example.com -d '*.example.com' -c dns_provider --provider dns-prod
```

终端可直接运行 `provider add`，交互输入名称与 executable 路径；`provider show`、`provider cleanup`、`provider remove` 缺少名称时交互选择已有 Profile。`cert issue -c dns_provider` 缺少 `--provider` 时也使用同一选择器。`remove` 选择后仍须确认（默认否），`--yes` 仅跳过确认，不跳过选择；`provider update` 未带变更参数时进入编辑菜单，可修改 executable、逐项增删 argv/zone 或明确清空，最后保存；子菜单提供返回选项，Esc 返回上一级并保留草稿，Ctrl-C 或主菜单取消才丢弃草稿且不写入。保存时在锁内复核完整 Profile 快照，有并发变化则拒绝覆盖。携带变更参数时直接应用参数，不额外弹编辑菜单。JSON/非 TTY 不提示，必须明确名称及必要参数（update 还须提供变更）。`provider list` 使用与 account/cert 一致的紧凑表格；`provider show` 展示完整脱敏字段及 Profile TOML 路径。

`--exec` 是存在且可执行的绝对文件路径；可重复使用 `--arg=VALUE` 设置独立 argv 值。进程直接启动，不经过 shell，不解析 shell 引号、变量展开、管道或重定向。Profile 名称使用 1–64 位 ASCII 字母、数字、下划线和连字符。不同云账号/区域/租户应使用不同 Profile。

Profile 固定保存在 `<data-dir>/providers/<name>.toml`，不是根 `config.toml` 的子表。首次 add 创建类似以下文件：

```toml
provider_profile_version = 1
backend_id = "com.astercosm.acme.adpp"
backend_config_version = 1
executable = "/absolute/path/my-dns-provider"
args = []
allowed_zones = [] # 默认不限制；例如 ["example.com"] 可启用附加限制
timeout_seconds = 30
ttl_seconds = 120 # 请求值；0..2147483647，厂商可采用最小值
propagation_timeout = 5 # 本地建议性检查的预算
propagation_interval = 5 # 发布成功后、首次检查前的等待

[provider_custom]
credential_profile = "production"
```

`--allow-zone` 是可选增强限制，不改变 DNS API 凭据本身的权限。配置非空列表时启用限制；`provider update NAME --clear-zones` 清空该配置，恢复默认不限制。

`provider_custom` 可在该私有文件中编辑，也可用 `--settings-file` 替换；内容由对应 backend 解释，ADPP 则交给 executable。它允许嵌套 TOML table、数组、字符串、布尔值和 JSON 可表达的有限数值；不使用 TOML 日期时间或 JSON null。整个 Profile 上限 64 KiB，其中自定义对象的 JSON 表示上限 32 KiB。损坏、未知版本、非法名称、相对 executable、非法 zone 后缀和无效期限均失败关闭，不自动重置。

## 凭据与敏感数据

外部 executable 可以自行访问它的凭据文件、Keychain 或 secret manager，AsterACME 只传 `credential_profile` 等选择信息。用户也可以把 token/secret 写入 `provider_custom`；这意味着凭据确实保存在该 Profile 文件中，不能宣称从未由 AsterACME 保存。

无论键名或内容看起来是否敏感，`provider_custom` 都按敏感对象处理：

- 内置后端只在本次状态机构造和 HTTP 请求中使用；外部后端仅在 ADPP stdin JSON `context.provider_custom` 中传递，不通过 argv 或 ENV 转发。
- `provider list/show` 的人类与 JSON 输出均隐藏整个对象；订单 journal 不保存自定义对象副本。
- 请求 stdin 不进入日志。provider stderr 不展示或存入订单；provider 必须保证响应错误文本和 `record_id` 不包含凭据，客户端还会防御性替换自定义值的直接回显。
- Unix Profile 文件使用 0600 和私有目录，链接/不安全权限会被拒绝。Windows 使用现有受校验文件机制和继承 ACL，不额外配置 ACL；操作者须保护 data-dir 的访问控制。

ADPP 子进程不继承宿主 ENV。脚本应使用可用的绝对解释器/shebang 或配置绝对 interpreter executable 加脚本 argv；不要依赖用户 PATH、HOME、代理或云凭据环境变量。它仍以当前用户权限运行，能够自行访问当前用户可访问的文件；ENV 清理不是操作系统沙箱。

## 手动指定发布目标

DNS 无法解析时，可以在新签发中重复指定 `--dns-target DOMAIN=TXT_NAME`。`DOMAIN` 是申请的证书域名（包含通配符时须写 `*.`）；`TXT_NAME` 是最终 TXT 记录的完整名称，不会自动添加 `_acme-challenge`：

```sh
aster-acme cert issue -a default -d example.com -d '*.example.com' -d other.net -c dns_provider --provider cf-prod \
  --dns-target 'example.com=verify.validation.net' \
  --dns-target '*.example.com=verify.validation.net' \
  --dns-target 'other.net=_acme-challenge.other.net'
```

每个映射仅作用于对应申请域名。根域和对应通配符共享原始 challenge 记录名，但需要分别发布 TXT 值；若两者都显式指定目标，目标必须相同。不同 challenge 记录名可以指定同一目标。未配置映射的域名仍探测 CNAME；只为根域或通配符之一指定目标时，另一条仍会探测，操作者须确保实际解析结果一致。映射保存于证书定义供续期使用，发布计划在写入前保存，恢复和清理沿用该计划。目标仍须符合 allowed_zones。手动指定不会验证真实 CNAME 是否指向目标，CA 仍按实际 DNS 验证；不提供恢复时更改配置的入口。

## CNAME 与传播等待

AsterACME 支持 `_acme-challenge` 的既有 CNAME 委派，不创建或改写 CNAME。例如：

```text
_acme-challenge.example.com. CNAME acme.validation.net.
```

默认不限制最终写入域：省略 `allowed_zones` 或设置 `[]` 均允许任意合法目标。如需额外限制，可在 add/update 中重复指定 `--allow-zone`，或填写非空列表；此时最终写入位置必须位于列表中的域或其子域。上述委派示例可设置 `--allow-zone validation.net`。匹配按完整 DNS 标签进行，`notvalidation.net` 不匹配 `validation.net`。检测 CNAME 环，最多跟随 8 个链接；系统 DNS 查询失败会保留具体原因，不过滤系统 nameserver、不 vendor/patch Hickory，也不回退到公共 DNS。

首次解析后的完整路径在 provider 调用前写入申请 journal。恢复和清理使用同一路径，不根据后来变化的 CNAME 改写发布目标。Profile 的当前允许 zone 仍会重新校验，配置缩窄后可能需要操作者恢复旧 zone 权限才能清理。

provider `present` 成功只表示 DNS API 操作已完成或完成对账。保存回执后默认等 5 秒，再对原始 challenge owner 做一次本地 TXT 建议性检查，默认检查预算为 5 秒；同名的全部预期值必须出现在同一份应答中。全部匹配立即请求 CA 验证；缺值、解析错误或本地检查超时仅警告，再等 10 秒后请求 CA，不循环等待本地可见。本地可见性不代表 CA 已通过验证。等待、检查和 CA 请求始终受取消及 `--operation-timeout` 限制；取消/整体超时仍保留记录与回执且不 ack。

`timeout_seconds` 为每次 provider 调用（含内置批次或外部进程）1–300 秒；`propagation_timeout` 现在表示单次本地检查预算（1–3600 秒）；`propagation_interval` 现在表示检查前等待（1–60 秒），不再表示轮询间隔。已有 Profile 使用文件中明确保存的数值，不自动重写；例如旧文件的 `propagation_timeout = 120` 会给单次检查最多 120 秒，可手动改为 5。额外等待固定为 10 秒。共享策略位于 `aster_acme_dns`，供外部及内置 adapter 复用。

`ttl_seconds` 默认 120，采用 RFC 2181 §8 的 `0..=2147483647` 范围。它是请求值，Cloudflare 当前将其限制到 60–86400；其他 backend 拥有各自的限制。TTL 不会清除已有递归或负缓存，也不代表传播等待时间。第一次写入前把 TTL 与目标和值一起固定在 publication plan 中；修改 Profile 只影响尚未生成计划的新发布，恢复、对账与清理继续使用已保存的计划，不因配置变化改写同一 publication ID。可通过 `provider add/update NAME --ttl-seconds 300` 设置；show 的人类和 JSON 输出也展示请求值。

## 恢复、所有权和清理

每个授权先保存稳定 `publication_id` 和写入计划，再调用 provider。每次进程还有独立 `request_id` 用于响应关联。外部 provider 必须保存自己的幂等/所有权事实：同一 publication ID 的重试不能变成重复创建，用户已有记录不能冒充本次创建。

AsterACME 保存逐记录回执后才运行传播策略和 challenge ack。部分失败不丢已确认回执；子进程超时、断管、非零退出或畸形响应保留结果未知，不生成另一个 publication ID。`rate_limited` 的重试下限会落盘，恢复不能绕过。

只有 CA 订单完成或已保存终态失败后才清理临时材料。精确同值、事先已存在的 TXT 标为 `preexisting` 并保留；`created` 只允许删除回执指向的未变对象，不清空 RRset。取消、整体超时、轮询上限和未知 CA 结果保留 TXT。DNS Persist 不通过这个临时 DNS-01 adapter 清理。

人类进度日志显示清理开始、已确认完成数、保留预存记录，以及失败后待重试状态；JSON 不混入日志。清理失败不抹掉已签发证书或原 CA 错误，也不阻止后续正常流程；待清理状态保留供重试。可单独重试：

```sh
aster-acme provider cleanup dns-prod
```

该命令逐一处理使用此 Profile 的终态、待清理申请，不加载 ACME 账户私钥、不调用 CA；未完成/结果未知的申请不会清理。缺失回执但已有持久化发布计划时，使用同一个 `publication_id` 对账，再保存回执和清理。正常终态清理自动执行；独立 cleanup 失败的后续重试由显式命令触发，目前没有额外的 daemon 清理扫描阶段。

持有 DNS 发布计划、尚未清理的 journal 不允许被 `cert remove` 丢弃。Profile 被保留证书定义引用时不能删除；这也保护后续续期。`provider remove dns-prod --yes` 仅在无引用时删除对应 Profile，不撤销证书或删除 DNS。

## 更新与续期

```sh
aster-acme provider update dns-prod --exec /absolute/path/new-provider
aster-acme provider update dns-prod --clear-args
aster-acme provider update dns-prod --clear-zones
aster-acme provider remove dns-prod --yes
```

Profile ID/schema、后端 ID、后端配置版本和非秘密远端 binding 保存在证书定义中，恢复/renew/daemon 复核当前配置。Cloudflare binding 是显式 zone ID 或自动发现模式。阿里云与 DNSPod 使用各自公网 API 的自动发现模式，实际 zone 身份按 publication 保存；ADPP binding 是 executable 路径与 argv，外部 executable 仍负责其 opaque custom 配置的账号/租户身份和旧回执的安全解释。后端或 binding 改变会拒绝恢复/续期/清理；保持身份的凭据轮换允许。更换目标应创建新 Profile 和新托管证书定义。

本次预发布布局要求 Profile 的 `backend_id` 和 `backend_config_version`，solver ID 为 `dns_provider`，保存定义还要求后端 binding 字段。旧布局和 `dns_external` 不自动读取、转换或删除。ADPP 的 `protocol = "com.astercosm.acme.adpp"` 与 version 1 现在只传最终记录名，不再传 challenge 名称及 CNAME 链；旧 provider 应适配此预发布协议变更。

Profile registry 使用跨进程共享/排他租约：签发持共享租约，更新和移除持排他租约；删除在事务中复核证书引用。已启动的后台存储任务会持锁到本地定义写完。daemon 将 `dns_provider` 视为非交互验证方式，续期仍沿用保存定义与现有证书租约；同名 TXT 多值并存和云 API 层的并发协调由 provider 实现。

本地 mock/loopback 验证与真实 DNS/CA staging 验收必须分开。接入新 executable 时先在受控 zone 和 staging CA 验证完整的创建、恢复、签发、预存值保留和清理链路。

内置发布在 `<data-dir>/providers/.publications/` 保存不含凭据的后端身份、固定记录和版本化检查点；`.locks/providers/` 按 publication 及后端/owner/TXT 键协调同一 data-dir 的进程。后台写任务持有租约到落盘结束，取消等待不会提前解锁。不同 data-dir 或其他工具的操作不受本地锁保护。
