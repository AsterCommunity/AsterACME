# DNS Provider 配置与自动发布

本页描述 CLI 的外部 DNS-01 自动化入口。协议定义见 [RFC 0001](rfc/dns-provider-protocol/0001-asteracme-dns-provider-protocol.md)，签发状态与持久化顺序见[签发设计](design/issuance.md)。内置云厂商 adapter 尚未提供；外部 executable 由用户安装并负责实际 DNS API 通信。

## 创建和选择 Profile

```sh
aster-acme provider add dns-prod --exec /absolute/path/my-dns-provider
aster-acme provider list
aster-acme provider show dns-prod
aster-acme cert issue -a default -d example.com -d '*.example.com' -c dns_external --provider dns-prod
```

`--exec` 是存在且可执行的绝对文件路径；可重复使用 `--arg=VALUE` 设置独立 argv 值。进程直接启动，不经过 shell，不解析 shell 引号、变量展开、管道或重定向。Profile 名称使用 1–64 位 ASCII 字母、数字、下划线和连字符。不同云账号/区域/租户应使用不同 Profile。

Profile 固定保存在 `<data-dir>/providers/<name>.toml`，不是根 `config.toml` 的子表。首次 add 创建类似以下文件：

```toml
provider_profile_version = 1
executable = "/absolute/path/my-dns-provider"
args = []
allowed_zones = [] # 默认不限制；例如 ["example.com"] 可启用附加限制
timeout_seconds = 30
propagation_timeout = 120
propagation_interval = 5

[provider_custom]
credential_profile = "production"
```

`--allow-zone` 是可选增强限制，不改变 DNS API 凭据本身的权限。配置非空列表时启用限制；`provider update NAME --clear-zones` 清空该配置，恢复默认不限制。

`provider_custom` 可在该私有文件中编辑，内容由 executable 自己解释。它允许嵌套 TOML table、数组、字符串、布尔值和 JSON 可表达的有限数值；不使用 TOML 日期时间或 JSON null。整个 Profile 上限 64 KiB，其中自定义对象的 JSON 表示上限 32 KiB。损坏、未知版本、非法名称、相对 executable、非法 zone 后缀和无效期限均失败关闭，不自动重置。

## 凭据与敏感数据

外部 executable 可以自行访问它的凭据文件、Keychain 或 secret manager，AsterACME 只传 `credential_profile` 等选择信息。用户也可以把 token/secret 写入 `provider_custom`；这意味着凭据确实保存在该 Profile 文件中，不能宣称从未由 AsterACME 保存。

无论键名或内容看起来是否敏感，`provider_custom` 都按敏感对象处理：

- 仅在本次 ADPP 请求的 stdin JSON `context.provider_custom` 中传递，不通过 argv 或 ENV 转发。
- `provider list/show` 的人类与 JSON 输出均隐藏整个对象；订单 journal 不保存自定义对象副本。
- 请求 stdin 不进入日志。provider stderr 不展示或存入订单；provider 必须保证响应错误文本和 `record_id` 不包含凭据，客户端还会防御性替换自定义值的直接回显。
- Unix Profile 文件使用 0600 和私有目录，链接/不安全权限会被拒绝。Windows 使用现有受校验文件机制和继承 ACL，不额外配置 ACL；操作者须保护 data-dir 的访问控制。

ADPP 子进程不继承宿主 ENV。脚本应使用可用的绝对解释器/shebang 或配置绝对 interpreter executable 加脚本 argv；不要依赖用户 PATH、HOME、代理或云凭据环境变量。它仍以当前用户权限运行，能够自行访问当前用户可访问的文件；ENV 清理不是操作系统沙箱。

## CNAME 与传播等待

AsterACME 支持 `_acme-challenge` 的既有 CNAME 委派，不创建或改写 CNAME。例如：

```text
_acme-challenge.example.com. CNAME acme.validation.net.
```

默认不限制最终写入域：省略 `allowed_zones` 或设置 `[]` 均允许任意合法目标。如需额外限制，可在 add/update 中重复指定 `--allow-zone`，或填写非空列表；此时最终写入位置必须位于列表中的域或其子域。上述委派示例可设置 `--allow-zone validation.net`。匹配按完整 DNS 标签进行，`notvalidation.net` 不匹配 `validation.net`。检测 CNAME 环，最多跟随 8 个链接；系统 DNS 查询失败会保留具体原因，不过滤系统 nameserver、不 vendor/patch Hickory，也不回退到公共 DNS。

首次解析后的完整路径在 provider 调用前写入申请 journal。恢复和清理使用同一路径，不根据后来变化的 CNAME 改写发布目标。Profile 的当前允许 zone 仍会重新校验，配置缩窄后可能需要操作者恢复旧 zone 权限才能清理。

provider `present` 成功只表示 DNS API 操作已完成或完成对账。保存回执后，AsterACME 单独等待原始 challenge owner 返回每个期望 TXT 值；默认最多 120 秒、每 5 秒查询，仍受 `--operation-timeout` 限制。`timeout_seconds` 为每次 provider 进程 1–300 秒；`propagation_timeout` 为 1–3600 秒；`propagation_interval` 为 1–60 秒。传播失败或取消保留记录与回执，不 ack；本地可见性始终不代表 CA 已通过验证。

## 恢复、所有权和清理

每个授权先保存稳定 `publication_id` 和写入计划，再调用 provider。每次进程还有独立 `request_id` 用于响应关联。外部 provider 必须保存自己的幂等/所有权事实：同一 publication ID 的重试不能变成重复创建，用户已有记录不能冒充本次创建。

AsterACME 保存逐记录回执后才运行传播策略和 challenge ack。部分失败不丢已确认回执；子进程超时、断管、非零退出或畸形响应保留结果未知，不生成另一个 publication ID。`rate_limited` 的重试下限会落盘，恢复不能绕过。

只有 CA 订单完成或已保存终态失败后才清理临时材料。精确同值、事先已存在的 TXT 标为 `preexisting` 并保留；`created` 只允许删除回执指向的未变对象，不清空 RRset。取消、整体超时、轮询上限和未知 CA 结果保留 TXT。DNS Persist 不通过这个临时 DNS-01 adapter 清理。

清理失败不抹掉已签发证书或原 CA 错误。可单独重试：

```sh
aster-acme provider cleanup dns-prod
```

该命令逐一处理使用此 Profile 的终态、待清理申请，不加载 ACME 账户私钥、不调用 CA；未完成/结果未知的申请不会清理。缺失回执但已有持久化发布计划时，使用同一个 `publication_id` 对账，再保存回执和清理。正常终态清理自动执行；独立 cleanup 失败的后续重试由显式命令触发，目前没有额外的 daemon 清理扫描阶段。

持有外部 DNS 发布计划、尚未清理的 journal 不允许被 `cert remove` 丢弃。Profile 被保留证书定义引用时不能删除；这也保护后续续期。`provider remove dns-prod --yes` 仅在无引用时删除对应 Profile，不撤销证书或删除 DNS。

## 更新与续期

```sh
aster-acme provider update dns-prod --exec /absolute/path/new-provider
aster-acme provider update dns-prod --clear-args
aster-acme provider update dns-prod --clear-zones
aster-acme provider remove dns-prod --yes
```

Profile ID 和 schema version 保存在证书定义中，恢复/renew/daemon 从同一 Profile 读取当前配置。更新会影响之后的调用；更改 executable 或凭据后仍须能识别旧回执并访问相同 DNS namespace。若要改为另一个 DNS 账号/租户，应另建 Profile，不能把碰巧相同的云记录 ID 当作同一对象。

Profile registry 使用跨进程共享/排他租约：签发持共享租约，更新和移除持排他租约；删除在事务中复核证书引用。已启动的后台存储任务会持锁到本地定义写完。daemon 将 `dns_external` 视为非交互验证方式，续期仍沿用保存定义与现有证书租约；同名 TXT 多值并存和云 API 层的并发协调由 provider 实现。

本地 mock/loopback 验证与真实 DNS/CA staging 验收必须分开。接入新 executable 时先在受控 zone 和 staging CA 验证完整的创建、恢复、签发、预存值保留和清理链路。
