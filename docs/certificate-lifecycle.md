# 证书续期计划与吊销

本轮实现 RFC 9773 的 RenewalInfo 获取、持久化续期计划，以及 RFC 8555 §7.6 的账户签名吊销。尚不执行自动续期、系统任务安装或常驻调度；后续由 `aster-acme daemon` 统一消费这些接口和期限。

## 托管证书与签发版本

托管证书是稳定的本地管理身份，独立于主域名和 CA order。每次新的 cert issue 创建新托管证书；默认名称为首个规范化域名（必要时截短显示前缀）加八位小写十六进制随机后缀。自动分配遇到 NameAlreadyExists 会换随机串重试，最多十六次；权限、损坏、锁失败等其他错误直接返回。显式 -n/--name 已存在时拒绝，不静默追加。

cert.toml 保存稳定的域名集合、账户名称/ID、CA directory、验证实现和 current。每个 operation 是一次签发版本，拥有自己的订单观察、固定密钥/CSR 与产物。IssueStore::create 原子声明新身份；IssueStore::renew 只为已有定义准备新版本，不接收新的域名/账户配置，也不会发起 CA 请求。调用方再使用 IssueService 推进该版本。本轮未增加 cert renew 命令或后台调度器。

每份托管证书只有一个 current；成功提交新版本后才切换，失败保留旧 current。只有 current 的续期计划可作为活跃任务；历史日期只是过去的观察。is_current 从本地选择读取，不写入版本 journal。未发布格式直接更新，不读取旧 schema、不迁移或删除用户旧数据。

cert list 默认每份托管证书一行，优先当前版本；没有 current 时仅显示未完成/历史库存摘要，不激活旧版本。cert list --history 展开全部版本。cert show NAME 默认当前版本，尚无 current 时允许查看唯一未完成申请；不会默认选择历史证书。cert show NAME --history 引导选择具体版本，脚本使用 --operation 精确定位。列表和选择器显示最多三个 SAN 域名，更多的用 +N 提示；详情/JSON 保留完整域名。列表区分 ORDER STATUS 和 CERT EXPIRES，避免将订单期限当作证书到期时间。

## ARI 与回退

1. 校验签发产物时，按叶子证书原始有效期保存回退计划：`renew_at = notBefore + (notAfter - notBefore) * 2 / 3`。这是本地默认策略，不是 RFC 强制值。
2. 完整产物提交后立即尝试 ARI。directory 没有 `renewalInfo` 或叶子没有 AKI keyIdentifier 时保留回退计划。
3. RFC 9773 §4.1 的证书标识为 `base64url(AKI keyIdentifier).base64url(raw DER serial)`；保留正整数序列号的前导零、不带 padding。请求是无签名 GET，不需要账户身份、nonce 或 JWS。
4. 有效窗口内均匀随机选时并保存；相同窗口刷新时保留已选时间。时间已到表示需要立即续期，不把它挪到未来。RFC 将零长或倒置窗口视为无效；本地还拒绝越过证书到期时间的窗口，保留原计划作为到期保护。
5. `Retry-After` 支持秒数和 HTTP-date，查询间隔限制为一分钟至一天。缺失或非法时采用六小时重查；有效窗口本身仍可使用。
6. 超时、5xx 最多尝试三次，间隔 1、2 秒指数退避，受取消和整体 deadline 限制。其他错误不在同次调用重试；耗尽后六小时重查。刷新失败保留上一次有效 ARI 选时，首次失败使用原回退计划，不永久关闭 ARI。
7. GET 前保存重查期限，避免取消、进程重启或连续调用造成请求风暴。初次查询失败不撤销已完成签发或切换回旧证书。

`RenewalPlan` 保存在每个版本的 `operation.toml` 内，包含证书标识、notBefore/notAfter、renew_at、来源 ari/fallback、建议窗口、说明 URL、最近查询及下次查询时间、失败标记。它不包含私钥。`cert issue` 完成后在产物路径下显示 Next renewal 和来源；`cert list` 的 NEXT RENEWAL 列与 `cert show` 使用相同计划。吊销后显示 disabled，未确认时显示 suspended，不把旧计划当成下一次续期。`cert list/show` 默认离线；`cert show --verify` 成功查询订单后刷新到期的 ARI 观察，未到期不额外查询。

`RenewalService::refresh` 接受 `dyn IssueSession` 和调用方的 `ExecutionContext`。这提供嵌入式调度入口，不启动全局任务。CLI 退出后不会自行唤醒；后续 daemon 应按持久化 `next_check_at` 重新查询，并独立按 `renew_at`、失败退避和验证方案调度真正的续期。尚未实现 newOrder.replaces，因为目前没有 renew 操作。

## 吊销

```sh
aster-acme cert revoke example.com
aster-acme cert revoke example.com --reason key-compromise --yes
aster-acme cert revoke --operation <FULL-ID> --yes --json
```

- `[NAME]` 与 `-n/--name` 等价且互斥；无名称时可交互选择。多版本时必须交互选定版本或提供完整 `--operation`，不猜最新/current。
- 未确认的操作默认否确认；脚本必须 `-y/--yes`。它不暗含强制或绕过身份/产物检查。目标、账户和文件先检查，确认前不发现 directory 或提交 HTTP。
- directory 提供 `revokeCert`，不拼固定路径。提交 struct→JSON，certificate 为叶子 DER 的无填充 base64url，不发送 PEM、fullchain 或证书私钥。
- 当前仅使用绑定的活动签发账户密钥，JWS 使用 kid/nonce。证书私钥 jwk 签名和其他账户授权模式尚未提供。
- `--reason` 可选：unspecified (0)、key-compromise (1)、affiliation-changed (3)、superseded (4)、cessation-of-operation (5)。缺省省略 reason；CA 可按自身策略拒绝某个原因。暂不提供 hold/removeFromCRL 等原因。
- 先保存 pending，再提交请求。只有 HTTP 200 或 HTTP 400 的 alreadyRevoked problem 确认成功，空成功 body 合法。网络、5xx、未知响应或确认写入失败保留未确认状态。
- 不自动重放超时或 5xx；transport 仅对 badNonce 有限重签。操作员显式再次执行 revoke 时，可使用同一证书和原原因重新请求，以 200/alreadyRevoked 确认。pending 不允许换原因；省略时沿用原原因。
- 首次请求的明确 4xx problem 拒绝可恢复为未请求；之后的拒绝不能抹除更早 pending 的不确定性。已确认重复调用直接返回本地结果。
- 文件和 current 链接保留，不会重新生成密钥、删除证书、撤回已部署副本或重载服务。吊销状态与 order.status=valid、签发 phase=completed 独立。pending/confirmed 不再作为续期候选或继续 issue --resume。

`RevocationService` 归 aster_acme，显式状态决策归 core；协议请求与端点归 protocol，叶子读取和 journal 事务归存储适配器。CLI 只选择、确认及渲染。复用账户→证书锁顺序，避免与换钥、删除和其他签发执行交叉。

## Nonce 边界

按 RFC 8555 §6.5、§7.2，签名 POST 的 nonce 从池中单次取走，缺少时 HEAD newNonce；badNonce 重试必须使用该错误响应的新 nonce，不能取池中的其他 nonce。非法/缺失 Replay-Nonce 不丢弃成功 POST 结果（尤其 Location），后续请求再 HEAD 获取。ARI 的无签名 GET 不消耗 nonce。newNonce 响应的 Cache-Control: no-store 是 CA 的规范义务；客户端 HTTP 池不缓存响应。

## 查询范围与吊销依据的展示

`cert show --verify` 的 `CA query: order and authorizations refreshed` 仅表示本次成功查询了订单和授权；默认离线为 `not performed (local data only)`。它不表示本次查询了证书吊销状态，order.status=valid 与证书已吊销可以同时成立。`Revocation source` 在已确认时为 `saved CA response`，未请求/未确认时为 `local state`；本轮不查询 OCSP/CRL。JSON 不提供整条记录的 verified/source，改用 ca_query.order_refreshed、ca_query.authorizations_refreshed 和 revocation_source，分别表达本次查询范围及已保存吊销观察的依据。

## 本地删除

- cert remove [NAME]：选择一个申请及其产物；多候选时交互选择，脚本显式 --operation ID，--yes 不猜目标。
- cert remove NAME --history：删除非 current 的已签发版本，保留 current 和未完成申请；没有一致的 current 时拒绝，不猜应保留哪个。
- cert remove NAME --revoked：只删除保存了 CA 吊销确认的版本；pending 不是 revoked。若匹配 current，会在确认中说明清空 current。
- cert remove NAME --all：明确删除该名称下全部申请、版本和密钥。

上述三种批量范围与 --operation 互斥。默认否确认；脚本 --yes，JSON 禁止提示。无匹配的 history/revoked 清理成功返回零删除，不创建清理标记。删除 current 只清空选择，不自动回退到可能过期/吊销的历史证书；删除最后一个申请同时移除托管证书目录索引。

确认显示范围、名称、数量、目录，单次删除还显示申请 ID/时间/域名；明确提醒不会吊销 CA 证书、清理 DNS 或撤回已部署副本，且密钥无备份不可恢复。无需账户存在或加载账户密钥，不发网络请求。JSON 包含 scope、operation_ids、current_removed 和 ca_request_performed=false，描述本次操作，不推断远端证书状态。

准备与确认期间持有同一 cert.lock，预检托管文件、目录和 current/临时链接的 no-follow、权限、owner 和硬链接边界；不解码私钥。用户额外文件/目录/链接保留原位，锁 inode 始终保留。阻塞清理保留租约至结束；先落盘 .removing 标记，中断后阻止新建复用残留；成功后移除标记。没有额外内容的版本目录会删除，名称目录可能仅剩锁文件。

account show 的核验输出统一为 CA query: account refreshed / not performed (local data only)，JSON 为 ca_query.account_refreshed。证书查询范围为 order_refreshed/authorizations_refreshed，吊销依据单列 saved CA response，不将整条记录笼统标为 verified。
