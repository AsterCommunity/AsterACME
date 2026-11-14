# 证书续期计划与吊销

已实现 RFC 9773 的 RenewalInfo、持久化计划、cert renew 单次续期，以及 RFC 8555 §7.6 的账户／证书私钥签名吊销。`daemon run-once`提供一次维护周期；`daemon run`以前台常驻方式重复该周期，不安装或修改系统服务。每个data-dir只允许一个常驻daemon，具体开机启动、重启和日志收集交给系统服务管理器。

## 托管证书与签发版本

托管证书是稳定的本地管理身份，独立于主域名和 CA order。每次新的 cert issue 创建新托管证书；默认名称为首个规范化域名（必要时截短显示前缀）加八位小写十六进制随机后缀。自动分配遇到 NameAlreadyExists 会换随机串重试，最多十六次；权限、损坏、锁失败等其他错误直接返回。显式 -n/--name 已存在时拒绝，不静默追加。

cert.toml 保存稳定的域名集合、账户名称/ID、CA directory、验证实现和 in_use。每个 operation 是一次签发版本，拥有自己的订单观察、固定密钥/CSR 与产物。IssueStore::create 原子声明新身份；IssueStore::renew 只为已有定义准备新版本，不接收新的域名/账户配置，也不会发起 CA 请求。调用方再使用 IssueService 推进该版本。cert renew 和由外部调度器触发的 `daemon run-once` 已提供。

每份托管证书只有一个 in_use；成功提交新版本后才切换，失败保留旧 in_use。只有 in_use 的续期计划可作为活跃任务；历史日期只是过去的观察。is_in_use 从本地选择读取，不写入版本 journal。预发布operation journal保持version=1，字段改为准确的新订单意图和授权发布要求，并从RenewalPlan获取证书到期时间；旧字段布局不提供兼容读取或自动迁移。

cert list 默认每份托管证书一行，优先当前版本；没有 in_use 时仅显示未完成/历史库存摘要，不激活旧版本。cert list --history 展开全部版本。cert show NAME 默认当前版本，尚无 in_use 时允许查看唯一未完成申请；不会默认选择历史证书。cert show NAME --history 引导选择具体版本，脚本使用 --operation 精确定位。列表和选择器显示最多三个 SAN 域名，更多的用 +N 提示；详情/JSON 保留完整域名。列表区分 ORDER STATUS 和 CERT EXPIRES，避免将订单期限当作证书到期时间。

## ARI 与回退

1. 校验签发产物时，从叶子证书的 `notBefore`/`notAfter` 计算回退目标：有效期至少 10 天取经过 2/3，不足 10 天取经过 1/2。随后在目标前一天到目标点之间均匀随机选择 `renew_at`，下界取 `max(notBefore, target - 1 day, 本地生成计划的时刻)`，上界不含目标点。若目标已过去则安排立即续期；若计划生成时已过期则拒绝建立计划。这是本地默认策略，不是 RFC 强制值。
2. 完整产物提交后立即尝试 ARI。directory 没有 `renewalInfo` 或叶子没有 AKI keyIdentifier 时保留回退计划。
3. RFC 9773 §4.1 的证书标识为 `base64url(AKI keyIdentifier).base64url(raw DER serial)`；保留正整数序列号的前导零、不带 padding。请求是无签名 GET，不需要账户身份、nonce 或 JWS。
4. 有效窗口内均匀随机选时并保存；相同窗口刷新时保留已选时间。时间已到表示需要立即续期，不把它挪到未来。RFC 将零长或倒置窗口视为无效；本地还拒绝越过证书到期时间的窗口，保留原计划作为到期保护。
5. `Retry-After` 支持秒数和 HTTP-date，查询间隔限制为一分钟至一天。缺失或非法时采用六小时重查；有效窗口本身仍可使用。
6. 超时、5xx 最多尝试三次，间隔 1、2 秒指数退避，受取消和整体 deadline 限制。其他错误不在同次调用重试；耗尽后六小时重查。刷新失败保留上一次有效 ARI 选时，首次失败使用原回退计划，不永久关闭 ARI。
7. GET 前保存重查期限，避免取消、进程重启或连续调用造成请求风暴。初次查询失败不撤销已完成签发或切换回旧证书。

`RenewalPlan` 保存在每个版本的 `operation.toml` 内，包含证书标识、notBefore/notAfter、renew_at、来源 ari/fallback、建议窗口、说明 URL、最近查询及下次查询时间、失败标记。它不包含私钥。`cert issue` 完成后在产物路径下显示 Next renewal 和来源；`cert list` 的 NEXT RENEWAL 列与 `cert show` 使用相同计划。吊销后显示 disabled，未确认时显示 suspended，不把旧计划当成下一次续期。`cert list/show` 默认离线；`cert show --verify` 成功查询订单后刷新到期的 ARI 观察，未到期不额外查询。

`RenewalService::refresh` 接受 `dyn IssueSession` 和调用方的 `ExecutionContext`。这提供嵌入式调度入口，不启动全局任务。CLI退出后不会自行唤醒；`maintenance::run_cycle`按持久化`next_check_at`刷新ARI，并统一查询到期续期和已配置部署重试候选。宿主注入续期事务和部署执行器，库控制阶段顺序、候选查询及取消边界；cert renew按发现的renewalInfo支持情况选择是否提交newOrder.replaces。

## 单次维护周期

```sh
aster-acme daemon run-once
aster-acme daemon run-once --data-dir /srv/aster-acme --json
aster-acme daemon run-once --request-timeout 30 --operation-timeout 600 --poll-interval 5 --max-polls 30
```

ARI刷新只扫描当前 in_use、已完成、未吊销、未过期且有ARI标识且`next_check_at`已到期的证书；这一阶段不需要账户密钥。随后自动续期独立筛选当前 in_use、已完成、未吊销且`renew_at`已到期的证书，不要求该轮先完成ARI刷新。两个阶段分别调用各自期限，不注册账户、不创建订单直到续期事务通过准入检查。最后重新查询当前证书及部署绑定，对到期的已知部署失败执行重试；续期成功仍通过既有自动部署/reload hook立即部署。

可嵌入入口`aster_acme::maintenance::run_cycle`协调ARI、续期与部署重试阶段；ARI资格判断、目录缓存与发现、延期重查和更新归`renewal::refresh::RefreshCycle`，实际GET及持久化复用`RenewalService`的同一实现。续期退避与部署重试准入属于库策略；租约及持锁快照重验由`IssueStore`实现，文件适配器用跨进程锁执行。ARI使用类型化`IssueQuery::ari_due_at`筛选，每项调用`IssueStore::open_observation`获取与前台执行共用的证书锁，锁内重验选用世代、到期与吊销状态。正常元数据会话不加载固定key/CSR，执行会话`open`仍做原有材料验证；Windows视图恢复仍遵循存储契约。查询快照过期则跳过，重叠进程不会基于旧快照重复更新。锁失败记录为该项失败，不跳过为成功。

同一轮共用HTTP池，每个CA成功发现的directory复用一次。发现失败或无 `renewalInfo` 时保留原续期计划，将下一次发现延后六小时，避免频繁cron请求；这不冒充一次成功ARI GET，`last_checked_at`保持不变。实际ARI查询复用 `RenewalService` 的持久化意图、窗口、Retry-After和重试策略。缺少/非法Retry-After仍可应用有效窗口，结果为 `retry scheduled`。全部时间写回对应版本的现有计划，不增加独立任务状态文件。查询前保存一次重试意图；失败或响应没有新信息时不重复写journal，只有计划变化才保存响应结果。成功路径直接返回已保存记录，失败路径仍在锁内重读以报告真实持久化状态。

参数覆盖config.toml的`[config].request_timeout`（单请求，默认30秒）、`operation_timeout`（每张证书每个ARI/续期阶段，默认600秒）、`poll_interval`（默认5秒）和`max_polls`（默认30轮）；缺省配置回退默认，不设置整批超时。预算包含发现、锁等待和查询，但不强行丢弃已开始的存储IO；存储租约等待自身有界，超时/取消后必须等写入完成才释放租约。单项失败继续其他证书；Ctrl-C停止后续项，保留已完成和本项持久化结果。人类表格或一次JSON报告携带ARI和续期结果。成功/空库存/跳过人工验证退出0，查询失败或续期失败退出1，用户取消退出130。

例如每15分钟检查一次（路径由用户替换，通过`crontab -e`添加，程序不安装crontab）：

```cron
*/15 * * * * /usr/local/bin/aster-acme daemon run-once --data-dir /srv/aster-acme
```

cron触发频率只决定何时检查保存的期限，不会绕过CA的Retry-After。也可使用`daemon run`常驻运行；配置`daemon_interval`或`--interval`决定周期完成后的等待时间，默认60秒。

`daemon help`、`daemon help run-once`与`--help`由clap原生生成，包含cron和常驻示例。维护表格与证书/部署/批量续期列表共用`common::table::listing`，统一表头与状态样式；同一ARI窗口保留已有`renew_at`，成功刷新不意味着续期时间必然改变。run-once输出一份完整报告；常驻daemon逐周期输出与签发一致的时间戳、级别日志，JSON逐行记录`started`、`cycle`、`stopped`事件。续期中的签发阶段仍保留实时CA/验证进度。

## 吊销

```sh
aster-acme cert revoke web --sign-with certificate-key --reason key-compromise --yes
aster-acme cert revoke example.com
aster-acme cert revoke example.com --reason key-compromise --yes
aster-acme cert revoke --operation <FULL-ID> --yes --json
```

- `[NAME]` 与 `-n/--name` 等价且互斥；无名称时可交互选择。多版本时必须交互选定版本或提供完整 `--operation`，不猜最新/in_use。
- 未确认的操作默认否确认；脚本必须 `-y/--yes`。它不暗含强制或绕过身份/产物检查。目标、账户和文件先检查，确认前不发现 directory 或提交 HTTP。
- directory 提供 `revokeCert`，不拼固定路径。提交 struct→JSON，certificate 为叶子 DER 的无填充 base64url，不发送 PEM、fullchain 或证书私钥。
- `--sign-with account`为默认，使用绑定的活动签发账户密钥，JWS 使用kid/nonce；`--sign-with certificate-key`只加载选中世代的证书私钥，向revokeCert发送匹配叶子公钥的jwk，不带kid，不读取/创建账户。
- 证书密钥来自当前选定的托管世代`private-key.pk8`；无需原账户私钥、账户目录或CSR。库可通过`RevocationTarget`和`dyn RevocationSession`注入外部证书及存储，CLI本轮不增加任意文件导入入口。CA directory由托管记录或嵌入调用方显式提供，不从证书猜端点。
- `JwsSigner`与`SoftwareSigningKey`是账户和证书共用的密码学边界，证书公钥通过`Jwk::from_spki`与签名器比较；不构造虚假账户或重复JWS实现。账户路径无需证书私钥；两条路径均不使用签发执行会话，不校验固定CSR、不强制证书仍在有效期内，CA最终决定是否接受吊销。
- `--reason` 覆盖 RFC 5280 全部已分配代码：unspecified (0)、key-compromise (1)、ca-compromise (2)、affiliation-changed (3)、superseded (4)、cessation-of-operation (5)、certificate-hold (6)、remove-from-crl (8)、privilege-withdrawn (9)、aa-compromise (10)。7 未定义，解析时拒绝。缺省省略 reason；CA 可用 badRevocationReason 拒绝，不设客户端 CA 政策白名单。remove-from-crl 是增量 CRL 的移除条目，不代表 ACME 支持恢复证书；本客户端无论提交何种原因都不会将 confirmed revoked 改回有效。
- nonce和签名准备完成后、真正发送前保存pending，固定精确叶子DER的SHA-256、directory、原因、实际签名方式及公钥指纹；会话从确认前固定目标并在每次写入时复核，证书文件变化不得更换吊销目标。只有 HTTP 200 或 HTTP 400 的 alreadyRevoked problem 确认成功，空成功 body 合法。网络、5xx、未知响应或确认写入失败保留未确认状态。
- 不自动重放超时或 5xx；transport 仅对 badNonce 有限重签。操作员显式再次执行 revoke 时，可使用同一证书和原原因重新请求，以 200/alreadyRevoked 确认。pending 不允许换原因；省略时沿用原原因。
- 首次请求的明确 4xx problem 拒绝可恢复为未请求；之后的拒绝不能抹除更早 pending 的不确定性。已确认重复调用校验保存的目标绑定后返回本地结果，不读取签名器或发现CA。
- 文件和 in_use 链接保留，不会重新生成密钥、删除证书、撤回已部署副本或重载服务。吊销状态与 order.status=valid、签发 phase=completed 独立。pending/confirmed 不再作为续期候选或继续 issue --resume。

`RevocationService`拥有单一提交/响应分类，`revocation::authority::RevocationAuthority`只拥有认证策略；core保存显式重试/已确认/原因冲突的决策，protocol拥有请求与端点。`storage::revocation::RevocationSession`只有target、revocation和save_revocation三个操作，不依赖IssueSession或CSR。CLI storage的`open_revocation`持有证书租约，阻塞读写保留IO许可和租约；账户模式沿用账户→证书锁顺序，证书密钥模式只取证书锁。

`--operation-timeout`包含确认、发现与提交，总预算默认沿用config.operation_timeout或600秒。取消与超时在未发送时保留原检查点，发送后保留pending；`RevocationInput`/`RevocationInterrupted`提供吊销专用诊断，不误导用户issue --resume。先前pending不会被后次签名身份切换或拒绝抹除；显式重试可切换account/certificate-key，仍固定同一DER、CA及原因。远端成功但本地确认保存失败继续保留pending，下次显式请求由200/alreadyRevoked确认。

预发布journal版本仍为1，但已有pending/confirmed记录缺少新的目标/身份字段会拒绝执行，不迁移、不从旧状态猜测证明。

## Nonce 边界

按 RFC 8555 §6.5、§7.2，签名 POST 的 nonce 从池中单次取走，缺少时 HEAD newNonce；badNonce 重试必须使用该错误响应的新 nonce，不能取池中的其他 nonce。非法/缺失 Replay-Nonce 不丢弃成功 POST 结果（尤其 Location），后续请求再 HEAD 获取。ARI 的无签名 GET 不消耗 nonce。newNonce 响应的 Cache-Control: no-store 是 CA 的规范义务；客户端 HTTP 池不缓存响应。

## 查询范围与吊销依据的展示

`cert show --verify` 的 `CA query: order and authorizations refreshed` 仅表示本次成功查询了订单和授权；默认离线为 `not performed (local data only)`。它不表示本次查询了证书吊销状态，order.status=valid 与证书已吊销可以同时成立。`Revocation source` 在已确认时为 `saved CA response`，未请求/未确认时为 `local state`；本轮不查询 OCSP/CRL。JSON 不提供整条记录的 verified/source，改用 ca_query.order_refreshed、ca_query.authorizations_refreshed 和 revocation_source，分别表达本次查询范围及已保存吊销观察的依据。

## 本地删除

- cert remove [NAME]：选择一个申请及其产物；多候选时交互选择，脚本显式 --operation ID，--yes 不猜目标。
- cert remove NAME --history：删除非 in_use 的已签发版本，保留 in_use 和未完成申请；没有一致的 in_use 时拒绝，不猜应保留哪个。
- cert remove NAME --revoked：只删除保存了 CA 吊销确认的版本；pending 不是 revoked。若匹配 in_use，会在确认中说明清空 in_use。
- cert remove NAME --all：明确删除该名称下全部申请、版本和密钥。

上述三种批量范围与 --operation 互斥。默认否确认；脚本 --yes，JSON 禁止提示。无匹配的 history/revoked 清理成功返回零删除，不创建清理标记。删除 in_use 只清空选择，不自动回退到可能过期/吊销的历史证书；删除最后一个申请同时移除托管证书目录索引。

确认显示范围、名称、数量、目录，单次删除还显示申请 ID/时间/域名；明确提醒不会吊销 CA 证书、清理 DNS 或撤回已部署副本，且密钥无备份不可恢复。无需账户存在或加载账户密钥，不发网络请求。JSON 包含 scope、operation_ids、in_use_removed 和 ca_request_performed=false，描述本次操作，不推断远端证书状态。

准备与确认期间持有根目录 .locks/certificates/<name>.lock，预检托管文件、目录和 in_use/临时链接的 no-follow、权限、owner 和硬链接边界；不解码私钥。用户额外文件/目录/链接保留原位，外置锁 inode 始终保留。阻塞清理保留租约至结束；先落盘 .removing 标记，中断后阻止新建复用残留；成功后移除标记。没有额外内容的版本目录会删除，无额外内容时名称目录也删除；锁载体只留在根目录 .locks。

account show 的核验输出统一为 CA query: account refreshed / not performed (local data only)，JSON 为 ca_query.account_refreshed。证书查询范围为 order_refreshed/authorizations_refreshed，吊销依据单列 saved CA response，不将整条记录笼统标为 verified。

## 证书密钥算法

RFC 8555 §7.4 没有封闭的证书公钥算法列表；CSR 表达公钥及自签名，CA 决定接受范围。§6.2 的 ES256 必须支持/Ed25519 建议支持针对账户 JWS，不约束证书公钥，也不决定 CA 证书签名算法。

公共 KeyAlgorithm 定义八个真实可生成选项：ecdsa-p256（默认）、ecdsa-p384、ecdsa-p521、ed25519、rsa-2048、rsa-3072、rsa-4096、rsa-8192。CLI `cert issue -k/--key-type` 直接从该枚举产生可选值，不复制第二套算法表，不按 CA 预设过滤。Let’s Encrypt 官方 integration guide 当前列出 P-256/P-384 和 RSA 2048/3072/4096；其他选项可用于接受它们的自定义 CA，拒绝时保留实际 badCSR 等错误，不自动换算法重下单。

ECDSA CSR 分别用 SHA-256/384/512，RSA CSR 用 PKCS#1 SHA-256，Ed25519 用原算法。全部由现有 AWS-LC/rcgen 后端生成，无 OpenSSL 或新密码学依赖；RSA 8192 通过 AWS-LC 标准 PKCS#8 接入 rcgen，耗时可能较长。账户与证书的选择相互独立，共用 crypto::key_algorithm::KeyAlgorithm。

key_algorithm 同时保存于稳定 cert.toml 和各 operation.toml；创建后不可变。恢复使用原密钥和固定 CSR，不能同时指定 --resume 与 --key-type；后续续期存储入口继承相同选择。读取时校验实际曲线或 RSA modulus 位数与保存选择一致，不以 digest 正确替代算法校验；返回证书继续验证公钥/SAN/有效期和链。issue 创建前输出 Certificate key type，恢复输出保存值，list/show/JSON 显示同一字段。未发布格式直接演进，不做缺字段兼容或迁移。

## 固定 CSR 被 CA 拒绝后的恢复

某些 CA 会为同一账户和域名集合复用未完成订单。独立本地申请的 CA order URL 因此可能相同；这不允许混用本地密钥和产物。finalize 的明确 HTTP400 badCSR 会保存到 operation.finalize_rejection，恢复先返回该固定 CSR 的原始问题，不再根据后来被其他申请完成的订单下载证书；列表 STATUS、详情和选择器标记红色 failed (CSR rejected)，ORDER STATUS 仍展示 CA 原始状态（例如蓝色 ready）。nonce 过期、网络超时或其他未确认结果不冒充 badCSR，不改变原有有界重试/不重放规则。

此前未保存的错误无法从已变更的远端订单还原，不自动猜测或补写。更换密钥算法必须显式新建申请，原始失败材料保留。协议问题使用 ProblemKind（RFC8555 §6.7 的24项标准值及 Unknown(String)），JSON/TOML 仍是原始 type URI，未知扩展无损保留，调用方按枚举分发。

CLI 的 ACME Problem 诊断集中到 common/error/problem，账户/签发/吊销共享；按 ProblemKind 穷尽映射可执行建议，不把所有错误都提示“resume”。保留 CA detail、未知 URI、Retry-After，以及最多8条 subproblem 的 identifier/detail；截断展示不修改库中的完整结构。仅改变展示，不从提示中增加自动重试策略。

终端样式统一用 common/output::Style 枚举，ANSI 数字只在该模块编码；表格只保留一个 align 实现，通过可选回调在计算纯文本宽度后着色。cert list 隐藏 IN_USE 列，show/JSON 保留 in_use；ORDER STATUS 的 valid=绿、ready=蓝、pending/processing=黄、invalid/unknown=红，本地 failed(CSR rejected) 独立为红。

## 单次续期

```sh
aster-acme cert renew web
aster-acme cert renew web --now
aster-acme cert renew web --yes --json
```

renew 只接受托管名称（位置 NAME / -n 互斥），缺省在终端选择。不能覆盖域名、账户、算法、验证实现或指定历史版本；使用稳定 cert.toml。默认只到期执行，未到期返回成功的 status=not_due，不创建版本、密钥、订单或发 CA 请求。--now仅提前续期；--yes确认操作，不补填输入或条款。DNS预检建议性且有界，CA仍决定授权，取消/总期限不变，无DNS跳过或force参数。

名称选择后按账户→证书锁序取得租约，锁内再次验证 expected_in_use 和计划；已变更 in_use 拒绝，pending 吊销不能绕过，confirmed revoked 仅显式 --now 才允许替换。已存在同一 predecessor 的未完成续期时恢复它，不重复生成 CSR/密钥或新订单。首次自动化续期仍先返回新 TXT，后续 cert renew NAME 或精确 issue --resume NAME --operation ID 继续；多个未完成候选不猜测。

每次新续期固定新密钥和 CSR，沿用域名/账户/算法，保存 renewal_of.operation_id/certificate_id。CA 公布 renewalInfo 且旧证书有 ARI 标识时发送 replaces；否则走纯 RFC8555 newOrder，不发 replaces。实际提交值保存为 submitted_replaces，恢复不因目录变动改变含义；要求 CA 后续订单回显一致，否则保存 Location 并拒绝继续，不悄悄降级重下单。成功完整校验和落盘后才切 in_use，新计划属于新 in_use，旧版本保留。旧续期结果不允许覆盖后来改变的 in_use。

进度分别展示 CA capabilities (advertised) 的 RFC8555 账户/订单/keyChange/revokeCert 端点与 RFC9773 ARI；再显示本次 RFC8555 基础流程或 RFC9773 replaces，以及 ARI/2⁄3 时间回退策略。它是 directory 广告和本次执行决策，不宣称完整 RFC 合规。JSON 静默。最终 ActionRequired/Completed/NotDue 是带标签枚举，完成产物与待操作指令不能同时出现。

## 外置锁与删除

对象锁集中在 <data-dir>/.locks/accounts/<name>.lock、.locks/certificates/<name>.lock和.locks/daemon/instance.lock；最后一项只允许一个常驻daemon拥有同一状态根。该锁区不属于对象数据，释放后保留 inode，避免等候者与重建者取得不同锁。accounts/<name>、certs/<name> 不再创建内部 account.lock/cert.lock；完整删除无用户内容时清除对象目录。用户额外文件保留原位；异常清理标记仍需检查。配置文件读改写锁继续由 toml_file 管理。未发布阶段直接改变布局，不迁移既有旧对象。

全库状态一致性检查：账户 remove 只标 ca_request_performed=false，不冒称 CA 未停用；账户 list 查询计数为 requested/refreshed/failed，不把部分失败的本地快照冒称全远端。通配符授权显示 *.域名。原有 core 账户、订单/授权/challenge 动作、吊销 pending/confirmed 与存储先意图后副作用的边界继续保留；一般输入/权限检查仍为普通条件。

普通证书名称选择器统一显示名称/SAN摘要/UTC申请时间/本地状态，不显示重复in_use标记；普通show也不重复Current字段。显式历史、删除或吊销的版本选择标记in use，历史/精确operation详情显示In use: yes/no，删除确认仍说明清空in_use的影响；JSON和存储继续保留current。账户及证书行展示由common/selection::ChoiceLabel统一，交互身份仍使用独立索引。

人工发布继续资格来自已持久化的TXT要求，而非--resume或new_order_intent_saved参数；早于TXT准备的中断即使带--yes恢复，也先返回新待办，不暗中通知CA。

## 批量续期

`cert renew --all` 按托管名称排序顺序执行，每份托管证书只处理选用的 in_use 版本，历史版本不单独调度。--all 与位置 NAME / --name 互斥，--now、--yes、HTTP 参数和 --operation-timeout 保持单次含义；operation-timeout 是每项执行预算，不是整个批次预算。

批量复用单份证书的事务执行入口、账户→证书锁序、到期检查、未完成恢复、ARI/replaces 和产物校验，不另写签发逻辑。一项失败继续后续项；无 in_use 的托管证书标记 skipped，不隐式完成初次申请。目录损坏等无法安全枚举的库存错误在批次开始前整体报错。

批量不弹逐项确认问题。手动 DNS 首次新材料始终先返回 action_required 并保存 TXT；已有材料则调用正常 DNS 检查（除非明确），不会因为 --all 自动假设已发布。逐项 action_required 不阻塞后续证书，也不计为完成。仍可用 `cert renew NAME` 或带完整 operation ID 的 issue --resume 继续。

单次与批量共用 CertificateResult（Issuance/NotDue）及实际 IssueOutcome；批量逐项增加 Skipped/Failed/Cancelled，最终一次渲染。人类输出汇总表、计数、错误建议和 TXT/产物细节；JSON stdout 仅一个对象，包含 status、summary 和 results，每项的 result 为带 status 的结构。失败时 status=partial_failure、退出1；无失败但有待办时 status=action_required、退出0；全部处理完毕为completed（不代表每份证书都新签出，需检查计数）；取消为cancelled、退出130。空库存成功返回空列表及零计数。退出边界不会另加第二份JSON错误。

整个批次共用取消令牌。Ctrl-C 停止进行中的异步执行，不再开始后续项，剩余项为 skipped/batch_cancelled；已返回的完成结果保留，不因提交后的取消改报失败。已启动的存储阻塞写入持有自身租约至完成，取消后状态与是否切换in_use以持久化记录为准。没有自动后台重试、定时调度或并行写DNS行为；账户密钥算法独立选择，不由证书续期改变。

批量显示收敛为一次结果表，不再展示重复本地计划表和逐项Checking renewal日志。仅有实际续期/恢复工作时先简报数量，执行时保持原进度；全部未到期时用“certificates checked; none due for renewal.”总结，混合结果只列非零计数，JSON仍完整。库存和执行结果按托管名称统一排序。

失败申请清理：`cert remove NAME --failed`只选择未签发、非in_use且存在不可恢复失败证据的generation。不能用“非resume候选”直接授权删除：newOrder响应丢失、408/429/5xx仍保留，已valid但尚未下载的订单也保留。storage在删除租约内用同一规则重新筛选，并沿用未知用户文件保护。


### 自动续期准入

daemon 只对当前 `in_use`、已完成、未过期、续期时间已到且吊销状态为 `NotRequested` 的证书执行自动续期。验证实现白名单是 `webroot`、`standalone`、`tls_alpn`、`dns_external` 和 `dns_persist`；`dns_persist`只有与已签发前任快照完全相同的长期TXT才免确认，新增或改变的材料返回待办；`manual_dns`、`manual_http` 以及未知实现返回 `manual validation` 跳过，不创建续期世代。`dns_external`沿用保存的Provider Profile引用，按发布回执与传播策略推进，不复制续期事务。

续期调用已有 `cert renew` 事务和签发后自动部署流程。账户锁、证书租约、`expected_in_use` 重验、固定 key/CSR、旧世代保护和部署 generation 检查全部复用；两个 daemon 或 daemon 与前台 renew 同时运行时，只有持锁成功的一方创建续期世代，另一方复用或报告锁竞争。

### 失败重试

续期失败状态保存在仍处于 `in_use` 的前任 operation 中，独立于 ARI `next_check_at` 与证书 `renew_at`。每次失败后的本地等待依次为 1 分钟、10 分钟、100 分钟，然后每天一次。若 CA 给出有效 `Retry-After`，实际等待取本地退避与 CA 时间的较晚者。确认的终态失败在期限到达后保留为历史，并创建新的续期世代；未终态、可恢复操作继续使用原 operation、key 和 CSR。newOrder 结果不确定且没有可用 Location 时，自动与 `--now` 重试都被阻止，直到操作员检查并处理该状态。即使进程在前任退避状态落盘前退出，准备新世代时仍核验历史子 operation 的提交证据和 CA Retry-After，不能因缺少重试状态而另下订单。

`cert renew NAME --now` 与 `cert renew --all --now` 可越过本地退避，供管理员提前重试；它们不能绕过 CA `Retry-After`、证书租约、`expected_in_use` 或不确定结果屏障。失败次数在证书租约内持久化，因此后续 cron 不会把同一失败重新当作首次尝试。账户或密钥不可用等签发 session 建立前的失败，通过元数据会话比较原 `in_use` 与重试快照后写入；若已有进程成功换代或记录了新失败，旧结果不再覆盖或重复计数。操作 deadline 耗尽计入失败退避，用户取消与租约竞争不增加失败次数。重试计算保留时间的小数精度，并保留此前更晚的 CA deadline 与不确定屏障。新证书成功提升为 `in_use` 后，旧世代的重试状态不再参与调度。

部署失败按 binding 与 generation 独立退避，使用相同的 1 分钟、10 分钟、100 分钟和每日上限。`daemon run-once` 在续期后扫描到期的 `PublishFailed`、`ReloadFailed` 和已发布但尚未 reload 的状态，只重试部署，不重新签发证书。新 generation 自动部署成功会清除该 binding 的失败计数。`Reloading`/`ReloadUncertain` 表示 reload 可能已影响服务，不进入自动重试；必须先检查服务，再由操作员显式执行 deploy retry。自动执行区分签发后部署与定时重试，两者均在持有证书租约后重新检查当前 generation、不确定状态与期限；定时重试还比较选中的完整 binding 快照，过时任务跳过且不发布文件、不执行 reload、不追加失败记录。只有人工显式执行可请求重试不确定 reload。单个续期或部署失败不阻断其他证书，最终退出状态报告周期内的失败。
