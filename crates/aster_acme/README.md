# aster_acme

面向应用的 ACME 层。目前实现输入类型、验证方法选择、响应材料推导与可注入 solver 契约；已实现账户注册/找回/查看/停用、多算法 JWS 和账户所需 transport；已实现 manual DNS-01 签发与恢复；已实现 ARI 续期计划和账户／证书密钥签名吊销；cert renew 单次执行已实现；`maintenance::run_cycle`按序协调ARI刷新、到期续期和部署重试，由宿主注入续期与reload执行器；常驻调度由CLI宿主提供，ACME服务库不启动后台任务；已接入可注入DNS provider发布与逐授权回执检查点，CLI提供ADPP external adapter。

- `account`：账户服务、注册恢复、不可恢复停用、条款/EAB。
- `storage::{account,issuance}`：对象安全的账户/签名器/轮换与证书会话契约；`storage::query` 提供类型化查询及纯版本投影，库不依赖文件系统。
- `crypto`：`dyn JwsSigner`、共享 KeyAlgorithm、EC/RSA/Ed25519 账户钥、EC/RSA/OKP JWK 与规范指纹、按算法生成 JWS 和 HS256 EAB。
- `transport`：共享 `HttpPool`、HTTPS directory、nonce 池、POST-as-GET、badNonce 限次重签、1 MiB 响应限制、超时和结构化错误。
- `identifier`：DNS/IDN 规范化、长度和通配符校验、wire identifier 与授权 wildcard 语义。
- `challenge`：已知与未知验证类型、Require/Prefer 策略、token/key authorization、DNS/HTTP/TLS材料；`challenge::dns_persist`实现草案-02长期TXT及预配置材料计算。
- `solver`：Send + Sync 的异步 trait，可通过 dyn 注入；方法匹配、ready及cleanup；类型化材料先由ACME持久化。

依赖方向：本 crate → protocol / core / Forge 宏；DNS 实现 → 本 crate。具体供应商代码不放在此处。

```rust
use aster_acme::{challenge::{ChallengeKind, ChallengePolicy}, identifier::DnsIdentifier};
use aster_acme_protocol::order::WireChallengeKind;

let identifier = DnsIdentifier::new("*.example.com")?;
let method = ChallengePolicy::Require(ChallengeKind::Dns01).select(
    &identifier,
    &[WireChallengeKind::Dns01],
    &[ChallengeKind::Dns01],
)?;
assert_eq!(method, ChallengeKind::Dns01);
# Ok::<(), Box<dyn std::error::Error>>(())
```

四种材料采用对称的子模块具名类型：`ChallengeMaterial::Dns01(dns01::Dns01Record)`、`DnsPersist01(dns_persist::DnsPersistRecord)`、`Http01(http01::Http01Response)`、`TlsAlpn01(tls_alpn01::TlsAlpn01Response)`。通过各类型的`derive`构造材料；未发布的聚合`ChallengeMaterial::derive`入口已移除，不保留透传兼容方法。`ChallengeKind`提供集中方法能力，订单/存储层通过`PublicationLifetime`及类型化长期快照使用这些能力。

Prefer 只在开始验证时选择兼容方法，不代表失败后自动回退。未知 wire 方法保留用于诊断，不能执行。当前仅定义 solver 接口，并未内置任何可用验证实现。

验证材料先保存到签发检查点，再调用 `ChallengeSolver::ready` 发布；恢复时通过 `restore` 重建运行期资源，并在终态调用 `cleanup` 清理自身材料，所有路径调用 `shutdown` 回收运行期任务。

`ChallengeKind::DnsPersist01`不使用token；其`ValidationRequirement::DnsPersist01`由已发现directory、challenge issuer参数和当前账户身份派生，展示给solver前执行账户控制权证明。长期TXT永不交给临时cleanup。嵌入式存储应在续期时携带同一账户/定义的`RenewalPredecessor.retained_validation`确认快照，保持历史密钥记录复用；缺快照的材料仍需发布。`DnsPersistRecord::provision`只计算材料，独立预配置的账户POST-as-GET及安全交付由调用者负责。规范与限制见[RFC参考](../../docs/rfc-reference.md#dns-persist-草案实现2026-11-14)。

```sh
cargo test -p aster_acme --locked
```

覆盖域名/IDN/通配符、DNS 长度边界、token 编码和长度、材料推导、方法选择组合、取消/超时及恢复数据编解码。依赖与 feature 统一从根 workspace 继承。License: MIT OR Apache-2.0.


## 账户服务边界

通过 `AccountService::new(Arc<AcmeClient>, Arc<dyn AccountStore>)` 注入存储；签名器为 `dyn JwsSigner`，具名密钥查询接口返回 `Arc<dyn JwsSigner>`。嵌入式服务可以提供数据库和外部签名器，不依赖 CLI 或文件系统。

流程先保存注册意图，使用同一密钥查找已有账户，仅在明确 accountDoesNotExist 后创建；网络超时/取消保持 pending 供后续对账。已有注册元数据不代表服务端仍 valid，每次查看会读取真实远端状态。条款由调用者显式同意，服务保存当前 directory 公布的实际 URL，URL 变化后要求重新接受；HS256 EAB 的新账户响应必须反映原绑定才确认成功。

遵守 RFC 8555 §6.2–6.7、§7.1.1–7.1.2、§7.2、§7.3–7.3.6，以及 RFC 7515/7518/7638。newAccount 使用 jwk，其他账户请求使用 kid；两者互斥。badNonce 重试直接使用错误响应 nonce；不自动重试网络超时、rateLimited、5xx 或条款交互。错误保留 problem URI、detail、instance、subproblems、扩展及 Retry-After。

Transport 不跟随重定向、默认验证系统信任的 TLS；仅显式本地测试选项允许数字 loopback HTTP。测试限额与证书信任不应通过禁用 TLS 来绕过。并发 nonce 池容量 64，响应体上限 1 MiB；账户服务的文件/分布式锁策略归存储适配。

验证记录见 [账户测试](../../docs/account-testing.md)。真实 staging 已验证注册、找回及复用，尚未运行 Pebble。

## 注册账户时发送的信息

依据 [RFC 8555 §7.3](https://www.rfc-editor.org/rfc/rfc8555#section-7.3) 和 [§7.3.1](https://www.rfc-editor.org/rfc/rfc8555#section-7.3.1)：

1. 获取 CA directory，读取 `newNonce`、`newAccount`、条款地址和 EAB 要求。
2. 在本地生成或加载 P-256 账户密钥，先持久化密钥及 pending 注册意图。
3. 获取 nonce，向 `newAccount` 发出由实际账户钥决定算法的签名请求，payload 为 `{"onlyReturnExisting":true}`。已有账户直接复用；只有明确 `accountDoesNotExist` 才创建。
4. 创建请求的 payload 可包含 `contact`、`termsOfServiceAgreed` 和 CA 要求时的 `externalAccountBinding`。`--accept-terms` 对应布尔字段，实际条款 URL 留在本地审计元数据中。
5. CA 返回账户资源与 `Location` 账户 URL。保存为 registered；后续查询以账户 URL 作为 JWS 的 `kid`，使用空 payload 的 POST-as-GET。

示例创建 payload（外层仍需 JWS 签名）：

```json
{
  "contact": ["mailto:you@example.com"],
  "termsOfServiceAgreed": true
}
```

JWS protected header 包含 由密钥决定的 `alg`（ES256/ES384/ES512/EdDSA/RS256）、账户公钥 `jwk`、防重放 `nonce` 和精确目标 `url`。账户名称、默认账户选择、本地路径和私钥不发给 CA。联系人在协议中可选，具体 CA 可有额外策略。EAB 使用 CA 发放的 ID 和 HMAC 秘密签出绑定对象，发送对象及 ID，不发送秘密本身。

账户不是邮箱/密码登录，身份控制依赖账户私钥。注册阶段不发送域名、CSR、证书私钥或 DNS 供应商凭据；域名属于后续订单，CSR 属于 finalize。HTTP 层会带 User-Agent，CA 也能观察请求来源 IP。

账户记录的 `contacts` 保存本地设置，`server_contacts: Option<Vec<String>>` 保存最近 CA 返回值。RFC 8555 §7.1.2 的 contact 是可选 URL 数组；响应省略不等于明确空数组，二者都不能抹除本地输入。`update_contacts` 按 §7.3.2 向原账户 URL 提交完整 contact 数组，空数组明确清空；仅 HTTP 200 和账户对象更新服务端观察。

`AccountService::deactivate` 遵守 RFC 8555 §7.3.6，仅接受已有账户 URL，不隐式恢复或创建；先保存 DeactivationState::Pending，再发送包含 status=deactivated 的 kid 签名 POST。仅 200 + deactivated 确认成功。失败/取消保持 pending，重复调用不自动重放；confirmed 返回本地结果。`inspect` 只有得到真实账户对象才解除/确认 pending；401 不作为停用证据。账户记录保留 last_status，注册阶段与远端有效性仍分开。

线上请求/响应模型集中在独立 `aster_acme_protocol`：AcmeUrl、Directory/DirectoryMeta、Problem、AccountObject、账户请求和 JWS 封装/header。调用方直接从 protocol 导入，不保留旧 transport/crypto 路径的 re-export。此 crate 保留密钥构造、签名、HTTP、nonce 和业务编排。协议请求使用 struct→JSON，不再 Map/json! 拼字段；真实路径由 CA 提供，测试验证任意路径和查询串的精确签名。

账户本地状态类型已归 core::account，注册/复用/停用/可用性通过显式 account_action 决策，不在 CLI/服务重复维护业务条件。AccountService 执行动作并在成功解析权威账户对象时集中应用观察。

AccountTimes 通过 flatten 保存 registered_at、last_status_at、last_used_at，UTC RFC 3339。registered_at 是本地首次成功确认（找回也算），不是 CA 原始创建时间；只写一次。成功认证查询/注册/找回/停用时更新状态观察和使用时间；失败、离线读取、已确认停用的本地返回不更新。AccountClock 支持 dyn 注入，默认 UTC 系统时钟。未知时间不猜测回填。

`AccountService::rotate_key(&dyn AccountRotationStore, Option<KeyAlgorithm>, Option<&AccountRecord>)` 以对象安全事务会话注入双钥持久化：stage、save、commit 全程持锁；服务负责 §7.3.5 双层 JWS 和 pending 对账。200 空 body 可确认换钥，不改变账户 URL/本地 ID/联系人。超时不重放，pending 仅用已保存新钥向原账户 URL 对账，confirmed 仅补完本地提交。400/409 的合法拒绝 problem 保留旧身份；无法证明结果时保留双钥。新钥支持统一 KeyAlgorithm 八种选择；省略算法时新轮换沿用原类型，恢复沿用已保存新钥；显式选择不得替换不匹配的暂存钥。未实现 CLI 私钥导入。

`http_client` 通过 registry 的 aster_forge_http =0.1.0-alpha.2 构造连接池，根 workspace 仅选择 json/rustls-aws-lc-rs/system-proxy，客户端显式选择 TlsBackend::Rustls，禁重定向和自动重试；保留全请求/连接超时、平台 TLS 根与默认系统代理。reqwest 仍用于 Response/Error/StatusCode/header 等公共类型，与 Forge 共享同版本；不单独打开 features，由 Forge 的 workspace 配置选择。`TransportOptions::validate` 在副作用前校验设置。

调用方创建一个 `HttpPool::default()`，通过 `pool.discover(directory_url, options).await?` 创建不同账户的 `AcmeClient`。池惰性初始化，克隆池句柄共用同一个 Forge/reqwest 客户端与连接池；每个 AcmeClient 持有池，其操作不再额外接收 HTTP 参数。请求直接借用池内客户端；User-Agent 和总期限逐请求设置，连接期限最多十秒且受更短的总期限约束，账户 nonce/directory 不共享。调用方决定池生命周期，库不创建全局单例。

## 手动 DNS-01 签发

`issuance::service::IssueService` 从已注册账户、签名器和已发现 directory 构造；`dyn IssueStore/IssueSession` 持有独立证书世代与固定密钥/CSR，`dyn ChallengeSolver` 返回待人工操作或本地 DNS 就绪。库不打印终端、不调用 DNS provider、不后台启动续期任务。CLI 的手动发布适配器询问用户，DNS crate 只做查询；DNS 预检为建议性观察，是否授权由 CA 判断。

依据 RFC 8555 §7.1.3–7.1.5、§7.4、§7.4.2、§7.5.1、§8.4：保存创建意图→newOrder 201/Location→获取授权→返回全部 TXT→就绪后空对象通知 challenge→等待授权/订单→固定 CSR finalize→processing 只轮询→valid 后 POST-as-GET 下载 PEM。原始线上模型 WireIdentifier/WireChallengeKind 归 protocol::order，客户端只拥有验证与执行语义。

CA 的订单/授权 expires 与证书 notAfter 分开处理；订单没有虚构的 expired wire 状态。恢复先观察，已过期申请不能继续验证/finalize；valid 订单允许取回已经签出的证书。newOrder 的 Location 丢失没有通用幂等恢复，不能自动再下单。challenge/finalize 的 Submitted 检查点令迟到的 pending/ready 只轮询，不自动重放。显式 fresh issue 才创建新操作。

本地证书检查包括 PEM 语法、SAN 精确集合、公钥与保存密钥一致、叶子非 CA/有效期，以及提供的相邻证书链签名；不代表建立了公众信任链，尤其不安装 staging 根。当前支持独立的 ECDSA P-256/P-384/P-521、Ed25519、RSA 2048/3072/4096/8192 证书密钥，不导入外部 CSR；ARI 续期计划、cron 触发的自动续期与多目标部署已实现；前台常驻维护已由CLI提供，外部DNS provider已通过ADPP接入，内置厂商实现与真实DNS/CA验收另计。自动续期准入和并发边界见生命周期契约。

续期计划和证书吊销的职责、持久化及失败边界见 [生命周期契约](../../docs/certificate-lifecycle.md)。ARI提供计划、显式刷新及由cron调用的`daemon run-once`；吊销保留本地文件，与订单状态独立。

证书 key_algorithm 使用公共 KeyAlgorithm 枚举，CLI -k/--key-type 默认 ecdsa-p256；定义、版本、恢复和实际密钥保持一致。RevocationReason 统一 RFC 5280 已分配代码（无7），CA 自行决定接受范围；remove-from-crl 不代表 ACME 恢复。详见生命周期契约。

0.1.0-alpha.1 提供 cert renew 单次到期/--now 提前续期，使用稳定定义、持久化 predecessor/replaces、未完成恢复和成功后 in_use 切换；常驻`daemon run`复用同一维护周期，默认60秒间隔，可由`config.daemon_interval`或`--interval`覆盖；`daemon run-once`刷新ARI建议，自动续期到期的webroot/standalone/tls_alpn/dns_persist/dns_external证书并执行已配置部署；manual验证会跳过。本地 DNS 采用建议性预检，不提供DNS跳过/force参数。对象锁集中于根 .locks/accounts、.locks/certificates与.locks/daemon，完整移除对象后清空无额外用户内容的目录，外置锁 inode 保留。

cert renew --all 提供按托管身份顺序执行的批量入口，复用同一事务及类型化结果；失败继续、人工TXT待办保存、取消停止，JSON一次汇总。未扩展账户签名算法，也不启动daemon；见生命周期契约。


## 方法与发布实现

验证材料先保存到签发检查点，再调用 `ChallengeSolver::ready` 发布；恢复时通过 `restore` 重建运行期资源，并在终态调用 `cleanup` 清理自身材料，所有路径调用 `shutdown` 回收运行期任务。

CLI已实现manual_dns、manual_http、webroot、HTTP standalone和TLS-ALPN。HTTP材料是未经哈希的key authorization，公开URL/路径由请求标识符和CA token推导；TLS-ALPN使用临时SNI/ALPN挑战监听器。本库不写webroot文件、不提示终端、不决定DNS预检是否应阻止用户操作。

临时挑战服务可实现`ChallengeSolver::restore`重建已保存的pending授权响应，包括已经通知CA的挑战；该hook不重发ack。`IssueService::run`在所有返回路径调用有界`shutdown`，与终态持久化材料`cleanup`分开；嵌入者直接丢弃运行future时必须关闭或丢弃solver。CLI HTTP standalone使用该契约；TLS-ALPN复用同一生命周期并提供TLS监听实现。

RFC错误证据与恢复：newOrder完整错误响应保存creation_failure（实际status、problem、绝对retry_at），不伪造Order invalid；创建拒绝/408或429延后/5xx未确认均不进入无URL恢复候选，不重发newOrder。finalize badCSR按实际4xx状态保存；orderNotReady明确拒绝后先查询订单，只有再次ready才提交相同CSR，轮询预算仍约束。授权invalid/deactivated/expired/revoked及选中challenge invalid保留具体problem并拒绝恢复，已valid订单仍可下载。具体RFC映射与未覆盖能力见[错误状态核对](../../docs/rfc-reference.md)。未发布finalize_rejection字段直接更新为HTTP证据结构，无旧格式兼容或用户数据回填。

## 可选预检

默认features为空。启用 `precheck` 获得 `precheck::Runner`、可注入的 `Check` 与结构化 `Report`；`precheck-http` 额外提供 `precheck::http::Http`。默认每阶段5秒，可用 `Runner::new(Duration)` 设置嵌入者预算；取消或整体执行期限到达返回中断。普通失败是报告项，本地超时保留已完成项并标记未检查项，不拒绝签发。

`Runner::run(&checker, &inputs, &execution)` 是显式调用；`IssueService::run` 不自动执行预检。HTTP检查器复用调用方HttpPool；CAA/TXT检查器由aster_acme_validation的对应feature提供，避免协议库依赖DNS解析器或CLI。


## 吊销与通用签名器

`crypto::JwsSigner`/`crypto::key::SoftwareSigningKey`共用于账户与证书密钥JWS，不保留AccountSigner/AccountKey旧名。`RevocationService::new(client, authority)`接受`revocation::authority::RevocationAuthority::{Account,CertificateKey}`，`revoke(&mut dyn RevocationSession, reason, &ExecutionContext)`只依赖精确证书target和可持久化检查点；不要求IssueSession、CSR或证书私钥导出。嵌入者可提供硬件/远程签名器和外部证书会话。

CertificateKey提交前比较签名器JWK与叶子SPKI，不以签发时的有效期/信任路径规则拒绝吊销。Account模式校验实际账户密钥/身份；外部target可无已知issuer约束，CA最终验证授权，托管CLI仍绑定原签发账户。nonce和签名准备后、发送前保存目标DER SHA-256、directory、原因及签名身份；取消/期限内未发送可恢复原检查点，发送后未知保留pending，显式重试不得改变目标/原因。完整RFC核对见[RFC参考](../../docs/rfc-reference.md#9-证书私钥吊销原文核对2026-11-14)。


预检的`Failure::Unavailable { reason }`携带检查器提供的初始化/缺失配置原因；报告保留该文字供嵌入者处理，CLI负责安全展示。`Failure`因此实现Clone而非Copy；取消、阶段预算和CA最终决定的语义保持一致，库默认仍不启用预检。

外部DNS自动发布使用 `-c dns_external --provider NAME`，Profile保存在`providers/<name>.toml`。发布计划、回执与传播等待分别推进；独立清理命令为`provider cleanup NAME`。详细配置、安全边界与恢复说明见[DNS Provider](../../docs/dns-providers.md)。
