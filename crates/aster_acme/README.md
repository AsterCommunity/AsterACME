# aster_acme

面向应用的 ACME 层。目前实现输入类型、验证方法选择、响应材料推导与可注入 solver 契约；已实现账户注册/找回/查看/停用、ES256 JWS 和账户所需 transport；已实现 manual DNS-01 签发与恢复；已实现 ARI 续期计划和账户签名证书吊销；自动 DNS 发布和 renew 执行尚未实现。

- `account`：账户服务、注册恢复、不可恢复停用、条款/EAB、对象安全的 `AccountStore` / `AccountKeyStore`。
- `crypto`：`dyn AccountSigner`、软件 P-256 密钥、JWK/thumbprint、原始 R||S ES256 JWS 和 HS256 EAB。
- `transport`：HTTPS directory、nonce 池、POST-as-GET、badNonce 限次重签、1 MiB 响应限制、超时和结构化错误。
- `identifier`：DNS/IDN 规范化、长度和通配符校验、wire identifier 与授权 wildcard 语义。
- `challenge`：已知与未知验证类型、Require/Prefer 策略、token/key authorization 和三种验证材料。
- `solver`：Send + Sync 的异步 trait，可通过 dyn 注入；prepare、wait_ready、cleanup 与版本化恢复句柄。

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

Prefer 只在开始验证时选择兼容方法，不代表失败后自动回退。未知 wire 方法保留用于诊断，不能执行。当前仅定义 solver 接口，并未内置任何可用验证实现。

调用方在 prepare 前持久化意图和 preparation ID，之后保存 receipt；同一 ID 的重试必须由 solver 对账。取消/超时不等于无副作用或清理完成；活动验证材料撤下前须核对 CA 状态。恢复句柄不存凭据，Debug 隐去资源信息。

```sh
cargo test -p aster_acme --locked
```

覆盖域名/IDN/通配符、DNS 长度边界、token 编码和长度、材料推导、方法选择组合、取消/超时及恢复数据编解码。依赖与 feature 统一从根 workspace 继承。License: MIT OR Apache-2.0.


## 账户服务边界

通过 `AccountService::new(Arc<AcmeClient>, Arc<dyn AccountStore>)` 注入存储；签名器为 `dyn AccountSigner`，具名密钥查询接口返回 `Arc<dyn AccountSigner>`。嵌入式服务可以提供数据库和外部签名器，不依赖 CLI 或文件系统。

流程先保存注册意图，使用同一密钥查找已有账户，仅在明确 accountDoesNotExist 后创建；网络超时/取消保持 pending 供后续对账。已有注册元数据不代表服务端仍 valid，每次查看会读取真实远端状态。条款由调用者显式同意，服务保存当前 directory 公布的实际 URL，URL 变化后要求重新接受；HS256 EAB 的新账户响应必须反映原绑定才确认成功。

遵守 RFC 8555 §6.2–6.7、§7.1.1–7.1.2、§7.2、§7.3–7.3.6，以及 RFC 7515/7518/7638。newAccount 使用 jwk，其他账户请求使用 kid；两者互斥。badNonce 重试直接使用错误响应 nonce；不自动重试网络超时、rateLimited、5xx 或条款交互。错误保留 problem URI、detail、instance、subproblems、扩展及 Retry-After。

Transport 不跟随重定向、默认验证系统信任的 TLS；仅显式本地测试选项允许数字 loopback HTTP。测试限额与证书信任不应通过禁用 TLS 来绕过。并发 nonce 池容量 64，响应体上限 1 MiB；账户服务的文件/分布式锁策略归存储适配。

验证记录见 [账户测试](../../docs/account-testing.md)。真实 staging 已验证注册、找回及复用，尚未运行 Pebble。

## 注册账户时发送的信息

依据 [RFC 8555 §7.3](https://www.rfc-editor.org/rfc/rfc8555#section-7.3) 和 [§7.3.1](https://www.rfc-editor.org/rfc/rfc8555#section-7.3.1)：

1. 获取 CA directory，读取 `newNonce`、`newAccount`、条款地址和 EAB 要求。
2. 在本地生成或加载 P-256 账户密钥，先持久化密钥及 pending 注册意图。
3. 获取 nonce，向 `newAccount` 发出 ES256 签名请求，payload 为 `{"onlyReturnExisting":true}`。已有账户直接复用；只有明确 `accountDoesNotExist` 才创建。
4. 创建请求的 payload 可包含 `contact`、`termsOfServiceAgreed` 和 CA 要求时的 `externalAccountBinding`。`--accept-terms` 对应布尔字段，实际条款 URL 留在本地审计元数据中。
5. CA 返回账户资源与 `Location` 账户 URL。保存为 registered；后续查询以账户 URL 作为 JWS 的 `kid`，使用空 payload 的 POST-as-GET。

示例创建 payload（外层仍需 JWS 签名）：

```json
{
  "contact": ["mailto:you@example.com"],
  "termsOfServiceAgreed": true
}
```

JWS protected header 包含 `alg=ES256`、账户公钥 `jwk`、防重放 `nonce` 和精确目标 `url`。账户名称、默认账户选择、本地路径和私钥不发给 CA。联系人在协议中可选，具体 CA 可有额外策略。EAB 使用 CA 发放的 ID 和 HMAC 秘密签出绑定对象，发送对象及 ID，不发送秘密本身。

账户不是邮箱/密码登录，身份控制依赖账户私钥。注册阶段不发送域名、CSR、证书私钥或 DNS 供应商凭据；域名属于后续订单，CSR 属于 finalize。HTTP 层会带 User-Agent，CA 也能观察请求来源 IP。

账户记录的 `contacts` 保存本地设置，`server_contacts: Option<Vec<String>>` 保存最近 CA 返回值。RFC 8555 §7.1.2 的 contact 是可选 URL 数组；响应省略不等于明确空数组，二者都不能抹除本地输入。`update_contacts` 按 §7.3.2 向原账户 URL 提交完整 contact 数组，空数组明确清空；仅 HTTP 200 和账户对象更新服务端观察。

`AccountService::deactivate` 遵守 RFC 8555 §7.3.6，仅接受已有账户 URL，不隐式恢复或创建；先保存 DeactivationState::Pending，再发送包含 status=deactivated 的 kid 签名 POST。仅 200 + deactivated 确认成功。失败/取消保持 pending，重复调用不自动重放；confirmed 返回本地结果。`inspect` 只有得到真实账户对象才解除/确认 pending；401 不作为停用证据。账户记录保留 last_status，注册阶段与远端有效性仍分开。

线上请求/响应模型集中在独立 `aster_acme_protocol`：AcmeUrl、Directory/DirectoryMeta、Problem、AccountObject、账户请求和 JWS 封装/header。调用方直接从 protocol 导入，不保留旧 transport/crypto 路径的 re-export。此 crate 保留密钥构造、签名、HTTP、nonce 和业务编排。协议请求使用 struct→JSON，不再 Map/json! 拼字段；真实路径由 CA 提供，测试验证任意路径和查询串的精确签名。

账户本地状态类型已归 core::account，注册/复用/停用/可用性通过显式 account_action 决策，不在 CLI/服务重复维护业务条件。AccountService 执行动作并在成功解析权威账户对象时集中应用观察。

AccountTimes 通过 flatten 保存 registered_at、last_status_at、last_used_at，UTC RFC 3339。registered_at 是本地首次成功确认（找回也算），不是 CA 原始创建时间；只写一次。成功认证查询/注册/找回/停用时更新状态观察和使用时间；失败、离线读取、已确认停用的本地返回不更新。AccountClock 支持 dyn 注入，默认 UTC 系统时钟。未知时间不猜测回填。

`AccountService::rotate_key(&dyn AccountRotationStore)` 以对象安全事务会话注入双钥持久化：stage、save、commit 全程持锁；服务负责 §7.3.5 双层 JWS 和 pending 对账。200 空 body 可确认换钥，不改变账户 URL/本地 ID/联系人。超时不重放，pending 仅用已保存新钥向原账户 URL 对账，confirmed 仅补完本地提交。400/409 的合法拒绝 problem 保留旧身份；无法证明结果时保留双钥。当前仅生成 ES256/P-256，不支持 CLI 导入新钥或选择其他算法。

`http_client` 通过 registry 的 aster_forge_http =0.1.0-alpha.2 构造连接池，根 workspace 仅选择 json/rustls-aws-lc-rs/system-proxy，客户端显式选择 TlsBackend::Rustls，禁重定向和自动重试；保留全请求/连接超时、平台 TLS 根与默认系统代理。reqwest 仍用于 Response/Error/StatusCode/header 等公共类型，与 Forge 共享同版本；不单独打开 features，由 Forge 的 workspace 配置选择。`TransportOptions::validate` 在副作用前校验设置。

## 手动 DNS-01 签发

`issuance::service::IssueService` 从已注册账户、签名器和已发现 directory 构造；`dyn IssueStore/IssueSession` 持有独立证书世代与固定密钥/CSR，`dyn DnsReadiness` 返回待人工操作或本地 DNS 就绪。库不打印终端、不调用 DNS provider、不后台启动续期任务。CLI 的手动发布适配器询问用户，DNS crate 只做查询；强制标志只跳过本地查询。

依据 RFC 8555 §7.1.3–7.1.5、§7.4、§7.4.2、§7.5.1、§8.4：保存创建意图→newOrder 201/Location→获取授权→返回全部 TXT→就绪后空对象通知 challenge→等待授权/订单→固定 CSR finalize→processing 只轮询→valid 后 POST-as-GET 下载 PEM。原始线上模型 WireIdentifier/WireChallengeKind 归 protocol::order，客户端只拥有验证与执行语义。

CA 的订单/授权 expires 与证书 notAfter 分开处理；订单没有虚构的 expired wire 状态。恢复先观察，已过期申请不能继续验证/finalize；valid 订单允许取回已经签出的证书。newOrder 的 Location 丢失没有通用幂等恢复，不能自动再下单。challenge/finalize 的 Submitted 检查点令迟到的 pending/ready 只轮询，不自动重放。显式 fresh issue 才创建新操作。

本地证书检查包括 PEM 语法、SAN 精确集合、公钥与保存密钥一致、叶子非 CA/有效期，以及提供的相邻证书链签名；不代表建立了公众信任链，尤其不安装 staging 根。当前支持独立的 ECDSA P-256/P-384/P-521、Ed25519、RSA 2048/3072/4096/8192 证书密钥，不导入外部 CSR；ARI 续期计划已实现；周期调度、自动续期、自动 provider 与部署未实现。

续期计划和证书吊销的职责、持久化及失败边界见 [生命周期契约](../../docs/certificate-lifecycle.md)。ARI 只提供计划及显式刷新，周期唤醒留给后续 daemon；吊销保留本地文件，与订单状态独立。

证书 key_algorithm 使用公共 CertificateKeyAlgorithm 枚举，CLI -k/--key-type 默认 ecdsa-p256；定义、版本、恢复和实际密钥保持一致。RevocationReason 统一 RFC 5280 已分配代码（无7），CA 自行决定接受范围；remove-from-crl 不代表 ACME 恢复。详见生命周期契约。
