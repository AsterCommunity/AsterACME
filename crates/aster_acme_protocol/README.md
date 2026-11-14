# aster_acme_protocol

ACME 线上协议契约，独立于 HTTP、密码学实现、文件系统和运行时。

- `url`：保留 CA URL 的精确字符串，校验 scheme、凭据和 fragment。
- `directory`：公开生产提供商 Provider、统一目录 URL 注册表，以及 CA 提供的 `newNonce` / `newAccount` 端点与元数据。
- `account`：账户创建、只读找回、状态更新请求和 CA 账户响应。
- `jws`：flattened JWS、互斥 jwk/kid header、无 nonce 的 EAB header。
- `problem`：标准错误标识及保留扩展字段的 problem 文档。

依赖 core 的状态枚举；core 不反向依赖本 crate。密钥、签名、nonce 池、重试和账户持久化仍由 `aster_acme` 及适配器负责。CLI JSON 是产品展示契约，保留在 CLI 的类型化 output 模块。

请求通过具名结构体序列化为 JSON，不用 `json!` 或 Map 拼业务字段。可选字段按规范省略，账户 contact 缺省与空列表保持区别。EAB 的确认响应使用具名对象反序列化并比较绑定。

ACME 没有固定的 `/account` 路径：请求使用 directory、Location 或资源响应提供的 URL，不按主机拼接路径、不重新编码签名 URL。当前只声明已经实现的账户协议字段，订单与证书契约随对应能力加入。

```sh
cargo test -p aster_acme_protocol --locked
```

MIT OR Apache-2.0.

公开提供商定义与入口地址由本 crate 的 directory::Provider 唯一持有，CLI 只通过 TypedValueParser 适配 Clap，配置直接反序列化 Provider。protocol 不依赖 Clap，不包含测试环境预设。

账户更新的 AccountUpdateRequest 与 §7.3.5 的泛型 KeyChangePayload / KeyChangeHeader 是独立线上模型；目录 key_change 可缺省。内层 header 不具备 nonce/kid 字段；FlattenedJws 本身就是外层 payload，不添加仅透传的包装类型。签名与文件事务留在上层。

`order` 拥有 RFC 8555 订单、授权和 challenge 模型，以及 NewOrderRequest、FinalizeRequest 和空对象 AcknowledgeRequest；DNS 标识符线上类型和 WireChallengeKind 从客户端直接迁入此处，不保留转发导出。Directory.new_order 从 CA 获取；所有资源使用发现的 URL。expires 严格解析 RFC3339，缺省是否合法由客户端按资源状态判断；证书有效期不是订单 expires。

续期计划和证书吊销的职责、持久化及失败边界见 [生命周期契约](../../docs/certificate-lifecycle.md)。ARI提供计划、显式刷新及由cron调用的`daemon run-once`；吊销保留本地文件，与订单状态独立。

证书 key_algorithm 使用公共 KeyAlgorithm 枚举，CLI -k/--key-type 默认 ecdsa-p256；定义、版本、恢复和实际密钥保持一致。RevocationReason 统一 RFC 5280 已分配代码（无7），CA 自行决定接受范围；remove-from-crl 不代表 ACME 恢复。详见生命周期契约。

ProblemKind 用 Forge wire_enum 表达 RFC8555 §6.7 的24种标准问题，未知 URI 进入 Unknown(String)，序列化仍为 URI；不保留散落的旧字符串常量。

0.1.0-alpha.1 提供 cert renew 单次到期/--now 提前续期，使用稳定定义、持久化 predecessor/replaces、未完成恢复和成功后 in_use 切换；`daemon run-once`执行一次维护，`daemon run`以前台常驻方式按配置间隔循环，默认60秒，同一data-dir由跨进程租约限制为单实例。两种模式刷新ARI建议、自动续期到期的webroot/standalone/tls_alpn/dns_persist/dns_external证书并执行已配置部署；manual验证会跳过。本地 DNS 采用建议性预检，不提供DNS跳过/force参数。对象锁集中于根 .locks/accounts、.locks/certificates与.locks/daemon，外置锁 inode 保留。


`WireChallengeKind::DnsPersist01`与`DnsPersistParameters`对应`draft-ietf-acme-dns-persist-02`。选中方法时才解码camelCase的`issuerDomainNames`，旧字段与未知扩展仍留在`ChallengeObject.parameters`，不会迫使同一授权的DNS-01执行要求新字段。`DirectoryMeta.issuer_domain_names`/`account_hash_prefix`允许缺省或不合规类型降为不可用，CAA metadata不合规时同样不可用于集合比较；是否可以预配置、issuer集合与hash prefix的语义校验归`aster_acme`，不在wire层执行DNS或账户查询。
