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
