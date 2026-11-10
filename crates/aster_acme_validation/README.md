# aster_acme_validation

按验证方法组织的实现与就绪检查层，当前实现 Hickory DNS TXT 可见性检查；尚无 provider 或 DNS 写入实现。手动 TXT 提示属于 CLI，不依赖 DNS provider。

依赖 `aster_acme` 的 solver 契约；负责 zone 路由、授权范围内的 DNS 委托、TXT 多值、传播检查和清理自建记录。core 状态机不依赖本 crate。

计划按需迁入 DNSO 的供应商源码并保留 MIT 声明，重新校验签名、分页、错误与 TXT 语义，不直接依赖已废弃的 DNSO crate。不得覆盖同名 TXT RRset 或删除借用记录。

接入时由应用构造具体 solver 并注入上层；目前没有可执行示例。实现时须覆盖并发授权、共享记录、创建后崩溃对账、传播超时、委托循环与幂等清理。

```sh
cargo check -p aster_acme_validation --locked
```

依赖与 feature 统一从根 workspace 继承。License: MIT OR Apache-2.0.

`dns01::visibility::DnsVisibility` 实现 `dyn DnsReadiness`，用系统 recursive resolver 查询每个 TXT owner，拼接同一 RR 内的字符片段、匹配完整值，保留同名多条 TXT 共存语义。NXDOMAIN/缺失预期值返回未就绪，网络错误返回可诊断失败。取消和执行 deadline 包含查询等待；force 在任何 DNS 初始化/查询前返回就绪，但仍检查取消/deadline。它不发布、不清理记录，也不能代替 CA 验证或证明公网传播完毕。

当前模块为 dns01/visibility；未来 HTTP-01、TLS-ALPN-01 分别归 http01、tls_alpn01，不添加空实现。manual_dns 的终端发布提示不进入本 crate。CLI 仅使用 -c manual_dns，ACME wire 方法由实现内部确定。
