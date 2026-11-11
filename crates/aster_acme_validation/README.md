# aster_acme_validation

按验证方法组织的实现与就绪检查层，当前实现 Hickory DNS TXT 可见性检查；尚无 provider 或 DNS 写入实现。手动 TXT 提示属于 CLI，不依赖 DNS provider。

依赖 `aster_acme` 的 solver 契约；负责 zone 路由、授权范围内的 DNS 委托、TXT 多值、传播检查和清理自建记录。core 状态机不依赖本 crate。

计划按需迁入 DNSO 的供应商源码并保留 MIT 声明，重新校验签名、分页、错误与 TXT 语义，不直接依赖已废弃的 DNSO crate。不得覆盖同名 TXT RRset 或删除借用记录。

接入时由应用构造具体 solver 并注入上层；目前没有可执行示例。实现时须覆盖并发授权、共享记录、创建后崩溃对账、传播超时、委托循环与幂等清理。

```sh
cargo check -p aster_acme_validation --locked
```

依赖与 feature 统一从根 workspace 继承。License: MIT OR Apache-2.0.

`dns01::visibility::DnsVisibility` 通过 `ChallengeSolver` 边界提供系统DNS查询，TXT RR内部片段拼接、多个RR分别匹配；NXDOMAIN/缺失返回false，解析器错误返回可诊断失败，取消和deadline有效。CLI把这个观察当建议，独立限2秒，失败/缺失/超时只警告并继续CA，不再提供skip标志。它不发布、不清理DNS，也不代替CA授权。

HTTP manual/webroot的实现选择、终端确认和站点文件操作归CLI validation模块；ACME只拥有方法及协议材料。本crate当前只实现dns01/visibility，无自动provider，不添加空HTTP/TLS实现。
