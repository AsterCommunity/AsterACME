# aster_acme_validation

按验证方法组织的可选 DNS 观察实现与建议性预检适配层，提供 Hickory TXT 可见性、CAA/TXT 检查器；不拥有验证方法调度、DNS 路由、provider、DNS 写入或清理。手动 TXT 提示和 webroot/临时 listener 属于 CLI。

依赖 `aster_acme` 的 solver/precheck 契约和 `aster_acme_dns` 的发布数据；ACME 库编排挑战生命周期及 DNS 路由策略，`aster_acme_dns_resolver` 提供系统 DNS adapter，CLI storage 管理 profile 与租约，`aster_acme_dns_adpp`/`aster_acme_process` 执行外部 provider。core 状态机不依赖本 crate。

构建厂商 provider 时优先实现 `aster_acme_dns::DnsProvider`，按 [ADPP](../aster_acme_dns/README.md) 保留逐记录 receipt/idempotency、CNAME routing 与 ownership cleanup；不要把 provider 凭据、写入或清理职责移入 validation crate。

```sh
cargo check -p aster_acme_validation --locked
```

依赖与 feature 统一从根 workspace 继承。License: MIT OR Apache-2.0.

`dns01::visibility::DnsVisibility` 是可注入的 `ChallengeSolver` 观察实现：TXT RR 内片段拼接、多个 RR 分别匹配；NXDOMAIN/缺失返回 false，解析器错误返回可诊断失败，取消和 deadline 有效。CLI 把观察作为独立的五秒建议，不更改 CA 授权。solver 通过 `aster_acme_dns` 发布契约发布／清理材料，visibility 本身不做写入。

HTTP manual/webroot的实现选择、终端确认和站点文件操作归CLI validation模块；ACME只拥有方法及协议材料。本crate按feature提供dns01/visibility、caa和txt，无自动provider，不添加空HTTP/TLS实现。

`caa::check` 接受可注入的递归查询接口，按 RFC 8659 逐级查找首个非空 CAA 集合；`SystemLookup` 使用系统递归 DNS 跟随别名。纯策略在 `aster_acme_core::caa`，结果分为不受限制、匹配、未匹配和未知，不控制 CA 操作。CLI 在首次 newOrder 前消费 directory 的 `caaIdentities`，所有 SAN 共享五秒建议性预算，取消和整体期限仍终止。

## Feature与嵌入

默认features为空，不带Hickory。`dns01` 提供独立DNS可见性solver；`precheck-caa` 提供CAA查询和 `caa::Caa` 检查器；`precheck-dns` 提供 `txt::Txt` 检查器。后两者启用aster_acme的通用precheck执行器，不启用HTTP检查器。

CAA可注入 `Lookup`（或使用SystemLookup）；TXT可用 `Txt::new(resolver)` 注入应用DNS配置，或 `Txt::system()` 使用系统DNS。调用方显式执行 `Runner::run` 并自行处理报告，不会自动创建订单、修改DNS或运行CLI。

完整可编译示例见 [caa_precheck.rs](examples/caa_precheck.rs)。`cargo run -p aster_acme_validation --example caa_precheck --features precheck-caa` 会显式查询DNS，不会联系ACME CA；自动测试仅编译示例，不执行公网查询。


`txt::Txt` 同时接受 DNS-01 及实验性 DNS-PERSIST-01 材料，分别查询 `_acme-challenge` 和 `_validation-persist` 的逻辑 TXT 值；只拼接同一 RR 的字符片段，不拼接不同 RR。观察不修改或删除长期记录，也不把本地可见性当作 CA 授权。DNS Persist 规范版本与部署限制见 [RFC参考](../../docs/rfc-reference.md#dns-persist-草案实现2026-11-14)。


## 系统解析器初始化诊断

`resolver::system`统一构建系统解析器；`InitializationError::{SystemConfiguration,Build}`保留阶段、底层错误文字和`Error::source()`。`Txt::system()`和`SystemLookup::new()`返回此类型，独立DNS可见性solver也使用同一入口。初始化不执行查询，未增加DNS回退、地址重写或Hickory源码修改。

CAA在通用预检报告的`Failure::Unavailable { reason }`里保留初始化原因；CA未广告`caaIdentities`则给出独立原因。CLI转义后展示实际文字，普通失败继续CA验证，取消/整体期限仍停止。Hickory 0.26.3的macOS系统地址解析不接受带接口标识的IPv6地址时，当前行为是如实诊断后跳过建议性预检，该兼容问题未在本项目中修补。
