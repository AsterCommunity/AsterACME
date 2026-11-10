# aster-acme

面向应用的 ACME 层。目前实现输入类型、验证方法选择、响应材料推导与可注入 solver 契约；账户、transport、issue/renew/revoke 编排尚未实现。

- `identifier`：DNS/IDN 规范化、长度和通配符校验、wire identifier 与授权 wildcard 语义。
- `challenge`：已知与未知验证类型、Require/Prefer 策略、token/key authorization 和三种验证材料。
- `solver`：Send + Sync 的异步 trait，可通过 dyn 注入；prepare、wait_ready、cleanup 与版本化恢复句柄。

依赖方向：本 crate → core / Forge 宏；DNS 实现 → 本 crate。具体供应商代码不放在此处。

```rust
use aster_acme::{challenge::{ChallengeKind, ChallengePolicy, WireChallengeKind}, identifier::DnsIdentifier};

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
cargo test -p aster-acme --locked
```

覆盖域名/IDN/通配符、DNS 长度边界、token 编码和长度、材料推导、方法选择组合、取消/超时及恢复数据编解码。依赖与 feature 统一从根 workspace 继承。License: MIT OR Apache-2.0.
