# aster_acme_core

纯状态机内核：ACME 账户、订单、授权和 challenge 的服务端状态，以及本地签发/准备/清理阶段。根据当前观察返回下一步动作，实际动作由上层执行。

- `account`：注册/复用、停用及可用账户选择的显式纯决策；本地注册与停用意图、CA 观察驱动的状态转换。
- `protocol`：保留未知值的资源状态枚举，使用 Forge 的 `wire_enum!`。
- `machine`：订单、授权及 challenge 的纯推进决策。未知和失败状态返回明确错误；processing 不重复提交 CSR。
- `caa`：RFC8659/RFC8657的纯建议性策略评估，不进行DNS查询，不决定CA能否签发。
- `workflow`：本地阶段，签发完成与清理完成分开记录。

不执行 DNS-01/HTTP-01/TLS-ALPN-01，不处理验证材料、密码学、网络、文件或运行时。生产依赖仅为 Forge 声明式宏、Serde 与 thiserror。

```rust
use aster_acme_core::{machine::{order_action, OrderAction}, protocol::OrderStatus};

assert_eq!(order_action(&OrderStatus::Processing, Some(&[]), aster_acme_core::workflow::SubmissionState::NotSubmitted), Ok(OrderAction::PollOrder));
```

`order_action` 以 None 表示未刷新的授权，Some(&[]) 才表示明确获取到空集合；不能用空列表伪装未查询的资源。新鲜订单状态优先于过时的本地授权状态。返回 DownloadCertificate 只代表可下载，不代表已落盘或部署。

```sh
cargo test -p aster_acme_core --locked
```

覆盖已知/未知 wire 状态、授权部分成功/失败、终态拒绝、跳跃观察及轮询动作。网络签发由上层 aster_acme 编排，此 crate 不执行 I/O。依赖只能从根 workspace 继承。License: MIT OR Apache-2.0.

账户决策返回 LookupExisting / Inspect / SendDeactivation / AlreadyDeactivated / Select；pending 停用必须对账，inactive/unknown 不能授权活跃操作。HTTP/磁盘/时间采样不进入 core。调用方 `aster_acme::AccountRecord::action` 委托纯函数，再按动作执行副作用；CA 状态观察同样应用 core 转换。

账户 Update/RotateKey 也由纯决策驱动；轮换 Pending 只允许 ReconcileKeyChange、Confirmed 只允许 FinalizeKeyChange，并阻止其他活跃操作/远端观察。Inspect 独立于注册资格，允许对停用意图做权威查询；不绕过轮换的双钥恢复。Core 不持有密钥或决定文件事务。

`SubmissionState::NotSubmitted/Submitted` 是本地持久化通知意图，区别于 CA 状态。order_action 接收 finalize 提交状态，ready + Submitted 返回 PollOrder；challenge_action 接收 acknowledgement 状态，pending + Submitted 返回 PollChallenge。只有未提交的动作允许上层保存意图后通知 CA，不能根据仍未变化的远端状态重放 mutation。

续期计划和证书吊销的职责、持久化及失败边界见 [生命周期契约](../../docs/certificate-lifecycle.md)。ARI提供计划、显式刷新及由cron调用的`daemon run-once`；吊销保留本地文件，与订单状态独立。

0.1.0-alpha.1 提供 cert renew 单次到期/--now 提前续期，使用稳定定义、持久化 predecessor/replaces、未完成恢复和成功后 in_use 切换；常驻调度未实现，`daemon run-once`刷新ARI建议，自动续期到期的webroot/standalone/tls_alpn证书并执行已配置部署；manual验证会跳过。本地 DNS 采用最多2秒的建议性预检，不提供DNS跳过/force参数。对象锁集中于根 .locks/accounts 与 .locks/certificates，完整移除对象后清空无额外用户内容的目录，外置锁 inode 保留。
