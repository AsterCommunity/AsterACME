# aster_acme_core

纯状态机内核：ACME 账户、订单、授权和 challenge 的服务端状态，以及本地签发/准备/清理阶段。根据当前观察返回下一步动作，实际动作由上层执行。

- `account`：注册/复用、停用及可用账户选择的显式纯决策；本地注册与停用意图、CA 观察驱动的状态转换。
- `protocol`：保留未知值的资源状态枚举，使用 Forge 的 `wire_enum!`。
- `machine`：订单、授权及 challenge 的纯推进决策。未知和失败状态返回明确错误；processing 不重复提交 CSR。
- `workflow`：本地阶段，签发完成与清理完成分开记录。

不认识 DNS-01/HTTP-01/TLS-ALPN-01，不处理域名、验证材料、密码学、网络、文件或运行时。生产依赖仅为 Forge 声明式宏、Serde 与 thiserror。

```rust
use aster_acme_core::{machine::{order_action, OrderAction}, protocol::OrderStatus};

assert_eq!(order_action(&OrderStatus::Processing, &[]), Ok(OrderAction::PollOrder));
```

`order_action` 使用已获取的授权快照；尚未查询的授权不能用空列表伪装。新鲜订单状态优先于过时的本地授权状态。返回 DownloadCertificate 只代表可下载，不代表已落盘或部署。

```sh
cargo test -p aster_acme_core --locked
```

覆盖已知/未知 wire 状态、授权部分成功/失败、终态拒绝、跳跃观察及轮询动作。仍未实现网络签发。依赖只能从根 workspace 继承。License: MIT OR Apache-2.0.

账户决策返回 LookupExisting / Inspect / SendDeactivation / AlreadyDeactivated / Select；pending 停用必须对账，inactive/unknown 不能授权活跃操作。HTTP/磁盘/时间采样不进入 core。调用方 `aster_acme::AccountRecord::action` 委托纯函数，再按动作执行副作用；CA 状态观察同样应用 core 转换。
