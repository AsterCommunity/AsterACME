# aster-acme-dns

DNS-01 solver 与 DNS provider 适配层，当前仍为骨架，尚无 provider 或 DNS 写入实现。

依赖 `aster-acme` 的 solver 契约；负责 zone 路由、授权范围内的 DNS 委托、TXT 多值、传播检查和清理自建记录。core 状态机不依赖本 crate。

计划按需迁入 DNSO 的供应商源码并保留 MIT 声明，重新校验签名、分页、错误与 TXT 语义，不直接依赖已废弃的 DNSO crate。不得覆盖同名 TXT RRset 或删除借用记录。

接入时由应用构造具体 solver 并注入上层；目前没有可执行示例。实现时须覆盖并发授权、共享记录、创建后崩溃对账、传播超时、委托循环与幂等清理。

```sh
cargo check -p aster-acme-dns --locked
```

依赖与 feature 统一从根 workspace 继承。License: MIT OR Apache-2.0.
