# aster-acme-cli

AsterACME 的命令行入口，二进制名 `aster-acme`。目前仅提供帮助和版本信息，普通执行以退出码 2 明确报告尚未实现。

```sh
cargo run -p aster-acme-cli -- --help
cargo run -p aster-acme-cli -- --version
```

计划负责参数、TOML 配置、状态与密钥文件适配、输出、进度和部署 hook；订单轮询、方法选择及 DNS 清理交给库，不在 CLI 重复实现。

实现证书输出时需覆盖进程锁、私钥权限、整组产物原子发布，以及 hook 失败后的独立重试。当前尚不支持证书申请、续期或吊销。

依赖与 feature 统一从根 workspace 继承。License: MIT OR Apache-2.0.
