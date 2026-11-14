# 测试与验证入口

先沿[任务路由](task-routing.md)选择相关测试。常规测试使用临时目录、loopback和mock；公网CA/真实服务操作单独验收，不把交叉编译当原生运行。

## 常用命令

```sh
cargo test -p aster_acme_cli_storage --locked issuance::deployment
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
cargo doc --workspace --no-deps --locked
python3 scripts/check-workspace-deps.py
python3 scripts/check-rust-imports.py
python3 scripts/check-tls-backend.py
python3 scripts/check-dependency-features.py
python3 -m unittest discover -s scripts/tests
python3 scripts/check-doc-links.py
python3 scripts/check-precheck-features.py
```

共享开发机资源紧张或计时测试受调度干扰时可用 `-- --test-threads=2`；记录实际失败和复测，不能把首次失败抹掉。CI矩阵以.github/workflows/ci.yml为准。

覆盖率由CI的Linux `coverage`任务收集：`cargo llvm-cov --workspace --locked --lcov --output-path coverage/rust/lcov.info`，随后发布摘要并上传Codecov（flag `rust`）。本地复现需先`rustup component add llvm-tools-preview`并安装`cargo-llvm-cov`；`coverage/`输出不入库。

## 证据记录

| 范围 | 记录 |
| --- | --- |
| 账户注册、换钥与远端交互 | [账户测试](account-testing.md) |
| 签发、文件恢复、续期、部署与平台差异 | [签发测试](issuance-testing.md) |
| 输出、panic和依赖feature | [CLI运行时测试](cli-runtime-testing.md) |

以上是带日期的验收记录，旧结果不证明当前checkout。新增测试结论注明revision/命令、平台、本地mock或外部系统边界；契约变化更新owner文档，不把每轮日志追加到架构。

预检feature矩阵独立按包构建，避免workspace feature合并隐藏缺失依赖：库默认关闭、仅runner、HTTP、DNS solver、CAA、TXT，以及CLI关闭预检均检查。脚本还验证关闭预检的库生产依赖图不包含Hickory；CLI的external DNS发布仍通过独立resolver crate使用Hickory，不受建议性precheck开关影响；Linux专用CI执行该矩阵，其他平台仍运行默认完整产品测试。

Unix原生确认终端回归：`python3 scripts/test-confirmation-terminal.py` 在PTY中验证提示/输入同一行、inquire可见答案、替换/退格、默认否，以及Esc/Ctrl-C/输入后期限校验和完整termios恢复。Linux/macOS CI执行；Windows保留原生编译和普通测试。
