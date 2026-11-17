# 测试与验证入口

先沿[任务路由](task-routing.md)选择相关测试。常规测试使用临时目录、loopback和mock；公网CA/真实服务操作单独验收，不把交叉编译当原生运行。

## 常用命令

进程生命周期机制的完整平台边界测试位于 AsterForge：`cargo test --locked -p aster_forge_process --all-targets`，Linux/macOS/Windows CI 原生执行。ACME 侧运行 `cargo test --locked -p aster_acme_dns_adpp --all-targets` 验证协议错误、清理失败优先级、启动前/后取消与副作用分类；CLI 的 `commands::cert::deployment::reload::tests` 验证清理不确定不会变成成功或自动超时重试。macOS alpha.3 的保守清理失败边界见[运行时设计](design/runtime.md#reload进程)。

```sh
cargo test -p aster_acme_cli_storage --locked issuance::deployment
cargo test -p aster_acme_dns --locked
cargo test -p aster_acme_dns_builtin --features cloudflare --locked
cargo test -p aster_acme_dns_http --locked
cargo test -p aster_acme_cli_storage --locked provider_publication
cargo check --workspace --locked
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

共享开发机资源紧张或计时测试受调度干扰时可用 `-- --test-threads=2`；记录实际失败和复测，不能把首次失败抹掉。CI矩阵以.github/workflows/ci.yml为准：仅 `main` 的 push 和目标为 `main` 的 PR 触发；同一 PR 或同一分支的新运行取消旧运行，避免功能分支同时运行 push/PR 两套检查。

证书报告的字节级回归用例位于 `crates/aster_acme_cli/src/commands/cert/render/tests/contract.rs`，快照来自模块拆分前的 `26ef130`，覆盖文本、颜色和 JSON 输出以及对应退出状态；ActionRequired 文本提示有意追加精确 `--operation`，对应两项基准已定点更新。预期路径仅按宿主路径分隔符适配，不修改实际输出；报告有意变更时应先核对 [CLI 契约](cli-contract.md)，不要在结构重构中重新生成快照掩盖差异。

覆盖率由CI的Linux `coverage`任务收集：`cargo llvm-cov --workspace --locked --lcov --output-path coverage/rust/lcov.info`，随后发布摘要并上传Codecov（flag `rust`）。本地复现需先`rustup component add llvm-tools-preview`并安装`cargo-llvm-cov`；`coverage/`输出不入库。

## 证据记录

| 范围 | 记录 |
| --- | --- |
| 账户注册、换钥与远端交互 | [账户测试](account-testing.md) |
| 签发、文件恢复、续期、部署与平台差异 | [签发测试](issuance-testing.md) |
| 输出、panic和依赖feature | [CLI运行时测试](cli-runtime-testing.md) |

以上是带日期的验收记录，旧结果不证明当前checkout。新增测试结论注明revision/命令、平台、本地mock或外部系统边界；契约变化更新owner文档，不把每轮日志追加到架构。

预检feature矩阵独立按包构建，避免workspace feature合并隐藏缺失依赖：库默认关闭、仅runner、HTTP、DNS solver、CAA、TXT，以及CLI关闭预检均检查。脚本还独立运行 validation 各 feature 的库测试，并验证关闭预检的库生产依赖图不包含Hickory、空 validation 不包含 Tokio/tokio-util；CLI的external DNS发布仍通过独立resolver crate使用Hickory，不受建议性precheck开关影响；Linux专用CI执行该矩阵，其他平台仍运行默认完整产品测试。

Unix原生确认终端回归：`python3 scripts/test-confirmation-terminal.py` 在PTY中验证提示/输入同一行、可见答案、光标/删除/退格、大小写、非法输入与长度上限、默认否，以及不发送任何按键时的deadline/外部取消/shutdown和完整termios恢复。Linux/macOS CI执行；Windows保留原生编译和普通测试。

Provider 原生终端回归：`python3 scripts/test-provider-terminal.py` 在 PTY 中验证 add/show/cleanup/remove/update 和签发 Profile 选择、搜索、颜色与 NO_COLOR、默认否/取消、update 保存/丢弃草稿、子菜单返回并保留草稿及 termios 恢复，不执行真实 Provider 或访问 CA；Linux/macOS CI 同步执行。

DNS 后端测试包括：registry 重复/未知 ID、编译 feature 集合、写请求前 checkpoint 确认、失败与部分结果、HTTP 精确字节/禁重试/禁重定向/收发上限/取消期限、Cloudflare 分页/同值所有权/错误脱敏/丢响应恢复/精确删除，以及条件 RRset 冲突重读、metadata 保留和不确定所有权。CLI loopback 测试使用真实 Cloudflare 状态机、实际文件恢复存储和 ACME 服务；PTY 额外核对后端选择及敏感输入不回显。真实 DNS/CA 验收不由这些 mock 代替。
