# 测试与验证入口

先沿[任务路由](task-routing.md)选择相关测试。常规测试使用临时目录、loopback和mock；公网CA/真实服务操作单独验收，不把交叉编译当原生运行。

## 常用命令

进程生命周期机制的完整平台边界测试位于 AsterForge：`cargo test --locked -p aster_forge_process --all-targets`，Linux/macOS/Windows CI 原生执行。ACME 侧运行 `cargo test --locked -p aster_acme_dns_adpp --all-targets` 验证协议错误、清理失败优先级、启动前/后取消与副作用分类；CLI 的 `commands::cert::deployment::reload::tests` 验证清理不确定不会变成成功或自动超时重试。macOS 的保守清理失败边界见[运行时设计](design/runtime.md#reload进程)。

```sh
cargo test -p aster_acme_cli_storage --locked issuance::deployment
cargo test -p aster_acme_dns --locked
cargo test -p aster_acme_dns_builtin --all-features --locked
cargo test -p aster_acme_cli --features dns-aliyun,dns-tencent-cloud,dns-huawei-cloud --locked signed_
cargo test -p aster_acme_cli --no-default-features --features dns-google-cloud-dns --locked google_
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

容器镜像在本地实际构建运行：`docker build -f docker/Dockerfile --build-arg ASTER_BUILD_REVISION=$(git rev-parse HEAD) -t aster-acme:dev .` 后，`docker run --rm aster-acme:dev version` 应报告该 revision；`docker run -d --name aster-acme-check aster-acme:dev` 后用 `docker exec aster-acme-check version`、`docker exec aster-acme-check cert --help` 验证子命令 shim，结束后 `docker rm -f aster-acme-check`。compose 示例用 `docker compose -f docker/docker-compose.yml config` 校验 schema。发布流水线的 cosign/SBOM/manifest 组合由 AsterDrive 规范约束，本地不重放。

证书报告的字节级回归用例位于 `crates/aster_acme_cli/src/commands/cert/render/tests/contract.rs`，快照来自模块拆分前的 `26ef130`，覆盖文本、颜色和 JSON 输出以及对应退出状态；ActionRequired 文本提示有意追加精确 `--operation`，对应两项基准已定点更新。预期路径仅按宿主路径分隔符适配，不修改实际输出；报告有意变更时应先核对 [CLI 契约](cli-contract.md)，不要在结构重构中重新生成快照掩盖差异。

覆盖率由 CI 的 Linux `coverage` 任务收集：先用 `cargo llvm-cov --workspace --all-features --locked --no-fail-fast --no-report` 运行普通测试，再在相同 `CARGO_TARGET_DIR` / `CARGO_LLVM_COV_TARGET_DIR` 中追加下文的账户与 PKCS#12 PTY 数据，最后以独立步骤运行 `cargo llvm-cov report --lcov --output-path coverage/rust/lcov.info` 导出合并报告，发布摘要并上传 Codecov（flag `rust`）。本地复现需先`rustup component add llvm-tools-preview`并安装`cargo-llvm-cov`；`coverage/`输出不入库。

## 证据记录

| 范围 | 记录 |
| --- | --- |
| 账户注册、换钥与远端交互 | [账户测试](account-testing.md) |
| 签发、文件恢复、续期、部署与平台差异 | [签发测试](issuance-testing.md) |
| 输出、panic和依赖feature | [CLI运行时测试](cli-runtime-testing.md) |

以上是带日期的验收记录，旧结果不证明当前checkout。新增测试结论注明revision/命令、平台、本地mock或外部系统边界；契约变化更新owner文档，不把每轮日志追加到架构。

预检feature矩阵独立按包构建，避免workspace feature合并隐藏缺失依赖：库默认关闭、仅runner、HTTP、DNS solver、CAA、TXT，以及CLI关闭预检均检查。脚本还独立运行 validation 各 feature 的库测试，并验证关闭预检的库生产依赖图不包含Hickory、空 validation 不包含 Tokio/tokio-util；CLI的external DNS发布仍通过独立resolver crate使用Hickory，不受建议性precheck开关影响；Linux专用CI执行该矩阵，其他平台仍运行默认完整产品测试。

Unix原生确认终端回归：`python3 scripts/test-confirmation-terminal.py` 在PTY中验证提示/输入同一行、可见答案、光标/删除/退格、大小写、非法输入与长度上限、默认否，以及不发送任何按键时的deadline/外部取消/shutdown和完整termios恢复。Linux/macOS CI执行；Windows保留原生编译和普通测试。

PKCS#12 原生终端回归：`python3 scripts/test-deployment-terminal.py` 验证隐藏密码与确认输入、取消零发布/零配置修改、JSON 不提示和 termios 恢复；Linux/macOS CI 执行。coverage 任务先运行普通测试保留 LLVM 数据，再通过 `cargo llvm-cov show-env --sh` 设置相同插桩环境，执行 PTY 驱动，最后导出合并报告，避免独立执行的终端测试遗漏于覆盖率。账户与部署驱动均可用 `--binary PATH` 复用已经插桩的测试程序；默认自行查找测试程序，子进程继承覆盖率环境。普通 Rust 测试不依赖 crate 归档之外的仓库脚本。密码来源、编码、解密、权限与自动部署的普通测试分别归 cli_storage 和 CLI deployment 模块。OpenSSL 互通使用手动验收，不引入自动测试依赖。

Provider 原生终端回归：`python3 scripts/test-provider-terminal.py` 在 PTY 中验证 add/show/cleanup/remove/update 和签发 Profile 选择、搜索、颜色与 NO_COLOR、默认否/取消、update 保存/丢弃草稿、子菜单返回并保留草稿及 termios 恢复，不执行真实 Provider 或访问 CA；Linux/macOS CI 同步执行。

账户条款原生终端回归：`python3 scripts/test-account-terminal.py` 使用 loopback CA、真实账户文件和 inquire 提示，覆盖 5 个注册与 19 个 update 场景。注册验证 `--yes --accept-terms` 不等待未来授权询问、显式同意、默认否、拒绝及取消；update 验证显式条款 flag 的人工确认与默认否、撤销确认同意/拒绝/取消时零 HTTP、菜单中的 `--yes` 不替代条款同意、三 scope 分别确认、拒绝/取消 profile 保留已提交联系人但不执行后续条款、profile 菜单只读取一次 directory、确认期间并发条款变更不覆盖、后续确认拒绝/取消时保留已提交 contacts/profile 的说明，以及 `crate::finish` 对拒绝或取消返回退出码 130（脚本运行 Rust 测试程序，测试子进程本身退出 0）。核对授权落盘、账户 POST 数量和 termios 恢复。Linux/macOS CI 同步执行，不访问公网 CA。

DNS 后端测试包括：registry 重复/未知 ID、编译 feature 集合、写请求前 checkpoint 确认、失败与部分结果、HTTP 精确字节/禁重试/禁重定向/收发上限/取消期限、Cloudflare 分页/同值所有权/错误脱敏/丢响应恢复/精确删除，以及条件 RRset 冲突重读、metadata 保留和不确定所有权。CLI loopback 测试使用真实 Cloudflare 状态机、实际文件恢复存储和 ACME 服务；PTY 额外核对后端选择及敏感输入不回显。真实 DNS/CA 验收不由这些 mock 代替。

阿里云与 DNSPod 的 mock 测试验证签名字节、分页、所有权和清理边界。CLI 的 `signed_rpc` 测试把真实文件 checkpoint、跨进程租约、厂商 HTTP mock 和 ACME loopback 服务组合在同一签发流程中。覆盖已持久化 ID、创建响应丢失、恢复、TTL 回读和限频下限。独立 feature 矩阵验证未启用、单厂商启用和 registry 一致性。

华为云测试对照官方 HWS GET/POST 签名向量，验证 marker 分页、TXT 引号/转义、多 publication 同 owner、意图与 ID 恢复、描述保留、最后一个值删除、变更身份拒绝、有界冲突与 pending、限频脱敏。CLI `signed_rpc` 同时覆盖华为云文件恢复、跨进程争用、丢响应和取消后的 ACME loopback 签发/清理。它证明本地契约，不证明云端 CAS 或真实厂商/公网 CA 验收。

Google Cloud DNS 的 mock 覆盖 OAuth RS256 签名/令牌过期、分页与最终 owner zone、changes 前置条件、保存 ID 后恢复、无 ID 未知提交不重放、同值拒绝、差异清理及错误脱敏。CLI `google_` 测试组合真实 publication 文件、子进程租约争用与 ACME loopback，并检查 settings 脱敏和限流下限持久化。真实 Google Cloud 项目和 CA 验收另记，不由本地测试替代。
