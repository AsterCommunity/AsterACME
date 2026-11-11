<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/readme/asteracme-on-dark.svg" />
    <img src="assets/readme/asteracme-on-light.svg" alt="AsterACME" width="320" />
  </picture>
</p>

<p align="center">
  可嵌入的 Rust ACME 客户端与 CLI，支持账户管理、手动 DNS 验证及可恢复的证书签发。
  <br />
  明确的协议状态、持久化检查点，以及可以直接部署的证书文件。
</p>

<p align="center">
  <a href="https://acme.astercosm.com"><img alt="官网" src="https://img.shields.io/badge/website-AsterACME-2563EB?style=for-the-badge"></a>
  <a href="README.md"><img alt="English README" src="https://img.shields.io/badge/README-English-E11D48?style=for-the-badge"></a>
  <a href="docs/architecture.md"><img alt="架构设计" src="https://img.shields.io/badge/architecture-overview-0F172A?style=for-the-badge"></a>
  <a href="docs/rfc-reference.md"><img alt="RFC 索引" src="https://img.shields.io/badge/ACME-RFC%208555-059669?style=for-the-badge"></a>
  <a href="CHANGELOG.zh.md"><img alt="更新日志" src="https://img.shields.io/badge/changelog-unreleased-7C3AED?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="https://github.com/AsterCommunity/AsterACME/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/AsterCommunity/AsterACME/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="rust-toolchain.toml"><img alt="Rust 1.99+" src="https://img.shields.io/badge/Rust-1.99%2B-000000?style=flat-square&amp;logo=rust"></a>
  <a href="LICENSE-MIT"><img alt="MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square"></a>
</p>

## AsterACME 是什么？

AsterACME 以 Rust 库和命令行应用实现 ACME 账户操作与手动 DNS-01 证书签发。用户声明证书需求，库负责创建订单、跟踪授权、提交固定 CSR、下载证书链并持久化结果；CLI 提供终端交互和本地存储。

项目正在开发，ACME 包尚未正式发布。手动签发与恢复、ARI 续期计划及账户签名证书吊销已经实现；自动 DNS provider、HTTP/TLS 验证、自动续期、daemon 和部署 hook 仍是计划能力。

## 适用场景

- 通过手动 DNS 验证申请单域名、多 SAN 和通配符证书。
- 管理多个具名账户，每个账户绑定自己的 CA 和密钥。
- 恢复已有签发申请，继续使用原证书私钥和 CSR。
- 将协议服务嵌入应用，注入存储、签名、就绪检查和进度接口。
- 使用终端提示，或通过显式参数与结构化 JSON 编写脚本。

无人值守的完整证书生命周期仍需要自动发布与续期，目前尚未提供。现有私有文件存储适配器支持 Unix；库的消费方可以实现其他适配器。

## 设计重点

- **协议有明确归属**：线上模型集中在 `aster_acme_protocol`。资源 URL 来自 CA，客户端不拼固定 ACME 路径。
- **状态决策显式可测**：纯 core 根据 CA 观察和本地提交状态返回动作，服务执行 HTTP、计时和副作用。
- **操作可以恢复**：提交 mutation 前保存意图；结果未确定时，不静默重下单或重复提交 finalize。
- **产物路径稳定**：每次申请独立保存到时间版本目录，校验完整文件集合后原子切换 `in_use`。
- **共用基础机制**：Forge HTTP、AsterFs 锁、rustls 和 AWS-LC 提供传输与密码学能力，业务规则保留在 ACME。

## 快速开始

### 从源码构建

使用 stable Rust 1.99 或更新版本：

```sh
git clone https://github.com/AsterCommunity/AsterACME.git
cd AsterACME
cargo build --release -p aster_acme_cli --locked
./target/release/aster-acme --help
```

也可以从本地 checkout 安装：

```sh
cargo install --path crates/aster_acme_cli --locked
```

可执行文件名为 `aster-acme`，Cargo 包名使用下划线。下文示例假设程序已加入 `PATH`。

### 注册账户

```sh
aster-acme account register default \
  --contact admin@example.com \
  --data-dir ./data
```

交互时查看并明确同意 CA 条款。默认 CA 为 Let's Encrypt 生产环境；`--ca` 还支持 `zerossl`、`google`，`--ca-directory <URL>` 可指定自定义 directory。只有所选 CA 要求 EAB 时才需要额外凭据。

```sh
aster-acme account list --data-dir ./data
aster-acme account show default --data-dir ./data
aster-acme account show default --verify --data-dir ./data
aster-acme account switch default --data-dir ./data
```

`show` 默认离线，显式 `--verify` 才查询 CA。注册、按密钥找回、联系人更新、换钥、CA 停用、本地移除分别是独立操作。删除本地文件不会停用 CA 账户，也不会吊销证书。

### 账户密钥算法

账户和证书各自选择密钥，共用上述八种选项；新账户默认 ECDSA P-256。`account rotate-key` 不传 `-k` 时沿用原类型，恢复则沿用已暂存的新钥；显式冲突拒绝。CA 接受范围各异，RFC 8555 强制 ES256、建议 Ed25519，不支持时不会静默换算法。

```sh
aster-acme account register work -k rsa-3072 --accept-terms
aster-acme account rotate-key work -k ed25519 --yes
aster-acme account show work
```

账户 TOML 和 list/show 展示实际密钥类型，JWS 对应 ES256/ES384/ES512/EdDSA/RS256；不改变独立的证书密钥选择。尚未发布：账户格式新增必需 key_algorithm，无旧格式读取或迁移。

### 申请证书

```sh
aster-acme cert issue \
  -n example-cert \
  -a default \
  -d example.com \
  -d '*.example.com' \
  -c manual_dns \
  --data-dir ./data
```

添加程序要求的全部 TXT 值，同时保留无关的已有记录。同一 owner 可能需要多个值共存。CLI 先检查本地 DNS 可见性，再通知 CA 验证；本地查询是就绪证据，授权是否有效最终由 CA 决定。

如果暂时无法完成，可以稍后继续：

```sh
aster-acme cert issue --resume example-cert --data-dir ./data
aster-acme cert list --data-dir ./data
aster-acme cert show example-cert --data-dir ./data
aster-acme cert show example-cert --verify --data-dir ./data
```

每次新的 issue 创建独立托管证书，默认名为主域名加随机后缀，碰撞时自动换串重试；显式 -n/--name 必须尚未使用。cert.toml 保存域名集合、账户、CA、验证方式等稳定定义，后续续期版本沿用该名称。--resume 继续已有操作。list/show 默认围绕 in_use，list --history 展开版本，show --history 或 --operation 查看具体历史；只有 in_use 的续期计划参与活跃调度。

不带名称的 `cert show` 会在终端引导选择。列举和查看证书不会推进验证或签发。过期申请仍可见，但不能继续验证或提交 finalize。

## 证书密钥算法

`-k/--key-type` 支持 ecdsa-p256（默认）、ecdsa-p384、ecdsa-p521、ed25519、rsa-2048、rsa-3072、rsa-4096、rsa-8192。这是客户端生成能力，是否接受由 CA 决定。选项持久化并在恢复和续期版本中沿用，账户签名独立选择，使用同一密钥算法枚举。issue 进度及 list/show 同时显示实际类型。

## 续期计划与吊销

签发后立即尝试获取 ARI，在建议窗口内随机选时并保存；不支持或首次获取失败时，默认在证书总有效期经过三分之二时续期。按 `Retry-After` 保存重查期限，临时错误有限退避，刷新失败保留已有计划。`cert list/show` 显示计划；`show --verify` 刷新到期 ARI。cert renew 已支持单次到期续期（--now 提前），批量使用 cert renew --all，按托管名称顺序执行，保留人工 TXT 待办，单项失败继续并输出一次汇总。--all 与名称互斥；JSON 只输出一个报告，存在失败退出1，取消退出130。周期唤醒留给后续 daemon。

```sh
aster-acme cert renew example-cert
aster-acme cert renew example-cert --now
aster-acme cert renew --all
aster-acme cert renew --all --now --json
aster-acme cert revoke example-cert --reason key-compromise --yes
aster-acme cert remove example-cert --history --yes
aster-acme cert remove example-cert --revoked --yes
aster-acme cert remove example-cert --all --yes
```

吊销使用绑定账户，默认需要确认；多版本必须明确选择。成功后保留本地文件，超时保留未确认状态。`cert remove` 默认精确删除一次申请；--history 清理非当前的已签发版本，--revoked 匹配已保存的吊销确认，--all 才删除整个分组。清空 in_use 不自动切回旧版本，不访问 CA，仅保留非 AsterACME 管理的文件，无其他内容时删除证书目录。详见 [续期与吊销契约](docs/certificate-lifecycle.md)。

## 脚本与确认

```sh
# 首次执行返回 status=action_required 的 JSON，以及需要添加的 TXT。
aster-acme cert issue -n script-cert -d example.com -c manual_dns --json --data-dir ./data

# 发布 TXT 后恢复，不再询问人工确认。
aster-acme cert issue --resume script-cert --yes --json --data-dir ./data
```

`action_required` 正常退出，但不代表证书已经签出；脚本需要检查 JSON 的 `status`。

| 参数 | 语义 |
| --- | --- |
| `-y`、`--yes` | 确认当前命令的操作；证书恢复时跳过 TXT 发布确认。不关闭名称选择，不代替同意条款，不跳过 DNS 检查。 |
| `--accept-terms` | 注册时明确同意所选 CA 当前公布的条款。 |
| `--skip-dns-check` | 只跳过本地 DNS 可见性检查；CA 验证、过期判断、产物校验照常执行。 |
| `--json` | 结构化输出，不弹交互、不输出颜色和人类进度日志。 |
| `--verify` | 显式查询已有资源的 CA 状态；默认查看仍离线。 |

首次自动化手动 DNS 申请，即使带 `--yes` 和 `--skip-dns-check`，仍先给出新 TXT 待办，发布后再恢复。`--yes` 不猜测缺失输入。HTTP 的 `--timeout`、前台执行的 `--wait-timeout` 与 CA 过期时间分别生效。完整参数范围与短参数见 [CLI 参数契约](docs/cli-contract.md)。

## 数据与证书文件

统一用 `--data-dir` 覆盖存储根。未指定时，使用 `com.astercosm.acme` 对应的平台配置目录。首次自动生成 `config.toml`，不提供独立 `--config` 路径。

```text
<data-dir>/
├── config.toml
├── .locks/{accounts,certificates}/<name>.lock
├── accounts/<name>/
│   ├── account.toml
│   └── account-key.pk8
└── certs/example-cert/
    ├── cert.toml
    ├── in_use -> 20261111T010851Z-9YowFEL2/
    └── 20261111T010851Z-9YowFEL2/
        ├── operation.toml
        ├── private-key.pk8
        ├── request.der
        ├── material.sha256
        ├── fullchain.pem
        ├── cert.pem
        ├── ca.pem
        └── private-key.pem
```

部署读取 `in_use/fullchain.pem`、`in_use/cert.pem`、`in_use/ca.pem`、`in_use/private-key.pem`。PEM 与内部 DER 是同一把证书私钥，与账户密钥独立。`ca.pem` 仅保存 CA 返回链中叶子以外的部分；只返回叶子时为空，客户端不自行追加或安装根证书。

新申请失败时，已有版本仍可使用。额外用户文件会保留，正确性检查只针对托管记录和产物。尚未发布的格式直接演进，不增加兼容读取或自动迁移。

## 项目结构

| crate | 职责 |
| --- | --- |
| [`aster_acme_core`](crates/aster_acme_core/README.md) | 纯资源状态与工作流决策，不执行网络、文件或运行时操作。 |
| [`aster_acme_protocol`](crates/aster_acme_protocol/README.md) | 线上资源、请求、Problem、JWS 封装和 CA directory。 |
| [`aster_acme`](crates/aster_acme/README.md) | 账户与签发编排、签名、transport、标识符和适配器契约。 |
| [`aster_acme_validation`](crates/aster_acme_validation/README.md) | 按验证方法组织实现，目前提供 DNS TXT 可见性检查。 |
| [`aster_acme_cli_storage`](crates/aster_acme_cli_storage/README.md) | 私有文件、锁、版本化 TOML、固定密钥/CSR 和产物切换。 |
| [`aster_acme_cli`](crates/aster_acme_cli/README.md) | 参数、交互、报告、渲染和进程退出行为。 |

各 crate 独立维护自身版本。所有依赖版本、来源和 features 仅在根 `workspace.dependencies` 定义，成员通过 `workspace = true` 领取。

## 开发与验证

仓库策略检查需要 Python 3.11+。release 使用体积优化 `opt-level="z"`、LTO、单 codegen unit、unwind panic，并剥离调试信息而保留函数符号。

```sh
python3 scripts/check-workspace-deps.py
python3 scripts/check-tls-backend.py
cargo fmt --all --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
```

本地测试使用 loopback CA、真实签名和文件存储，覆盖重启、取消、过期及失败边界。常规检查不访问公网 CA；真实 staging 验收与本地证据分开记录。

- [官网](https://acme.astercosm.com)
- [架构设计](docs/architecture.md)
- [RFC 索引](docs/rfc-reference.md)
- [账户测试与 staging 记录](docs/account-testing.md)
- [签发测试与能力边界](docs/issuance-testing.md)
- [CLI 参数契约](docs/cli-contract.md)
- [中文更新日志](CHANGELOG.zh.md) / [English changelog](CHANGELOG.md)

## 许可

可以选择 [MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE) 许可。

除非明确另行说明，有意提交并纳入本项目的贡献同样采用上述双许可。

新申请必须显式 -c/--challenge，不默认选择验证方式；恢复及续期沿用保存方式，不允许覆盖。--yes自动接受全部操作确认，不补填输入或跳过验证，条款同意仍独立。
