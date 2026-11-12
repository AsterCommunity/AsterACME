<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/readme/asteracme-on-dark.svg" />
    <img src="assets/readme/asteracme-on-light.svg" alt="AsterACME" width="320" />
  </picture>
</p>

<p align="center">
  可嵌入的 Rust ACME 客户端与 CLI，支持账户管理、DNS/HTTP 验证及可恢复的证书签发。
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

AsterACME 以 Rust 库和命令行应用实现 ACME 账户操作与 DNS-01/HTTP-01 证书签发。用户声明证书需求，库负责创建订单、跟踪授权、提交固定 CSR、下载证书链并持久化结果；CLI 提供终端交互和本地存储。

项目正在开发，ACME 包尚未正式发布。手动签发与恢复、HTTP standalone、TLS-ALPN-01、ARI 续期计划、前台续期、证书部署和账户签名证书吊销已经实现；自动 DNS provider 与 daemon 调度仍是计划能力。

## 适用场景

- 通过手动 DNS 验证申请单域名、多 SAN 和通配符证书。
- 管理多个具名账户，每个账户绑定自己的 CA 和密钥。
- 恢复已有签发申请，继续使用原证书私钥和 CSR。
- 将协议服务嵌入应用，注入存储、签名、就绪检查和进度接口。
- 使用终端提示，或通过显式参数与结构化 JSON 编写脚本。

Webroot和standalone支持非交互前台续期；证书部署可绑定多个文件目标并在续期后自动 reload，无人值守调度尚未实现。存储适配器包含 Unix 权限策略及 Windows 继承权限策略；平台运行证据分别记录，不以交叉编译冒充 Windows 验收。

## 设计重点

- **协议有明确归属**：线上模型集中在 `aster_acme_protocol`。资源 URL 来自 CA，客户端不拼固定 ACME 路径。
- **状态决策显式可测**：纯 core 根据 CA 观察和本地提交状态返回动作，服务执行 HTTP、计时和副作用。
- **操作可以恢复**：提交 mutation 前保存意图；结果未确定时，不静默重下单或重复提交 finalize。
- **产物路径稳定**：每次申请独立保存到时间版本目录，校验完整文件集合后原子切换 `in_use`。
- **共用基础机制**：Forge HTTP、标准库文件锁、rustls 和 AWS-LC 提供传输与密码学能力，业务规则保留在 ACME。

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

添加程序要求的全部 TXT 值，同时保留无关的已有记录。同一 owner 可能需要多个值共存。确认发布后可进行最多2秒的建议性 DNS 预检；缺失、解析错误或超时只警告后继续 CA 验证，取消和总期限仍生效。

如果暂时无法完成，可以稍后继续：

```sh
aster-acme cert issue --resume example-cert --data-dir ./data
aster-acme cert list --data-dir ./data
aster-acme cert show example-cert --data-dir ./data
aster-acme cert show example-cert --verify --data-dir ./data
```

每次新的 issue 创建独立托管证书，默认名为主域名加随机后缀，碰撞时自动换串重试；显式 -n/--name 必须尚未使用。cert.toml 保存域名集合、账户、CA、验证方式等稳定定义，后续续期版本沿用该名称。--resume 继续已有操作。list/show 默认围绕 in_use，list --history 展开版本，show --history 或 --operation 查看具体历史；只有 in_use 的续期计划参与活跃调度。

不带名称的 `cert show` 会在终端引导选择。列举和查看证书不会推进验证或签发。过期申请仍可见，但不能继续验证或提交 finalize。

## 验证实现

| `-c/--challenge` | 协议 | 行为 |
| --- | --- | --- |
| `manual_dns` | DNS-01 | 自行添加 TXT；本地 DNS 预检最多2秒且只作建议 |
| `manual_http` | HTTP-01 | 按保存的 URL、文件路径及内容部署，随后恢复 |
| `webroot` | HTTP-01 | 在现有 HTTP 服务器的网站根目录发布并清理拥有的文件 |
| `standalone` | HTTP-01 | 临时监听挑战请求，默认 `0.0.0.0:80` |
| `tls_alpn` | TLS-ALPN-01 | 临时提供域名挑战证书，默认监听 `0.0.0.0:443` |

```sh
aster-acme cert issue -d example.com -c manual_http
aster-acme cert issue --resume example.com-xxxxxxxx --yes
aster-acme cert issue -d example.com -c webroot --webroot /srv/www
aster-acme cert issue -d example.com -c standalone
aster-acme cert issue -d example.com -c standalone --listen-address 0.0.0.0:8080
aster-acme cert issue -d example.com -c tls_alpn
```

HTTP/TLS-ALPN 不支持通配符；manual_http/webroot 须通过现有服务器为全部 SAN 在公网80端口提供验证路径。webroot 需要同目录 hard-link 支持；不覆盖已有不同内容，不删除借用或被用户修改/替换的文件。规范绝对路径及配置持久化，恢复/续期沿用。只为新文件/目录设置Unix 0644/0755，已有站点权限不变，Windows沿用继承权限。

未显式设置新名称时，终端会在生成密钥前提示是否恢复完整匹配的未完成申请。脚本默认停止并给出恢复命令；`--if-similar-order` 在唯一匹配时恢复、零匹配时新建、多个匹配时报错。匹配完整域名集合、账户/CA、方法/配置及密钥类型。newOrder结果未确认的记录也会提示，但没有保存Location就不会自动重发；`--name <NEW_NAME>` 明确创建独立身份。

删除DNS跳过/force参数。DNS预检不代替CA决定；用户取消、总期限和CA过期照常生效。DNS-PERSIST及自动CNAME委托仍未实现。

TLS-ALPN在本地443端口使用RFC 8737临时挑战证书，只有SNI匹配且协商`acme-tls/1`时才提供；证书包含单一域名SAN和critical `acmeIdentifier`扩展，临时私钥与申请证书私钥分离。公网443须转发至监听器并保留原SNI，恢复时重建挑战响应但不重复ack。

### HTTP standalone

Standalone只响应当前HTTP-01挑战对应的Host/path GET，不写验证文件。TLS-ALPN使用RFC 8737临时挑战证书和`acme-tls/1` ALPN；两种监听地址都持久化并在恢复/续期沿用，终态均关闭。公网入口分别须是80/443，转发须保留原Host/SNI。端口占用/权限不足明确失败，不替换其他服务器。INFO显示实际监听启动/停止，DEBUG说明转发要求。

## 证书密钥算法

`-k/--key-type` 支持 ecdsa-p256（默认）、ecdsa-p384、ecdsa-p521、ed25519、rsa-2048、rsa-3072、rsa-4096、rsa-8192。这是客户端生成能力，是否接受由 CA 决定。选项持久化并在恢复和续期版本中沿用，账户签名独立选择，使用同一密钥算法枚举。issue 进度及 list/show 同时显示实际类型。

## 续期计划与吊销

签发后立即尝试获取 ARI，在建议窗口内随机选时并保存；不可用时，有效期至少 10 天以经过三分之二为目标，较短证书以经过一半为目标，再在目标前一天内随机选择。窗口下界不会早于本地生成计划的时刻；若目标已过，则安排立即续期。按 `Retry-After` 保存重查期限，临时错误有限退避，刷新失败保留已有计划。`cert list/show` 显示计划；`show --verify` 刷新到期 ARI。cert renew 已支持单次到期续期（--now 提前），批量使用 cert renew --all，按托管名称顺序执行，保留人工 TXT 待办，单项失败继续并输出一次汇总。--all 与名称互斥；JSON 只输出一个报告，存在失败退出1，取消退出130。周期唤醒留给后续 daemon。

使用 `cert deploy add CERT_NAME -n DEPLOY_NAME` 为一张证书绑定多个部署目标。目录目标会发布标准四个 PEM 文件，也可通过 --cert-path/--key-path/--ca-path/--fullchain-path 独立指定任意文件，给什么路径就发布什么。部署名通过可选 -n/--name 设置，脚本缺省在锁内自动生成，终端先提示可确认/修改的默认名称；裸 add 可交互选择证书和输入目录，reload 留空只发布文件。Reload 命令按 executable 与 argv 执行，不经 shell。签发和续期成功后自动发布到已配置目标并执行有界 reload；使用 `cert deploy list CERT_NAME` 列表和 `cert deploy show CERT_NAME DEPLOY_NAME` 查看完整配置及保存状态，检查失败/不确定的 reload 后可用 `cert deploy run CERT_NAME -n DEPLOY_NAME` 重试。

`cert deploy update CERT_NAME -n DEPLOY_NAME` 只保存指定配置，不发布或reload，`--clear-reload` 可关闭reload。Unix的add/update支持 `--file-mode 0644 --key-mode 0640`（缺省均0600），Windows继承权限。目标不能与其他绑定或托管状态重叠。Reload展示标注目标/次数/输出流的stdout/stderr，每路每次最多64KiB，JSON通过结构化事件返回。单目标失败后继续其余目标并退出非零；文件逐一替换，整组原子切换尚未实现。

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

命令带 `--debug` 可查看安全的检查点和HTTP状态/耗时，不输出正文、私钥或nonce值。JSON模式不混入人类诊断；debug不能补回之前已丢失的newOrder Location。

订单轮询由 `--max-polls`（默认30，范围1–1000）和总超时共同限制；每轮显示次数，等待注明CA `Retry-After`或本地轮询间隔。达到上限保留申请供恢复。HTTP人工/webroot共用HTTP池做最多2秒的建议性内容预检，失败或跳转只警告，继续交给CA验证。

本地轮询默认5秒；config的`poll_interval`或`--poll-interval <SECONDS>`可覆盖（1–300秒），CLI > 配置 > 内置。有效CA Retry-After仍优先；适用于issue/resume及每份证书renew（含--all），配置缺省不写回也能使用5秒。

Webroot在INFO逐项显示文件发布/清理路径，--debug显示根目录到URL映射供配置服务器。invalid订单保留CA problem供查看，不能继续恢复。

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
| `--json` | 结构化输出，不弹交互、不输出颜色和人类进度日志。 |
| `--verify` | 显式查询已有资源的 CA 状态；默认查看仍离线。 |

首次自动化手动 DNS 申请，即使带 `--yes`，仍先给出新 TXT 待办，发布后再恢复。`--yes` 不猜测缺失输入。HTTP 的 `--request-timeout`、前台执行的 `--operation-timeout` 与 CA 过期时间分别生效。完整参数范围与短参数见 [CLI 参数契约](docs/cli-contract.md)。

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

CLI 接入已发布 Forge panic alpha.2，私有 `<data-dir>/crash.log` 移除原始 panic payload，屏幕只给安全的人类/JSON 诊断；正常命令及 help/version 不创建崩溃文件，panic 不重试 ACME 修改。CI 检查实际生产 feature，禁止未经审查的 TLS、密码、HTTP、交互及日志功能。

```sh
python3 scripts/check-workspace-deps.py
python3 scripts/check-tls-backend.py
python3 scripts/check-dependency-features.py
python3 -m unittest discover -s scripts/tests
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

新申请终端缺少 -c/--challenge 时交互选择验证方式；脚本必须显式指定，不自动默认选择；恢复及续期沿用保存方式，不允许覆盖。--yes自动接受全部操作确认，不补填输入或跳过验证，条款同意仍独立。

裸 `cert issue` 在终端先输入域名，再选择 manual_dns/manual_http/webroot/standalone/tls_alpn；webroot 输入现有目录，standalone/TLS-ALPN 输入监听地址（默认0.0.0.0:80/443）。显式参数跳过提示，通配符只提供DNS方式，非TTY/JSON缺少必需输入在初始化配置/密钥/网络前报错。
