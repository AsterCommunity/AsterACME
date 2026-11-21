<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/readme/asteracme-on-dark.svg" />
    <img src="assets/readme/asteracme-on-light.svg" alt="AsterACME" width="320" />
  </picture>
</p>

<p align="center">
  可嵌入的 Rust ACME 客户端与 CLI，支持账户管理、DNS 与 HTTP 验证，以及可恢复的证书签发。
  <br />
  明确的协议状态、持久化检查点，以及可以直接部署的证书文件。
</p>

<p align="center">
  <a href="https://acme.astercosm.com"><img alt="官网" src="https://img.shields.io/badge/website-AsterACME-2563EB?style=for-the-badge"></a>
  <a href="https://acme.docs.astercosm.com"><img alt="文档站" src="https://img.shields.io/badge/docs-Astro_Starlight-7C3AED?style=for-the-badge&logo=astro&logoColor=white"></a>
  <a href="README.md"><img alt="English" src="https://img.shields.io/badge/README-English-E11D48?style=for-the-badge"></a>
  <a href="developer-docs/architecture.md"><img alt="架构设计" src="https://img.shields.io/badge/architecture-overview-0F172A?style=for-the-badge"></a>
  <a href="developer-docs/rfc-reference.md"><img alt="RFC 参考" src="https://img.shields.io/badge/ACME-RFC%208555-059669?style=for-the-badge"></a>
  <a href="CHANGELOG.zh.md"><img alt="更新日志" src="https://img.shields.io/badge/changelog-unreleased-7C3AED?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="https://github.com/AsterCommunity/AsterACME/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/AsterCommunity/AsterACME/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="rust-toolchain.toml"><img alt="Rust 1.99+" src="https://img.shields.io/badge/Rust-1.99%2B-000000?style=flat-square&amp;logo=rust"></a>
  <a href="LICENSE-MIT"><img alt="MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square"></a>
</p>

AsterACME 通过保存请求状态、固定密钥与 CSR，以及明确的中断恢复流程，管理证书生命周期。可以交互使用 CLI、编写脚本，也可以将 Rust 服务嵌入应用，注入自己的存储、签名器和验证适配器。

CLI 源码构建默认包含 Cloudflare、阿里云云解析 DNS、腾讯云 DNSPod 和华为云 DNS。华为云 RRset 更新无法保证与外部写入者原子隔离；嵌入式应用仍需显式选择所需 provider feature。[DNS Provider 配置](developer-docs/dns-providers.md)

**现已发布：** AsterACME `0.1.0-alpha.3` 已发布到 crates.io。这是预发布版本，Rust API 与本地格式仍可能变化。内置 Cloudflare 和 ADPP 后端已包含在统一的 DNS solver 之中，真实 DNS/公网 CA 验收另计。

## 能力

- 具名 CA 账户：注册、找回、联系人更新、换钥和停用。
- 单域名、多 SAN、通配符与 IP 地址（RFC 8738）证书，账户与证书可独立选择密钥类型。
- CA 证书 profile（draft-ietf-acme-profiles）：发现广告列表、设置账户默认或按次选择——Let's Encrypt 的 IP 标识符需要 `shortlived`。
- 保存申请后恢复、ARI 刷新、前台单次／批量续期，以及受支持验证方式的无人值守维护。
- 每张证书绑定多个部署目标，续期后自动部署，reload 有界执行并展示 stdout/stderr。
- 交互式输入、结构化 JSON、离线查看及可选 debug 诊断。

| 验证方式 | 实现 |
| --- | --- |
| DNS-01 | `dns_provider --provider NAME`：内置 DNS 或 ADPP 自动发布；`manual_dns`：手动发布 TXT，支持通配符 |
| DNS-PERSIST-01（草案 -02） | `dns_persist`：首次手动配置长期 TXT，后续续期复用；支持通配符 |
| HTTP-01 | `manual_http`、`webroot`，或临时监听 80 端口的 `standalone`；支持 DNS 与 IP 标识符 |
| TLS-ALPN-01 | 临时监听 443 端口的 `tls_alpn`；支持 DNS 与 IP 标识符 |

`dns_persist`要求CA支持[对应草案版本](developer-docs/rfc-reference.md#dns-persist-草案实现2026-11-14)。TXT保留供续期使用；它不包含DNS provider自动写入，也不表示已通过公网CA验收。

## 快速开始

通过 Homebrew 安装 CLI：

```sh
brew install astercommunity/tap/aster-acme
```

从 crates.io 安装已发布的 `0.1.0-alpha.3` CLI。若有匹配的预编译二进制，`cargo-binstall` 会优先使用；否则回退到 Cargo 源码构建：

```sh
cargo binstall aster_acme_cli@0.1.0-alpha.3
```

没有 `cargo-binstall` 时，可直接通过 Cargo 安装同一版本：

```sh
cargo install aster_acme_cli --version 0.1.0-alpha.3
```

使用 **Rust 1.99+** 从源码安装：

```sh
git clone https://github.com/AsterCommunity/AsterACME.git
cd AsterACME
cargo install --path crates/aster_acme_cli --locked
```

嵌入 Rust 库时可运行仓库自带的端到端示例——CA 发现、账户注册、嵌入方实现的 HTTP-01 webroot solver 与产物——默认指向 Let's Encrypt **staging** 并使用临时 data-dir：

```sh
cargo run -p aster_acme --example embedded_issuance -- --domain example.com --webroot /srv/www
```

[示例源码](crates/aster_acme/examples/embedded_issuance.rs)就是嵌入入口：`ChallengeSolver` 实现、存储适配器和 `AccountService`/`Workflow` 编排属于嵌入方。示例适配器只保留临时状态；实际嵌入时需提供持久存储以支持进程重启后的恢复。

不本地安装时可直接运行已发布的容器镜像（多架构；`latest` 只跟随稳定版本）：

```sh
docker run -d --name aster-acme -v aster-acme-config:/data ghcr.io/astercommunity/aster-acme:latest
```

容器默认运行维护 daemon；一次性命令用 `docker exec aster-acme cert list` 执行。详见[容器镜像](developer-docs/docker.md)。

先注册账户并阅读 CA 条款，再申请证书。默认使用 **Let's Encrypt 生产环境**。

```sh
aster-acme account register default --contact admin@example.com
aster-acme cert issue -n example-cert -a default -d example.com -c manual_dns
```

无人值守续期可在注册时显式委托自动接受 CA 条款更新：

```sh
aster-acme account register default --auto-accept-new-terms
```

该参数同时同意当前公布的条款。账户记录仍保存精确的已接受 URL，`account show` 会显示未来更新授权是否启用。`--yes`、JSON 模式和签发时的隐式账户检查都不会开启授权；不带该参数的普通 `account register` 会保留已有授权，避免日常恢复操作意外撤销无人值守续期信任。

注册后可用 `account update` 修改该授权（条款授权与联系人/profile 互斥）：

```sh
aster-acme account update default --auto-accept-new-terms --yes      # 接受当前条款并开启委托
aster-acme account update default --clear-auto-accept-new-terms --yes  # 撤销，保留已接受 URL
```

开启会读取在线 directory 并记录精确的当前条款 URL；读不到 directory 时直接失败，不会静默开启；CA 未公布条款时仍会保存授权并在报告中明确说明。撤销是纯本地操作、不发送任何请求，并保留已接受 URL。两种修改都不会向 CA 发送账户更新。

按提示发布 TXT 并确认。中途退出后可以继续原申请，续期沿用保存的验证方式：

```sh
aster-acme cert issue --resume example-cert
aster-acme cert show example-cert
aster-acme cert renew example-cert
aster-acme cert renew --all
```

`daemon run` 在前台常驻，启动后立即检查，之后按配置间隔（默认 60 秒）开始下一轮维护。它刷新 ARI 建议、自动续期使用`webroot`、`standalone`、`tls_alpn`、`dns_provider`或已配置`dns_persist`的到期证书，并重试已配置部署；人工验证方式会跳过。按 `Ctrl-C` 或 Unix `SIGTERM` 后停止新周期并保留已启动工作的结果。建议通过系统服务管理器启动和重启；`daemon run-once` 仍可供 cron 使用。

常驻 daemon 会独占对应的 data-dir。可在 `config.toml` 设置 `daemon_interval = 60`，或用 `daemon run --interval 60` 覆盖。人类日志与签发使用相同的时间戳和级别格式；`--json` 逐行输出 JSON 对象。

`renew` 默认到期才执行，`--now` 可提前续期。无人值守维护可使用常驻 `daemon run` 或由 cron 定期调用 `daemon run-once`，仅支持无需人工确认的验证方式。其他验证方式和脚本确认规则见 [CLI 契约](developer-docs/cli-contract.md)。

## 证书私钥吊销

```sh
aster-acme cert revoke example-cert --sign-with certificate-key --reason key-compromise --yes
```

使用所选托管世代的证书私钥，不依赖原ACME账户或CSR；默认`--sign-with account`继续使用签发账户。两种方式均保留本地文件和部署副本，不自动换钥或reload。详见[吊销契约](developer-docs/certificate-lifecycle.md#吊销)。

## 部署

先让服务读取一个已存在的目标目录，再为证书添加部署绑定：

```sh
aster-acme cert deploy add example-cert -n nginx \
  --target /etc/nginx/certs/example \
  --reload-cmd "systemctl reload nginx"
aster-acme cert deploy show example-cert nginx
```

添加绑定会立即部署，之后续期成功会自动使用它。全部文件准备完成后逐一替换，仅全部发布成功才执行 reload；部署直接使用普通文件，目录路径保持稳定。绑定管理、文件权限、精确路径和重试见 [`cert deploy`](developer-docs/cli-contract.md#证书部署)。

PKCS#12（`.p12`）使用精确路径发布，包含证书链和私钥，Unix 权限沿用 `--key-mode`（默认 0600）。daemon 推荐使用用户管理的 0600 密码文件：

```sh
aster-acme cert deploy add example-cert -n java \
  --p12-path /etc/myservice/certificate.p12 \
  --p12-password-file /etc/myservice/p12-password
```

也可用 `--p12-password-env ENV_VAR`（daemon 依赖启动环境）。绑定只存来源引用，不存密码。无来源时只有交互式 `cert deploy run` 隐藏询问一次；add、JSON 和自动部署不提示，缺少密码时发布失败。目录模式仍只发布 PEM 四件套。

## 文档

用户与运维文档使用 Astro Starlight 发布在 [acme.docs.astercosm.com](https://acme.docs.astercosm.com/)。

- [快速开始](https://acme.docs.astercosm.com/start/quick-start/)
- [安装](https://acme.docs.astercosm.com/start/install/)
- [选择验证方式](https://acme.docs.astercosm.com/using/challenges/)
- [账户管理](https://acme.docs.astercosm.com/using/accounts/)
- [签发与恢复](https://acme.docs.astercosm.com/using/issuance/)
- [续期与 ARI](https://acme.docs.astercosm.com/using/renewal/)
- [部署与 reload](https://acme.docs.astercosm.com/using/deploy/)
- [DNS Provider 自动发布](https://acme.docs.astercosm.com/admin/dns-providers/)
- [常驻守护与定时任务](https://acme.docs.astercosm.com/admin/daemon/)
- [容器运行](https://acme.docs.astercosm.com/admin/docker/)
- [CLI 命令参考](https://acme.docs.astercosm.com/reference/cli/)
- [开发文档](developer-docs/README.md)：项目契约、任务路由、架构、crate 归属与测试
- [RFC 参考](developer-docs/rfc-reference.md)与[更新日志](CHANGELOG.zh.md)

状态默认保存在 `com.astercosm.acme` 的平台目录；可通过 `--data-dir PATH` 或 `ASTER_ACME_DATA_DIR` 指定其他根目录（命令行参数优先）。`list/show` 默认离线；`--json` 禁止交互，只输出一份结构化结果。

## 安全

- 请通过 [GitHub Security Advisories](https://github.com/AsterCommunity/AsterACME/security/advisories/new) 或 `report@esaps.net` 私密报告漏洞，完整政策见 [SECURITY.md](SECURITY.md)
- 已发布的安全公告：[github.com/AsterCommunity/AsterACME/security/advisories](https://github.com/AsterCommunity/AsterACME/security/advisories)

## 许可

采用 [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)，任选其一。除非明确另行说明，提交的贡献遵循相同双重许可。

外部DNS Profile配置、敏感自定义值、CNAME委派、传播等待及清理见[DNS Provider](developer-docs/dns-providers.md)。
