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
  <a href="README.md"><img alt="English" src="https://img.shields.io/badge/README-English-E11D48?style=for-the-badge"></a>
  <a href="docs/architecture.md"><img alt="架构设计" src="https://img.shields.io/badge/architecture-overview-0F172A?style=for-the-badge"></a>
  <a href="docs/rfc-reference.md"><img alt="RFC 参考" src="https://img.shields.io/badge/ACME-RFC%208555-059669?style=for-the-badge"></a>
  <a href="CHANGELOG.zh.md"><img alt="更新日志" src="https://img.shields.io/badge/changelog-unreleased-7C3AED?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="https://github.com/AsterCommunity/AsterACME/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/AsterCommunity/AsterACME/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="rust-toolchain.toml"><img alt="Rust 1.99+" src="https://img.shields.io/badge/Rust-1.99%2B-000000?style=flat-square&amp;logo=rust"></a>
  <a href="LICENSE-MIT"><img alt="MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square"></a>
</p>

AsterACME 通过保存请求状态、固定密钥与 CSR，以及明确的中断恢复流程，管理证书生命周期。可以交互使用 CLI、编写脚本，也可以将 Rust 服务嵌入应用，注入自己的存储、签名器和验证适配器。

**尚未正式发布：** ACME 包暂未发布，本地格式与 Rust API 仍可能变化。自动 DNS provider 尚未实现。

## 能力

- 具名 CA 账户：注册、找回、联系人更新、换钥和停用。
- 单域名、多 SAN 与通配符证书，账户与证书可独立选择密钥类型。
- 保存申请后恢复、ARI 刷新、前台单次／批量续期，以及受支持验证方式的无人值守维护。
- 每张证书绑定多个部署目标，续期后自动部署，reload 有界执行并展示 stdout/stderr。
- 交互式输入、结构化 JSON、离线查看及可选 debug 诊断。

| 验证方式 | 实现 |
| --- | --- |
| DNS-01 | `manual_dns`：手动发布 TXT，支持通配符 |
| DNS-PERSIST-01（草案 -02） | `dns_persist`：首次手动配置长期 TXT，后续续期复用；支持通配符 |
| HTTP-01 | `manual_http`、`webroot`，或临时监听 80 端口的 `standalone` |
| TLS-ALPN-01 | 临时监听 443 端口的 `tls_alpn` |

`dns_persist`要求CA支持[对应草案版本](docs/rfc-reference.md#dns-persist-草案实现2026-11-14)。TXT保留供续期使用；它不包含DNS provider自动写入，也不表示已通过公网CA验收。

## 快速开始

使用 **Rust 1.99+** 从源码安装：

```sh
git clone https://github.com/AsterCommunity/AsterACME.git
cd AsterACME
cargo install --path crates/aster_acme_cli --locked
```

先注册账户并阅读 CA 条款，再申请证书。默认使用 **Let's Encrypt 生产环境**。

```sh
aster-acme account register default --contact admin@example.com
aster-acme cert issue -n example-cert -a default -d example.com -c manual_dns
```

按提示发布 TXT 并确认。中途退出后可以继续原申请，续期沿用保存的验证方式：

```sh
aster-acme cert issue --resume example-cert
aster-acme cert show example-cert
aster-acme cert renew example-cert
aster-acme cert renew --all
```

`daemon run` 在前台常驻，启动后立即检查，之后按配置间隔（默认 60 秒）开始下一轮维护。它刷新 ARI 建议、自动续期使用`webroot`、`standalone`、`tls_alpn`或已配置`dns_persist`的到期证书，并重试已配置部署；人工验证方式会跳过。按 `Ctrl-C` 或 Unix `SIGTERM` 后停止新周期并保留已启动工作的结果。建议通过系统服务管理器启动和重启；`daemon run-once` 仍可供 cron 使用。

常驻 daemon 会独占对应的 data-dir。可在 `config.toml` 设置 `daemon_interval = 60`，或用 `daemon run --interval 60` 覆盖。人类日志与签发使用相同的时间戳和级别格式；`--json` 逐行输出 JSON 对象。

`renew` 默认到期才执行，`--now` 可提前续期。无人值守维护可使用常驻 `daemon run` 或由 cron 定期调用 `daemon run-once`，仅支持无需人工确认的验证方式。其他验证方式和脚本确认规则见 [CLI 契约](docs/cli-contract.md)。

## 证书私钥吊销

```sh
aster-acme cert revoke example-cert --sign-with certificate-key --reason key-compromise --yes
```

使用所选托管世代的证书私钥，不依赖原ACME账户或CSR；默认`--sign-with account`继续使用签发账户。两种方式均保留本地文件和部署副本，不自动换钥或reload。详见[吊销契约](docs/certificate-lifecycle.md#吊销)。

## 部署

先让服务读取一个已存在的目标目录，再为证书添加部署绑定：

```sh
aster-acme cert deploy add example-cert -n nginx \
  --target /etc/nginx/certs/example \
  --reload-cmd "systemctl reload nginx"
aster-acme cert deploy show example-cert nginx
```

添加绑定会立即部署，之后续期成功会自动使用它。全部文件准备完成后逐一替换，仅全部发布成功才执行 reload；部署直接使用普通文件，目录路径保持稳定。绑定管理、文件权限、精确路径和重试见 [`cert deploy`](docs/cli-contract.md#证书部署)。

## 文档

- [CLI 与配置](docs/cli-contract.md)：命令、交互、JSON、超时及 `--debug`。
- [证书生命周期](docs/certificate-lifecycle.md)：续期、ARI、吊销和删除。
- [开发文档](docs/README.md)：项目契约、任务路由、架构、crate 归属与测试。
- [RFC 参考](docs/rfc-reference.md)与[更新日志](CHANGELOG.zh.md)。

状态默认保存在 `com.astercosm.acme` 的平台目录；可通过 `--data-dir PATH` 或 `ASTER_ACME_DATA_DIR` 指定其他根目录（命令行参数优先）。`list/show` 默认离线；`--json` 禁止交互，只输出一份结构化结果。

## 许可

采用 [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)，任选其一。除非明确另行说明，提交的贡献遵循相同双重许可。
