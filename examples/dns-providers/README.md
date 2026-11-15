# Cloudflare 外部 DNS Provider 示例

`cloudflare_adpp.py` 是一个实现 [ADPP v1](../../docs/rfc/dns-provider-protocol/0001-asteracme-dns-provider-protocol.md) 的外部 DNS provider executable，通过 Cloudflare API v4 完成 DNS-01 的 `present` 与 `cleanup`。仅依赖 Python 3.9+ 标准库，无第三方包。Provider 配置、凭据边界和恢复语义见 [Provider 操作文档](../../docs/dns-providers.md)。

## 安装与配置

脚本需要绝对路径解释器（AsterACME 启动 provider 时不继承 ENV，`/usr/bin/env` shebang 不可依赖）。两种配置方式任选其一：

```sh
# 方式一：直接执行脚本（依赖 /usr/bin/python3 存在且脚本有可执行位）
aster-acme provider add cf-prod \
  --exec /absolute/path/examples/dns-providers/cloudflare_adpp.py \
  --allow-zone example.com

# 方式二：显式解释器 + 脚本参数（Windows 或无 /usr/bin/python3 的平台）
aster-acme provider add cf-prod \
  --exec /absolute/path/python3 \
  --arg=/absolute/path/examples/dns-providers/cloudflare_adpp.py
```

凭据写入 Profile 的 `provider_custom`（文件为 owner-only 权限）：

```toml
[provider_custom]
# 两种凭据来源二选一：
api_token = "cloudflare-api-token"        # 直接保存 token（会存入 Profile 文件）
# token_file = "/absolute/path/token"     # 或让脚本从自有文件读取

# 可选项：
# zone_id = "0123456789abcdef0123456789abcdef"  # 固定 zone，跳过自动发现
# api_base = "https://api.cloudflare.com/client/v4"  # 仅本地 mock 测试覆盖
```

Cloudflare token 需要 `Zone → DNS → Edit` 权限并授权到目标 zone。子进程不继承 ENV，`CLOUDFLARE_API_TOKEN` 之类环境变量不会生效。

## 行为要点

- **Zone 发现**：从发布名逐级上溯查询 `GET /zones?name=`，最长后缀匹配；多账号 token 看到同名 zone 时报 `zone_ambiguous`。
- **幂等**：创建记录时把 `publication_id` 写入 record `comment`；同一 publication 重试会复用既有记录并返回相同回执，不产生重复。
- **用户记录保护**：无匹配 comment 的同值记录标为 `preexisting`，cleanup 返回 `retained`，永不删除。
- **精确清理**：`created` 回执按 record ID + 精确值核对后才删除；值已被改动则 `record_not_owned` 失败关闭，保留记录。
- **错误映射**：401/403/429/5xx 分别映射为 ADPP 的 `authentication_failed`/`authorization_denied`/`rate_limited`/`provider_unavailable`；结构化拒绝可证明无副作用，仅传输层失败标 `unknown`。
- **TTL**：按请求值写入，收敛到 Cloudflare 允许的 60–86400 秒；缺省 120 秒。
- stderr 输出人类可读诊断；stdout 只承载协议响应。脚本自身不打印 token。

## 本地测试

```sh
python3 -m unittest discover -s examples/dns-providers/tests
```

测试内置一个 Cloudflare API mock（本地回环 HTTP server），覆盖创建、幂等重试、preexisting 保留、部分失败、清理 fail closed、请求级错误、限流与凭据缺失路径，不联网、不使用真实凭据。

真实 Cloudflare 的签发验收（创建 → CA 验证 → 清理）未在本仓库执行；接入真实 zone 前先按 [dns-providers.md](../../docs/dns-providers.md) 的建议在受控 zone 与 staging CA 验证完整链路。
