# 开发任务路由

先读[项目契约](project-contract.md)。本表给出最小上下文和代码起点，后续沿实际调用链阅读相邻实现与测试。

| 任务 | 先读 | 代码入口 | 验证重点 |
| --- | --- | --- | --- |
| 账户注册/找回/联系人/停用/换钥 | [账户设计](design/account.md)、[RFC](rfc-reference.md) | aster_acme/account、core/account、cli_storage/account、CLI commands/account | 意图先保存、确认身份、租约、双钥、取消与重启恢复 |
| ACME wire/JWS/transport/Problem | [RFC](rfc-reference.md)、[运行时设计](design/runtime.md) | protocol、aster_acme/transport、crypto | 精确URL/签名、nonce、明确未发送与结果未知、未知扩展 |
| 签发/恢复/验证材料 | [签发设计](design/issuance.md) | aster_acme/issuance、core/machine、CLI cert/validation | 固定key/CSR、终态problem、ack/finalize重放边界 |
| HTTP/webroot/standalone/TLS-ALPN | [签发设计](design/issuance.md)、[CLI](cli-contract.md) | CLI cert/validation/{webroot,listener,standalone,tls_alpn,manual} | 所有权、取消/期限、线程/终端恢复、清理用户替换文件 |
| 续期/ARI/吊销/删除 | [生命周期](certificate-lifecycle.md) | aster_acme/{renewal,renewal_calculation,revocation}、cli_storage/issuance、CLI cert | 过期边界、时间窗口、旧in_use保留、批量已提交结果 |
| 存储查询/文件/恢复/部署发布 | [存储设计](design/storage.md) | storage/query、cli_storage/{inventory,issuance,account,state_file,toml_file} | 路径裁剪、持锁重验、故障恢复、平台差异 |
| deploy/reload | [CLI部署契约](cli-contract.md#证书部署)、[存储设计](design/storage.md) | CLI cert/deployment、cli_storage/issuance/deployment | 完整准备、逐文件替换、进程输出/取消、部分失败 |
| 参数/交互/配置/输出 | [CLI契约](cli-contract.md)、[运行时](design/runtime.md) | CLI common、commands、config | 非TTY/JSON、缺省值、转义、最终报告与退出码 |
| 构建/CI/依赖策略 | [Rust约定](rust-guidelines.md)、[测试](testing.md) | Cargo.toml、CLI build.rs、scripts、.github/workflows | 原生平台、编码、可复现构建、feature漂移 |
| 文档 | [文档索引与规则](README.md) | docs及对应crate README | owner唯一、链接、双语和当前事实 |

验证命令集中在[测试指南](testing.md)。Review先绑定被审查revision，对照当前代码验证；同类问题从共享所有权入口修复，不按评论数量创建重复分支。
