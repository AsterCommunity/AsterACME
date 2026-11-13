# 文档索引

## 从哪里开始

- 使用CLI：[中文README](../README.zh.md)、[CLI契约](cli-contract.md)。
- 修改代码：[项目契约](project-contract.md) → [任务路由](task-routing.md) → 对应owner文档及crate README。
- 理解结构：[架构概览](architecture.md)、[Rust与依赖约定](rust-guidelines.md)。
- 查协议：[RFC参考与接入边界](rfc-reference.md)。
- 查验证：[测试入口](testing.md)。

## 文档职责

| 文档 | 唯一负责内容 |
| --- | --- |
| 根AGENTS.md | 加载顺序、任务入口及少量硬约束 |
| project-contract.md | 长期产品/可靠性不变量 |
| architecture.md | crate归属、依赖方向及当前调用链 |
| task-routing.md | 按任务定位文档、代码、验证范围 |
| rust-guidelines.md | Rust组织、依赖及本仓库约束 |
| cli-contract.md | 参数、配置、交互、输出和退出码 |
| certificate-lifecycle.md | 托管身份、续期、ARI、吊销与删除语义 |
| design/account.md | 账户协议、确认及换钥恢复 |
| design/issuance.md | 签发、验证材料及solver生命周期 |
| design/storage.md | 文件、查询、平台发布与恢复 |
| design/runtime.md | 输出会话、HTTP池及panic |
| rfc-reference.md | 权威来源、扩展实现与缺口 |
| testing.md | 按风险选择检查和执行命令 |
| github-automation.md | GitHub 标签体系、自动化 workflow 入口及权限边界 |
| *-testing.md | 有日期及平台范围的测试证据 |

## 维护规则

每页围绕一个读者任务，细节放回所有者，通过链接发现，避免复制契约。已有owner页面能容纳时不新增平行说明；根AGENTS不追加实现日记或验证命令清单。

当前契约、未来设计和历史记录要明确区分。代码示例应对应当前API；无法执行的设想标为设计草案，不冒充现有用法。旧验收不能证明当前checkout，规范性结论链接RFC/供应商原文。

README.md/README.zh.md与CHANGELOG.md/CHANGELOG.zh.md配对；开发者文档目前使用中文，不为文件数对称制造英文空页。新增/移动文档同时更新索引、任务路由和引用。链接校验：`python3 scripts/check-doc-links.py`（只检查本地路径，不联网）。
