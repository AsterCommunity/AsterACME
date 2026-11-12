# AsterACME

AsterACME是可嵌入的Rust ACME客户端与CLI。全局身份和工程流程遵循会话指定的canonical文件，本文件只保存项目入口和硬约束。

## 开始工作

1. 读[项目契约](docs/project-contract.md)，确认产品与可靠性边界。
2. 按[任务路由](docs/task-routing.md)定位本次代码、owner文档和验证入口，不机械通读所有文档。
3. 检查branch、HEAD和worktree；review与历史结论必须对应当前代码。修改前沿调用链读相邻实现和测试。

架构归属见[架构概览](docs/architecture.md)，完整目录见[文档索引](docs/README.md)。命令语义查[CLI契约](docs/cli-contract.md)，协议查[RFC索引](docs/rfc-reference.md)，Rust约定查[Rust与依赖](docs/rust-guidelines.md)。

## 硬约束

- 保留现有修改和暂存边界；不reset、stash、批量覆盖或清理用户数据。
- core纯决策，protocol拥有wire，aster_acme拥有协议编排，cli_storage拥有文件/查询，CLI拥有交互和进程；具体规则回到所有者，不复制状态机。
- 禁止use super（含测试），使用crate::实际所有者路径。禁止生产unsafe及unwrap/expect/panic占位。
- 依赖版本和features仅根workspace定义，成员只workspace=true；稳定Rust，标准库锁，HTTP复用Forge/rustls/AWS-LC。
- 不增加纯透传facade、隐藏全局注册表、旧导入路径兼容层。内部API/schema改变同步全部调用方、测试、示例及文档；未发布格式不自动迁移或删除旧数据。
- 持久化先保存意图，取消不提前释放后台写任务租约；不确定远端结果不自动重放。私钥/凭据不进入日志或公开输出。
- deploy直接发布普通文件并保持目录，全部文件准备成功后逐文件替换，全部发布成功才reload；不使用部署链接或承诺整组原子事务。容器与reload的服务更新逻辑由用户负责。
- 实现和重构覆盖完整调用链；按[测试入口](docs/testing.md)验证实际行为。测试记录、当前契约及未来计划分开，不把编译/交叉检查当真实平台验收。

文档按[索引规则](docs/README.md)更新，README/CHANGELOG中英文配对。具体操作说明和验证命令留在对应文档，不往本文件堆叠。
