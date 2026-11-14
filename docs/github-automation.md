# GitHub 自动化与标签

AsterACME 使用组织共享的 [`AsterCommunity/aster-automation`](https://github.com/AsterCommunity/aster-automation) Action（固定 commit SHA）和组织 GitHub App `AsterCommunity Automation` 维护 PR 标签、关联 Issue 生命周期、CI 诊断和默认分支故障 Issue。产品路径、标签、workflow 与提示规则保留在默认分支的 `.github/aster-automation.json`，本文只说明本仓接入了哪些能力和各自入口，不复制共享引擎语义。

## 标签体系

标签按来源分三类，全部定义在 `.github/aster-automation.json` 的 `labels.definitions`，由 scheduled reconciliation 每小时幂等同步（缺失创建、颜色/描述漂移纠正）：

- 生命周期：`Priority:*`（仅继承自全部 closing issue，不猜测）、`Status:*`、`Wait For More Info`、`Wait For PR`、`Merged`、`Tracking: Epic`
- CI 事实：`CI: Failure` / `CI: Infrastructure` / `CI: Flaky` 只用于故障 Issue，`CI: Running` / `CI: Passed` 只用于 PR
- 路径证明：`Rust`、`Python`、`Documentation`、`Dependencies`、`Scope: Core|Protocol|Client|Crypto|Challenges|Storage|CLI|Deployment` 按 changed files 维护，`Risk: High` 覆盖 crypto/transport/storage 模块入口及目录、revocation、换钥、部署发布/reload 和 workflow 变更

自动化只维护可由文件路径或 GitHub API 事实证明的标签；人工添加的非托管标签保留。新建 Issue 由 `.github/ISSUE_TEMPLATE/*` 预置初始标签（`Bug`/`Enhancement`/`Documentation`/`Question` + `Wait For More Info`）。

## Workflow 入口

| Workflow | 触发 | 职责 |
| --- | --- | --- |
| Repository Automation | `.github/workflows/**` 或 `.github/aster-automation.json` 变更 | 校验配置 schema 与仓库静态契约（workflow 名称、CI Diagnostics 订阅、共享 Action pin） |
| PR Automation | `pull_request_target` | 按 changed files 维护路径标签与关联 Issue 生命周期，为当前 HEAD 建立初始 Gate |
| CI Diagnostics | `workflow_run`（Repository Automation、CI、IANA ACME Registry 完成后）及手动 run ID 入口 | 按 source workflow run ID 聚合检查状态为 `PR Gate`，维护 `CI: Running/Passed`、诊断评论和默认分支故障 Issue |
| Repository Reconciliation | 每小时及手动 | 最终一致性：同步标签定义、重算 Gate/Readiness/tracking Issue/incident 状态，维护 `Release readiness dashboard` |

历史 workflow 结束后 Gate 未收敛时，从 Actions 手动运行 CI Diagnostics 并传入源 workflow run ID；PR 关闭后仍有 pending Gate 时手动运行 PR Automation 并传入 PR 编号。自动触发的 CI Diagnostics 用 source run ID 做并发身份，使同一 SHA 上不同上游运行可分别处理。

## 添加或修改 workflow 时

在 `.github/workflows/` 增删 workflow 后，必须同步 `.github/aster-automation.json` 的 `workflows` 名称与路径规则，并把新名称加入 `ci-diagnostics.yml` 的 `workflow_run` 订阅；否则 Repository Automation 的契约校验会失败。共享状态机与路径匹配测试由 `AsterCommunity/aster-automation` 持有。PR Automation、CI Diagnostics、Repository Reconciliation 使用共同 FIFO concurrency queue，因为 pinned action 会整体 PUT 标签集合；`queue: max` 最多容纳100个等待项，队列满时 GitHub 会取消新等待项。

## 权限边界

- `pull_request_target` 与 `workflow_run` 只 checkout 默认分支；checkout、App token 与共享 Action 全部固定 commit SHA，checkout 使用 `persist-credentials: false`。
- App token 只授予 Actions 读、Checks 写、Contents 读、Issues 写和 Pull requests 写；CI 日志、标题、正文和路径按不可信输入处理。
- 自动化只计算和发布事实，不自行合并、批准或修改分支保护。

## 本地验证

共享引擎在 `AsterCommunity/aster-automation` 运行 Node.js 单元测试（`npm run validate`）；配置 schema 与仓库静态契约由 `Repository Automation` 在 CI 中执行 `validate-config` / `validate-repository`。本仓本地验证保留 workflow 静态检查：

```bash
actionlint -ignore 'unexpected key "queue" for "concurrency" section' .github/workflows/*.yml
python3 scripts/check-github-automation-workflows.py
python3 -m unittest scripts/tests/test_github_automation_workflows.py
git diff --check
```

标签与文档变更不需要重跑 Rust 测试；`python3 scripts/check-doc-links.py` 覆盖本地链接。

PR Automation、CI Diagnostics 和 Repository Reconciliation 都会通过共享 Action 全量替换标签。三者共用 `aster-repository-label-writers` 串行组和 GitHub FIFO `queue: max`，避免一个 workflow 用旧标签快照覆盖另一个 workflow 的更新；Actionlint 1.7.12 的内置 schema 尚未识别 GitHub 新增的 `queue` key，因此验证时只忽略该精确 schema 报告，并由仓库脚本及单元测试校验 queue 与模块入口路径契约。
