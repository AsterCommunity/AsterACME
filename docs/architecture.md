# 架构概览

AsterACME 提供可嵌入的 Rust ACME 客户端与 CLI。本文只说明层次、调用链和模块归属；长期约束见[项目契约](project-contract.md)，按任务找代码见[任务路由](task-routing.md)。

## Crate 所有权

| Crate | 负责 | 不负责 |
| --- | --- | --- |
| `aster_acme_core` | 账户、订单、授权、challenge、续期和吊销的纯状态决策 | HTTP、文件、运行时、交互 |
| `aster_acme_protocol` | 具名wire模型、directory与Provider、精确URL、Problem、JWS结构 | HTTP执行、签名、CLI输出DTO |
| `aster_acme` | ACME编排、JWS签名、transport、证书校验、材料推导、对象安全存储/solver契约、维护周期编排与重试准入策略 | 文件布局、终端、部署进程 |
| `aster_acme_validation` | 验证方法实现，目前DNS可见性检查 | ACME协议推进、CLI选择 |
| `aster_acme_cli_storage` | 账户/证书文件、查询、租约、恢复、部署文件发布 | CLI配置schema、CA请求、reload进程 |
| `aster_acme_cli` | 参数/配置、交互、solver适配、维护任务执行器、报告、reload | 重新实现协议状态机、维护候选筛选或重试准入 |

依赖由外向内。Forge提供产品无关机制；不要因为潜在复用就迁移ACME领域语义。具体文件/锁留在CLI storage，嵌入者可替换为数据库或远程签名器。

## 入口与执行链

```text
CLI app / dispatch
  → commands/<account|cert|daemon>/{args,execute,report,render}
  → AccountService / IssueService / RenewalService / RevocationService
  → core动作 + protocol模型 + transport / signer / store / solver
```

执行返回类型化报告，render不执行存储、HTTP或进程。`CommandContext`拥有本次输出与共享HTTP池；`ExecutionContext`显式携带取消令牌与单调deadline，CA发现、签发和自动部署共用剩余预算。

账户写入显式接收当前 `Arc<dyn AccountLease>`，后台写任务克隆并持有到结束；独立本地编辑由文件适配器新获取租约。换钥与签发会话分别串行化自身IO，不通过全局状态推断租约归属。

## Challenge边界

`challenge::{dns01,dns_persist,http01,tls_alpn01}`分别拥有响应材料及派生约束，`ChallengeMaterial`只聚合具名类型。方法元数据准入、发布生命周期、账户证明要求和响应身份由`ChallengeKind`集中穷尽分发；纯`issuance::authorization`准备材料与检查点，`IssueService`负责持久化顺序和协议副作用。`create`保持方法无关；存储和CLI续期通过通用`retained_validation`快照携带长期材料，材料所有者判断发布范围，通用层不解析TXT。具体流程见[签发设计](design/issuance.md)。

## 当前能力

已实现账户注册/找回/联系人更新/停用/换钥，DNS-01人工验证、草案DNS-PERSIST-01首次人工配置及持续复用、HTTP-01人工/webroot/standalone、TLS-ALPN-01 standalone，签发恢复、ARI及随机回退计划、前台单次/批量续期、账户签名吊销和多目标文件部署/reload。

`daemon run-once`与常驻`daemon run`都调用库的`maintenance::run_cycle`，由库按ARI刷新、到期续期、已配置部署重试的顺序查询候选并控制取消边界；CLI提供续期事务和reload执行回调。常驻循环不并发重叠，每轮完成后等待配置的间隔。CLI storage对每个data-dir提供跨进程daemon租约，证书级租约和expected_in_use重验保护daemon与人工renew/deploy竞争。验证实现准入及reload进程属于宿主能力，续期退避和部署重试准入属于库策略。自动DNS provider尚未实现；IANA或RFC列出某种扩展不代表执行实现已接入。当前发行状态和能力以双语README、CHANGELOG及代码为准，历史测试记录只证明当时的验收范围。

## 详细设计入口

| 主题 | 详细契约 |
| --- | --- |
| 账户、换钥、确认与恢复 | [账户设计](design/account.md) |
| newOrder/ack/finalize、材料、webroot与临时监听器 | [签发设计](design/issuance.md) |
| 文件布局、查询、平台视图、部署发布 | [存储设计](design/storage.md) |
| 输出会话、HTTP池、panic与依赖策略 | [运行时设计](design/runtime.md) |
| 续期时间、ARI、吊销、删除与批量结果 | [证书生命周期](certificate-lifecycle.md) |
| 命令、交互、配置优先级与退出码 | [CLI契约](cli-contract.md) |
| 规范出处与尚未实现的扩展 | [RFC索引](rfc-reference.md) |

开发者文档组织规则和验证入口统一见[文档索引](README.md)，不在本文追加每轮修改日记或复制测试结果。

预检所有权：aster_acme的precheck feature提供Runner/Check/Report，precheck-http提供HTTP实现；validation的precheck-caa和precheck-dns按需引入Hickory。CLI只负责预检时机和渲染，protocol只描述directory字段。禁用CLI预检不会改变ACME正式验证。
