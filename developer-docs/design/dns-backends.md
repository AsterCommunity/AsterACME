# DNS 后端、状态机与宿主边界

## 所有权

`aster_acme_dns::backend` 定义后端 ID、字段描述符、配置校验/远端 binding/工厂契约及显式不可变 registry。注册项通过 `linkme` 收集，宿主也可调用 `ProviderRegistry::new` 注入实现；重复 ID、坏描述符和未编译的后端失败关闭。CLI 对所有供应商使用同一字段展示和工厂，不维护厂商分支。描述符和运行时构造始终来自同一个 backend 对象。

`aster_acme_dns_builtin` 保存厂商配置、签名、API 解析和状态机，无网络或文件访问。默认 feature 为空；当前只有 `cloudflare` 厂商 feature。它同时提供 `ConditionalRrsetFactory`，供具备真实条件更新能力的后端复用；这不代表已实现其他厂商。`aster_acme_dns_adpp` 通过同一注册表提供外部后端，保留自己的 wire/process 错误语义。

`aster_acme_dns::operation` 拥有通用 runner，解释 HTTP、保存检查点、读取凭据、等待和完成等 effect，将执行结果作为 event 送回厂商状态机。每次写请求必须消耗一个已经持久化确认的检查点；没有检查点、保存失败、取消或超时均不能启动后续写。宿主限制整批期限和步数，逐记录保留成功与失败，不把 HTTP 200 当作 DNS 或 CA 成功。

`aster_acme_dns_http` 通过 Forge 执行完整请求，不重新序列化签名后的 body，拒绝会被 URL parser 隐式规范化的已签名目标，不重试、不跟随重定向，限制收发大小并覆盖响应 body 的取消和期限。CLI 拥有凭据文件读取策略和命令生命周期内的惰性共享池。嵌入者注入自己的 `HttpExecutor` 与 `PublicationStore`。

`aster_acme_cli_storage::provider_publication` 保存固定 backend/binding/record、版本化非秘密状态，以及同一 data-dir 的进程租约。锁不因 async 等待取消而提前释放。ACME 服务仍拥有材料、CA 推进和回执落盘顺序；DNS solver 共用 CNAME/传播/清理流程，不解释厂商 API。

## 身份与格式

- 后端类型：`com.astercosm.acme.dns.cloudflare`、`com.astercosm.acme.adpp`。
- ADPP wire `protocol`：`com.astercosm.acme.adpp`；相同字符串位于不同语义字段，不用 wire 协议版本推断后端配置版本。
- Profile 名称是用户配置实例，publication ID 是稳定发布身份，两者不代替后端/账号/zone 范围。
- 保存证书定义冻结后端和非秘密 binding，续期沿用；凭据本身不写入定义或发布检查点。
- 状态机阶段不直接持久化 Rust 枚举内存布局，而是版本化、可校验的领域事实。重启从已保存事实重建，重新读取远端，而非恢复旧的已签名 HTTP 字节。

预发布本地布局直接演进：旧 Profile 缺 `backend_id`/`backend_config_version`、旧 `dns_external` 定义或缺 binding 字段时失败，不提供兼容别名、自动迁移或数据删除。ADPP wire v1 请求只发送最终记录名，CNAME 路由留在宿主；旧 provider 需适配此预发布协议变更。

## RRset 覆盖

`ConditionalRrsetFactory` 的协议 adapter 必须实现完整读取、无损 metadata 保存和真正原子的 revision precondition，revision 不得复用，不存在的 RRset 也要有可靠的条件创建语义。缺条件能力时拒绝写入；本地锁不能补足云 API 的并发契约。

发布读取当前所有值并只加入目标值；清理重新读取当前集合，只减去有持久化所有权证据的目标值，保留后来新增值、TTL 和未知字段，不恢复旧快照。明确条件冲突后重新读取/合并，最多四次。写入结果不确定后，观察到值存在不能证明由本次创建，缺乏厂商幂等/所有权依据时失败保留。该通用构件不提供跨 data-dir 的同值 publication 引用计数；具体后端接入前必须明确同值占用和外部修改的所有权契约。

Cloudflare 使用单记录对象及 publication comment，不使用 RRset 全量覆盖。其他 AsterACME publication 的同值记录拒绝借用，以避免创建者清理时破坏借用者的验证。

## 扩展和验证

新增供应商在 builtin 中增加独立 feature、配置/描述符和注册项，实现自己的 `OperationFactory`，不修改 CLI。新增 effect 只有出现真实的通用宿主执行需求时才扩展，不把厂商流程搬入 runner。

常规验证使用厂商 API mock、实际文件 checkpoint/跨进程锁和 ACME 服务 loopback，覆盖断点、未知副作用、条件冲突、部分成功和脱敏。feature 矩阵分别构建默认关闭/单厂商/CLI 关闭和开启厂商的组合；release 另检查实际注册项仍可发现。真实 Cloudflare 和公网 CA 验收必须单独记录。
