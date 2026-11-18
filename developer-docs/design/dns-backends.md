# DNS 后端、状态机与宿主边界

## 所有权

`aster_acme_dns::backend` 定义后端 ID、字段描述符、配置校验/远端 binding/工厂契约及显式不可变 registry。注册项通过 `linkme` 收集，宿主也可调用 `ProviderRegistry::new` 注入实现；重复 ID、坏描述符和未编译的后端失败关闭。CLI 对所有供应商使用同一字段展示和工厂，不维护厂商分支。描述符和运行时构造始终来自同一个 backend 对象。

`aster_acme_dns_builtin` 保存厂商配置、签名、API 解析和状态机，无网络或文件访问。默认 feature 为空；提供 `cloudflare`、`aliyun`、`tencent_cloud`、`huawei_cloud` 厂商 feature。它同时提供 `ConditionalRrsetFactory`，供具备真实条件更新能力的后端复用；这不代表已实现其他厂商。`aster_acme_dns_adpp` 通过同一注册表提供外部后端，保留自己的 wire/process 错误语义。

供应商 feature 在 Cargo 中自动启用 `_http`、`_signed-api`、`_individual-records` 等内部能力，共享模块只判断能力开关，不枚举所有使用它的厂商。下划线前缀的 feature 是实现细节，宿主只选供应商 feature。`HttpRequest.method` 使用 `aster_acme_dns::operation::HttpMethod`，类型及其完整动词集合不按厂商裁剪；仅签名和 HTTP 传输边界转换为 wire 表示。

`aster_acme_dns::operation` 拥有通用 runner，解释 HTTP、保存检查点、读取凭据、等待和完成等 effect，将执行结果作为 event 送回厂商状态机。每次写请求必须消耗一个已经持久化确认的检查点；没有检查点、保存失败、取消或超时均不能启动后续写。宿主限制整批期限和步数，逐记录保留成功与失败，不把 HTTP 200 当作 DNS 或 CA 成功。

`aster_acme_dns_http` 通过 Forge 执行完整请求，不重新序列化签名后的 body，拒绝会被 URL parser 隐式规范化的已签名目标，不重试、不跟随重定向，限制收发大小并覆盖响应 body 的取消和期限。CLI 拥有凭据文件读取策略和命令生命周期内的惰性共享池。嵌入者注入自己的 `HttpExecutor` 与 `PublicationStore`。

`aster_acme_cli_storage::provider_publication` 保存固定 backend/binding/record、版本化非秘密状态，以及同一 data-dir 的进程租约。锁不因 async 等待取消而提前释放。ACME 服务仍拥有材料、CA 推进和回执落盘顺序；DNS solver 共用 CNAME/传播/清理流程，不解释厂商 API。

## 身份与格式

- 后端类型：`com.astercosm.acme.dns.cloudflare`、`com.astercosm.acme.dns.aliyun`、`com.astercosm.acme.dns.tencent-cloud`、`com.astercosm.acme.dns.huawei-cloud`、`com.astercosm.acme.adpp`。
- ADPP wire `protocol`：`com.astercosm.acme.adpp`；相同字符串位于不同语义字段，不用 wire 协议版本推断后端配置版本。
- Profile 名称是用户配置实例，publication ID 是稳定发布身份，两者不代替后端/账号/zone 范围。
- 保存证书定义冻结后端和非秘密 binding，续期沿用；凭据本身不写入定义或发布检查点。
- 状态机阶段不直接持久化 Rust 枚举内存布局，而是版本化、可校验的领域事实。重启从已保存事实重建，重新读取远端，而非恢复旧的已签名 HTTP 字节。

预发布本地布局直接演进：旧 Profile 缺 `backend_id`/`backend_config_version`、旧 `dns_external` 定义或缺 binding 字段时失败，不提供兼容别名、自动迁移或数据删除。ADPP wire v1 请求只发送最终记录名，CNAME 路由留在宿主；旧 provider 需适配此预发布协议变更。

## 单记录与无原子标记的所有权

DNSPod 与阿里云共用单记录发布生命周期。厂商模块各自解释错误并签名。逐页读取的结果必须完整且 ID 唯一。找到最终 TXT owner 的最长 zone 后先保存 zone 身份。后续调用沿用已保存的 zone。匹配同值集合为空时，`create_intent` 同时表示空的发布前同值快照。有记录时先保存 `preexisting` 和所有匹配 ID。

- 阿里云 `AddDomainRecord` 不接受备注，独立的备注更新无法给创建请求提供原子标记。发布前发现的同值记录一律保留并拒绝借用。仅创建响应的 `RecordId` 可转成 `created`。丢响应后同值出现或消失都不足以接管记录或重放创建。
- DNSPod 的 `CreateRecord.Remark` 随记录写入。只有已有 `create_intent` 且发现唯一、精确匹配的本次标记时，才可在丢响应后保存 `created`。其他 publication 的值拒绝借用。单条已启用的默认线路用户同值记录可借用并保留。
- 发出创建回执前重读 ID、zone、owner、类型、值、线路、启用状态和有效 TTL。DNSPod 还核对备注。清理要求 journal ID 等于回执 ID，并核对当前记录元组后保存删除意图。只有厂商明确的对象不存在错误可确认缺失。
- 明确拒绝需要先持久化才能再次创建。传输结果未知、结构错误或无法解释的错误代码均保留创建意图。退避下限由 solver 随签发 journal 落盘。凭据和厂商原始报错不会落盘。

## RRset 覆盖

`ConditionalRrsetFactory` 的协议 adapter 必须实现完整读取、无损 metadata 保存和真正原子的 revision precondition，revision 不得复用，不存在的 RRset 也要有可靠的条件创建语义。缺条件能力时拒绝写入；本地锁不能补足云 API 的并发契约。

发布读取当前所有值并只加入目标值；清理重新读取当前集合，只减去有持久化所有权证据的目标值，保留后来新增值、TTL 和未知字段，不恢复旧快照。明确条件冲突后重新读取/合并，最多四次。写入结果不确定后，观察到值存在不能证明由本次创建，缺乏厂商幂等/所有权依据时失败保留。该通用构件不提供跨 data-dir 的同值 publication 引用计数；具体后端接入前必须明确同值占用和外部修改的所有权契约。

Cloudflare 使用单记录对象及 publication comment，不使用 RRset 全量覆盖。其他 AsterACME publication 的同值记录拒绝借用，以避免创建者清理时破坏借用者的验证。

### 华为云：明确不保证原子性的 RRset 后端

`huawei_cloud`（#41）使用独立厂商状态机，描述符为 `best_effort_rrsets`。它不进入 `ConditionalRrsetFactory`，不伪造 revision，也不承诺一定安全。公开 API 未提供可验证的 ETag/If-Match/revision 前置条件，因此读取、合并和 PUT/DELETE 之间，控制台、其他 data-dir 或外部客户端的并发写入可能被覆盖或误删。写前重读、进程锁、description 和写后核对都不能消除这个时间窗。使用者必须自行协调所有写入者；推荐给 ACME 分配专用委派 owner。

- 公网 zone 使用 marker 分页，按最终 TXT owner 的最长标签后缀选取。zone ID/名称随 publication 保存；重启继续使用该 zone。`project_id` 和 region 组成非秘密 binding，凭据可轮换。
- 默认线路 RRset 的 `records` 按 TXT quoted-string 编码；读取能识别多 chunk 和十进制转义，同逻辑值有多个表示时拒绝歧义。合并保留当前其他 wire 值；PUT 只发送 `records` 和 description，使 TTL 和其他未修改字段留在服务端。
- description 中默认使用 `asteracme-<publication_id>=<sha256(value)>` 按分号分隔，保留用户原文和其他 publication 标记。provider 可覆盖备注格式；阿里云单记录使用 `acme-<publication_id>` 以满足 50 字符上限，读取兼容早期冒号格式。marker 与值绑定，根域/通配符不同值可共享同一 RRset。超过 255 字节或所有权不一致时拒绝写入；不为扩容截断用户描述。
- 无标记同值保留为 preexisting；其他 publication 同值拒绝借用。创建/合并前保存意图，已知响应先保存真实 RRset ID，再重读 ACTIVE 状态、ID、zone、owner、TXT 值与 marker 后产生回执。响应丢失仅在本次意图和完整 marker 可对账时接管，不凭值存在重放写入。
- 清理重新读当前集合，仅减去本 publication 有证据的值和 marker。有其他值时 PUT；没有剩余值才 DELETE。核验 ID 与 marker 后也存在外部竞态。写后再读取确认，后续重复清理使用终态 checkpoint，不再次删除后来重建的记录。华为云对空 description 的更新可能保留原值，因此不承诺清空最后一个 description 标记；过期标记仍不能绕过新 publication 的所有权校验。
- 仅对结构化明确 409 拒绝保存证据后重读合并，单次调用最多四次写入；429/认证/授权等错误结构化脱敏，限频下限随签发 journal 持久化。不确定响应保留意图；pending 状态有界轮询，不能把 HTTP 200/202 当作完成。

官方 SDK revision `3da3be180a23bcbf8f6e668606c6ef26e76e95af` 的 [请求元数据](https://github.com/huaweicloud/huaweicloud-sdk-go-v3/blob/3da3be180a23bcbf8f6e668606c6ef26e76e95af/services/dns/v2/dns_meta.go#L1711) 声明整组 POST/PUT/DELETE，未声明条件写入。签名测试对照同 revision 的 [HWS 官方向量](https://github.com/huaweicloud/huaweicloud-sdk-go-v3/blob/3da3be180a23bcbf8f6e668606c6ef26e76e95af/core/auth/signer/signer_test.go)。这只证明公开契约边界，不断言未公开的请求头能力。

## 扩展和验证

新增供应商在 builtin 中增加独立 feature、配置/描述符和注册项，实现自己的 `OperationFactory`，不修改 CLI。新增 effect 只有出现真实的通用宿主执行需求时才扩展，不把厂商流程搬入 runner。

常规验证使用厂商 API mock、实际文件 checkpoint/跨进程锁和 ACME 服务 loopback，覆盖断点、未知副作用、条件冲突、部分成功和脱敏。feature 矩阵分别构建默认关闭/单厂商/CLI 关闭和开启厂商的组合；release 另检查实际注册项仍可发现。真实 Cloudflare 和公网 CA 验收必须单独记录。
