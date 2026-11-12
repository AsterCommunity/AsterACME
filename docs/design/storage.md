# 存储查询、平台发布与恢复

本文描述当前实现；长期边界见[项目契约](../project-contract.md)，验证记录见[测试入口](../testing.md)。

## 标准库优先与桌面平台存储

最低 Rust 1.99 已覆盖 1.89 稳定的 File::try_lock/unlock；账户/配置租约与 panic 报告锁均使用标准库，移除 aster-fs 的 workspace/成员/lockfile 依赖。FileLease 仍负责显式释放，配置有限等待、取消后持锁完成写入及对象外置锁路径不变。AsterFs [#4](https://github.com/AsterCommunity/AsterFs/issues/4) 固定生态职责：补充标准库缺口而非封装每个 std::fs 操作，不承担 fs2/fs4 接口兼容义务；[#3](https://github.com/AsterCommunity/AsterFs/issues/3) 跟踪可信目录安全打开。模块顶部 TODO 标明尚未上游交付的身份/链接检查及持久化能力。

state_file 集中必要平台差异。Unix 复用 Forge 的目录描述符 IO 并保留 owner、单链接和 0700/0600 检查；Windows 使用标准库读写/替换及最小 winapi-util 句柄信息查询，拒绝 reparse point/托管文件硬链接，不管理 ACL。Windows 原子文件替换前同步文件；目录仅验证可访问，不把缺少目录 flush 的实现冒充 Unix 的目录持久化保证。普通 IO 和锁不要求依赖 AsterFs。平台检查 future API 真正交付后再替换临时适配。

Windows in_use 是完整副本目录，含 fullchain.pem/cert.pem/ca.pem/private-key.pem 与 .generation 所有权标记；Unix 保持相对符号链接。先在同级 .in_use-<operation> 准备全部文件，再把旧目录保留到 .in_use.previous，最后把完整新目录改名为 in_use。catalog 提交前保留旧副本；持证书锁重启后按已保存选择回滚或清理。它有两次 rename 间的可见空隙，属于可恢复切换，不保证外部读取者跨平台无间隙或原子交换。未知用户内容不删除，失败不逐个覆写正在使用的四个文件。

本地托管名称使用跨平台纯校验，拒绝路径转义、Windows 设备名和尾点；DNS 通配符仍在 identifiers 中，自动托管名使用 wildcard- 前缀，不能把 * 放进 Windows 路径。平台原生 CI 矩阵覆盖 Linux/macOS/Windows；交叉编译只证明构建与类型，运行结果需另行确认。


## 存储查询与资源边界

`aster_acme::storage::account` 提供账户 metadata/key/rotation 契约，`storage::issuance` 提供证书 store/session 契约，`storage::query` 定义 `AccountQuery`、`IssueQuery`、完整定义匹配及版本投影。实现无文件系统依赖，文件适配器仍在 cli_storage，数据库适配器可用相同查询语义。

CLI 将查询条件交给 storage，负责交互、歧义处理和渲染。name 查询避开无关目录；operation/in_use 避开无关 journal；Managed 投影支持 list/renew --all，每个托管名一行且保留无 in_use 项作为显式 skipped。show 默认为 CurrentOrUnfinished；显式历史保留全部；revoke 只选择已签发世代；resume 和相似申请经查询谓词筛选。执行资格仍在持锁事务复查，查询结果不授权 mutation。

账户 list --verify 只刷新被验证账户的快照，不重新枚举目录；单次及批量证书操作的 Ctrl-C 等待任务由 RAII guard 管理；部署共享只读产物，阻塞写入保留租约直到完成。签发后部署事件与手动 deploy 共用事件生成、日志和表格渲染，人类报告按证书完成→空行→Started deployment→发布/reload→部署列表排列；JSON 仍只有一份结构化结果。

部署配置/目的路径归storage的 `issuance/deployment/{targets,permissions,update}`：跨证书配置锁先于证书租约获取，add/update/open均检查路径所有权；证书租约覆盖发布与reload，配置锁在open完成后释放。路径检查展开目录目标并规范化父路径，拒绝跨绑定覆盖和写入托管状态，不引入第二份目标注册表。update只更改配置及重置变化后的检查点，保留原目标文件。产物发布归 `issuance/deployment/publication`：全部选定文件先在各自父目录暂存、设权、同步，完整prepare成功后才进入commit逐一替换。临时文件集合通过RAII持有，准备失败不改现有目标并清理临时文件；提交前重新检查整组路径，单个替换前再次检查。Unix发布适配器只打开最终父目录，不要求祖先目录可读；初始路径解析由内核按搜索权限遍历。在prepare时保留父目录句柄，以openat/renameat/unlinkat及句柄sync完成暂存、替换、清理与持久化，避免最终路径检查后的父目录替换重定向IO；路径身份复核只负责提前失败。初始父路径解析仍需要可信祖先，Windows路径适配器仍依赖父目录及祖先受信任。目录路径保持稳定，直接发布普通文件，不使用部署链接或目录交换；整组原子切换不作保证。手动及自动执行在取消后仍等待已启动发布并保存结果；发布失败记录PublishFailed，发布成功但取消阻止reload时记录PublicationComplete。已有Reloading/ReloadUncertain在显式重试的发布期间保持，直到新reload获得确定结果；未spawn就取消时恢复前一个检查点，命令出口保留已产生的部署报告和事件。崩溃可能留下Publishing，显式重试重新发布完整选定集合；只有publish返回成功才reload，不自动回滚或宣称服务已加载。进程崩溃不保证临时文件自动清理。

CLI部署执行逐目标收集错误，库存/打开/锁失败不冒充空列表或历史成功；执行事件独立于保存的绑定状态，报告同时保留本次execution_error与历史状态。reload生命周期由小型process-wrap适配提供Unix进程组和Windows Job Object，取消时Drop清理、超时终止并有界回收；启动后wait失败记录ReloadUncertain，不与可重试的spawn失败混淆；stdout/stderr并行排空且每路每次只收集64KiB。手动输出实时显示，自动输出随统一部署报告显示；内容仅存本次events，不持久化到cert.toml，不承诺自动脱敏或终止主动脱组的daemon。

新申请输入补全由 CLI 的 cert/interaction 模块负责，所有显式与交互配置调用同一个 validation::configuration 校验。输入步骤在账户选择、config初始化、私钥创建和 CA discovery 前完成；恢复/续期沿用保存定义，不进入新申请向导。交互菜单复用 ValidationMethod 的 ValueEnum 注册表/帮助描述，不维护平行方式列表。

Windows状态写入只保证替换完成和进程重启恢复；临时文件先sync，但尚无持久化rename目录项的机制，不承诺掉电事务。账户删除和轮换确认以原账户身份/事务快照为条件，重新持锁复核。普通账户写任务共享操作租约，取消等待不提前放锁；同一换钥会话的stage/save/commit串行化。Confirmed换钥恢复只提交本地状态，不依赖directory。已保存签发以稳定账户ID、directory和kid匹配；历史指纹仅继续绑定原验证材料，不要求等于轮换后的签名器指纹。

证书调用在CA发现前建立同一取消/deadline，自动部署继承剩余预算，取消后不启动部署；批量不从外层丢弃可能已经提交产物的事务。手动确认的终端轮询有界，shutdown等待读取结束并恢复raw mode；Esc/Ctrl-C作为CLI取消，终端IO失败独立报告。Webroot清理将路径实际对象移入私有临时目录再核验；身份改变则无覆盖恢复，恢复冲突保留隔离内容并报告位置。
