# CLI 参数与交互契约

本文件是 account、cert 及后续命令的共同约定。参数来自实际 Clap 声明；新命令复用 `common/args.rs` 的存储/输出和 HTTP 参数组，只暴露自己用得上的能力。

## 确认、输入、输出分别控制

| 参数 | 统一含义 | 不包含的权限 |
| --- | --- | --- |
| `-y / --yes` | 自动接受当前命令所有操作确认 | 不选目标、不填写缺失输入、不自动同意条款、不绕过校验、不强制重放 mutation |
| `--accept-terms` | 注册时同意所选 CA 当前实际公布的条款 | 不确认复用已有账户，不作为永久自动接受配置 |
| `--verify` | 查询已有资源的 CA 状态，更新观察快照 | 不启动验证、不 finalize、不新建订单 |
| `--json` | 输出结构化命令结果/诊断，禁止提示、ANSI 和人类阶段日志 | 不隐含确认或强制，不猜测歧义目标 |

没有通用的 `--skip-*` 同义参数。--yes 不等于“完全非交互”：终端里的名称选择、输入、独立条款同意仍有自己的条件；脚本应提供完整参数，JSON 或非 TTY 从不弹问题。没有 --yes 的危险操作在交互终端默认否，在脚本中立即给出确认要求。取消交互退出 130。

## 当前 --yes 的范围

| 命令 | --yes 确认什么 |
| --- | --- |
| `account register` | 复用/继续已经存在的本地身份；不代替 --accept-terms |
| `account update-contact` | 替换或显式清空已有账户联系人 |
| `account rotate-key` | 轮换或对账当前保存的换钥事务 |
| `account deactivate` | 不可逆地停用 CA 账户 |
| `account remove` | 删除本地托管账户资料及私钥 |
| `cert remove` | 确认所选申请或显式 --history/--revoked/--failed/--all 的本地清理范围；不会吊销 CA 证书 |
| `cert revoke` | 永久吊销所选版本；多版本仍需明确选择，超时后显式重试沿用原原因 |
| `cert issue --resume <NAME>` | 跳过“Have you published these TXT values?”，然后正常检查 DNS |

人工验证首次脚本调用先返回新材料待办，--yes不能让尚未展示的材料被当作已发布。非TTY/JSON恢复不弹问题；必须--yes显式确认，否则仍返回action_required。终端未带--yes可现场确认；CA始终决定实际授权。

--yes 不出现在 list/show/switch/recover/version；这些命令没有相同的危险操作确认。issue/renew及后续验证实现均按这里的通用确认语义扩展，不让 --yes 获得额外隐式权限。

## 名称与选择

- account 的单账户命令支持位置 `[NAME]` 和 `-n/--name`，互斥；名称统一为 1–64 位 ASCII 字母、数字、下划线或连字符。
- `cert issue -n/--name` 设置长期证书名称，缺省为首个规范化域名加随机后缀；自动名称碰撞换串重试，仅用户指定的已存在名称拒绝；`-a/--account` 使用与账户命令一致的名称校验。
- `cert list -n/--name` 筛选证书；`cert show [NAME]` 和 `cert show -n/--name NAME` 等价且互斥。
- `cert issue --resume [NAME]` 从证书名称恢复（终端可省略 NAME 交互选择，脚本必须提供），不与创建用的 -d/-n/-a 混用。`--operation` 接受完整申请 ID，恢复时必须与 --resume 一起使用。
- `cert show --operation ID` 可以直接定位申请；无参数时终端先选证书，多申请再选具体请求，脚本必须明确目标。
- 多申请选择仅显示主域名、UTC 申请时间和状态；界面行身份与显示标签分离，同标签也不会误选第一行。--yes 不跳过这一选择。
- 所有已有账户命令先验证本地身份；只有 register 可以创建缺失的本地身份。不存在账户不进入确认或 HTTP。

## 短参数字典

| 短参数 | 长参数 | 范围 |
| --- | --- | --- |
| `-h` | `--help` | 命令帮助 |
| `-V` | `--version` | 根命令版本 |
| `-n` | `--name` | 账户目标、证书名称/目标/筛选 |
| `-a` | `--account` | cert issue 的账户选择 |
| `-d` | `--domain` | cert issue 的域名，可重复 |
| `-k` | `--key-type` | cert issue 的证书公钥算法，默认 ecdsa-p256；与 resume 互斥 |
| `-c` | `--challenge` | manual_dns/manual_http/webroot/standalone/tls_alpn；webroot用-w，监听用--listen-address |
| `-m` | `--contact` | account register/update-contact 的邮箱，可重复 |
| `-y` | `--yes` | 上述命令的操作确认 |

其他参数保留明确长名称，不为每个选项硬配短字母。删除的 order、--solver、-c dns-01、--config 不保留兼容别名。

## 命令参数范围

所有 account/cert 命令共用 --data-dir / --json；下表列出其余业务参数。不是全局参数的选项，不向无关子命令泄漏。

| 命令 | 业务参数 |
| --- | --- |
| account list | --verify；--user-agent / --request-timeout 仅在 verify 时可用 |
| account show | [NAME] / -n；--verify；已有账户 CA 选择；HTTP 参数要求 verify |
| account switch | [NAME] / -n；仅本地操作，无 CA/HTTP/注册参数 |
| account register | [NAME] / -n、-m、-k/--key-type、--ca / --ca-directory、--accept-terms、HTTP、-y、成对 EAB |
| account recover | [NAME] / -n、已有账户 CA 选择、HTTP；不创建新密钥/新 CA 账户 |
| account update-contact | [NAME] / -n、-m 或 --clear-contacts、已有账户 CA 选择、HTTP、-y |
| account rotate-key | [NAME] / -n、-k/--key-type、已有账户 CA 选择、HTTP、-y |
| account deactivate | [NAME] / -n、已有账户 CA 选择、HTTP、-y |
| account remove | [NAME] / -n、-y；仅本地操作 |
| cert renew | [NAME] / -n 或 --all；--now、-y、HTTP、--operation-timeout；定义固定，未到期返回 not_due |
| cert deploy | run/add/list/show/update/remove [CERT_NAME]；show 另接受位置 DEPLOY_NAME，其余部署名称用 -n/--name；add/update 提供目标、reload、权限配置 |
| cert issue | -n、重复 -d、-a、-c manual_dns/manual_http/webroot/standalone/tls_alpn、webroot的-w、监听的--listen-address、-k/--key-type；或 --resume NAME / --operation ID；-y、HTTP、--operation-timeout |
| cert list | -n 筛选；默认每个托管证书一行，--history 展开版本；不访问 CA |
| cert show | [NAME] / -n、--operation 或 --history、--verify；默认 in_use，HTTP 参数要求 verify |
| cert revoke | [NAME] / -n、--operation、可选 --reason、-y、HTTP；不删除本地文件 |
| cert remove | [NAME] / -n、--operation 或 --history/--revoked/--failed/--all、-y；纯本地，无 HTTP 参数 |
| version | 仅 --json，不读取配置或初始化状态 |

已有账户的显式 CA 选择只用于匹配其绑定，不能修改绑定。--name 表示当前子命令的目标；--account 专门表示证书申请使用的账户，避免两个名字含混。

## 参数组及互斥

- `--data-dir PATH`：唯一状态根覆盖；也可设置 `ASTER_ACME_DATA_DIR`。命令行参数优先于环境变量，未设置时使用平台默认目录；配置固定为状态根中的 config.toml。所有账户/证书操作共用；version/help 不加载状态。
- 常驻 `daemon run` 的周期默认60秒，可设置 `[config].daemon_interval` 或传入 `--interval SECONDS` 覆盖（1–86400秒；CLI优先于配置）。值在启动时加载，修改配置后重启daemon生效。
- `--ca` 与 `--ca-directory` 互斥；内置只有公开生产提供商 letsencrypt/zerossl/google。已有账户始终绑定原 CA，显式不同 CA 拒绝，不因选项换成新账户。
- `--user-agent` 与 `--request-timeout`：只在确实需要 HTTP 的命令暴露。show/list 的这些参数要求 --verify。timeout 为单请求 1–300 秒；--operation-timeout 为签发前台总预算 1–86400 秒，与 CA expires 独立。
- 显式 register User-Agent 保存为账户偏好；其他命令覆盖只影响本次。内置默认值不落盘，config 不拥有全局 User-Agent。
- `--contact` 是完整替换列表，`--clear-contacts` 明确清空，二者互斥；缺省输入不当作清空。
- `--eab-kid` 与 `--eab-key-file` 必须成对且只属于注册。秘密从文件读取，不直接放 CLI 参数中。

## 证书部署

执行部署/添加绑定只查询已完成、当前 in_use 且没有吊销意图的证书；查看/移除绑定查询托管库存，允许已吊销、吊销未确认或没有当前版本的记录，执行时不会发布文件或 reload。部署命令与 show/renew/remove 共用证书选择器：交互终端省略 NAME 时列出托管证书供选择；JSON/非交互必须明确名称，不自动猜测目标。`list` 无绑定时显示空状态和添加提示；有绑定时复用公共表格对齐、表头和状态配色，仅显示保存的执行状态，不宣称服务当前健康。deploy 的证书选择行额外展示 `deployments: none` 或 `deployments: N`，数量来自同一次库存查询读取的 cert.toml，不逐证书另查；其他选择器行不增加该字段。

`cert deploy add [CERT_NAME] [-n DEPLOY_NAME]` 保存一个证书部署绑定并立即执行首次发布。部署名称的命令行输入只通过 `-n/--name` 指定；交互终端省略时提示名称，首个默认建议 default，已有同名时建议未占用的 deploy-N，Enter 接受或编辑，重名/非法输入原地重试。非TTY/JSON省略时在 storage 的证书租约内生成 deploy-<随机后缀> 并有限处理碰撞。接受的交互名称和显式 -n 都在 storage 保存前重新检查唯一性，不静默更改。证书始终是已有托管证书，不生成新的证书身份。

交互终端执行裸 add 时先选择证书、确认或修改默认部署名称，再输入已存在的目标目录，最后询问可选 reload 命令；留空则只发布文件，不启动进程。交互引导只支持目录，精确文件地址需要显式传参。目标使用 `--target DIR`（写入 fullchain.pem、cert.pem、ca.pem、private-key.pem），或独立提供 `--cert-path`、`--key-path`、`--ca-path`、`--fullchain-path` 的任意非空组合，只发布指定的产物，不强制配对或依赖。目录模式与精确路径互斥，所有精确目标必须互不相同，父目录必须预先存在且由部署操作者控制；Unix在准备时固定父目录句柄，之后相对该句柄创建、替换、清理和同步；已发现父目录身份变化时拒绝提交。初始路径解析及Windows路径发布仍要求受信任祖先目录，不能把路径检查当作恶意目录替换的安全边界。无效输入会留在提示内重试，取消不保存绑定。脚本/JSON 必须提供 CERT_NAME 与完整目标路径，部署名和 reload 均可省略（脚本不询问部署名），不弹提示。

全部选定文件先在各自父目录完成暂存、写入、设权和同步，再逐文件原子替换并同步父目录；准备阶段任何失败都不改变现有目标，正常错误返回时清理已准备临时文件。提交前重新检查整组目标，拒绝准备期间变成目录或链接的路径。部署直接发布普通文件并保持目录路径，不使用部署链接或目录交换，不保证整组切换。提交中途失败可能留下部分更新，记录PublishFailed且不执行reload；显式run重新发布完整选定集合，全部成功后才reload。手动add/run与自动部署均传播取消，等待已启动的文件发布结束并保存结果后才返回；若成功发布但取消阻止reload，保存PublicationComplete；发布失败保存PublishFailed。执行中的reload取消保存ReloadUncertain，不自动重放；reload意图保存后但进程未启动就取消时恢复尝试前的状态，不计为已启动。显式重试在取得新reload确定结果前保留原不确定状态，发布前取消或发布失败不能解除自动执行屏障。手动取消保留本次及已完成的多绑定部署报告和events（JSON亦然），后续绑定不启动，不由命令出口丢弃。进程崩溃可能遗留临时文件，不按前缀擅自清理。Unix 默认0600；add/update 的 `--file-mode 0644` 设置证书、CA链和fullchain，`--key-mode 0640` 单独设置私钥。输入为3–4位八进制且仅接受000–777普通权限位，在临时文件发布前设置，不修改父目录。权限随绑定保存并用于后续续期；Windows 使用继承权限，显式 Unix mode 明确报不支持，不静默忽略。服务必须能读取配置后的私钥。

可选 `--reload-cmd "systemctl restart nginx"` 按引用规则拆成程序与 argv，不启动 shell。未配置命令时发布完成即 deployed，attempts=0；不会声称 reload 成功。`--reload-timeout` 仅在配置 reload 时限制每次进程及输出收集，默认30秒（1–3600）；`--max-retries` 为额外尝试次数，默认3（0–10）。续期后仍默认自动部署，只有配置了 reload 才执行进程。

手动部署实时展示reload的stdout/stderr，自动部署在证书结果后的统一部署区展示；每条输出注明目标、尝试次数与输出流。每次尝试每路保留最多64KiB，超限继续排空并标记截断；失败和超时也保留已收集内容，错误包含退出状态或启动/等待原因。JSON只输出一个结构化结果，通过events/deployment_events携带输出、level、时间和目标，不夹杂人类日志。进程输出不自动脱敏、不写入cert.toml。超时或取消终止拥有的Unix进程组/Windows Job Object，正常结束也清理残留后代；不保证回收主动脱离该组/job的daemon。超时/中断及已启动但无法观测退出状态均保留ReloadUncertain，不自动重放；只有明确启动失败或已知非零退出才按配置重试。

`cert deploy update [CERT_NAME] -n DEPLOY_NAME` 至少需要一个配置修改，可省略部署名称在终端选择。未指定的配置保留；`--clear-reload` 清除命令且与 `--reload-cmd` 互斥。提供目标参数时整体替换目的路径集合，未提供的产物不再发布；它不删除原目标文件。配置变化通常清空执行检查点并返回configured；原Reloading/ReloadUncertain及generation必须保留，直到显式部署得到确定结果，仅保存，不发布或reload；下一次显式run或续期应用修改。

存储层在跨证书配置锁和证书租约下拒绝重复/冲突目标（含目录展开、父目录链接及..别名），并禁止覆盖托管账户、证书和控制文件；每次执行重新检查。某个目标打开/发布/reload失败后继续其他目标，单次及批量报告退出非零。打开前失败不会篡改历史成功检查点：本次列表显示execution failed，JSON保留saved status并另附execution_error；仅list仍展示保存状态。自动部署库存读取失败也报告错误，不将空结果当成功。

`cert deploy list [CERT_NAME]` 查看状态；`cert deploy run [CERT_NAME]` 部署全部绑定，`cert deploy run CERT_NAME -n DEPLOY_NAME` 只部署一个，也用于检查服务后显式重试失败/不确定结果。`cert deploy remove CERT_NAME -n DEPLOY_NAME` 只删除绑定，不删除已发布文件，成功只输出 `[DONE] Deployment 'DEPLOY_NAME' removed.`；JSON 返回 status=removed、certificate、deployment，不列剩余绑定。

除 `cert deploy show CERT_NAME DEPLOY_NAME` 明确允许两个位置参数外，每个命令最多一个业务位置参数。终端省略 CERT_NAME 时选择现有证书；run 缺 -n 执行全部，remove/update 缺 -n 可交互选择，非交互必须给 -n。`--data-dir`/`--json` 位于具体子命令；删除旧操作选项和第二个位置参数，不保留别名。未配置权限时采用平台默认策略，已保存reload命令继续生效。


`cert deploy show [CERT_NAME] [DEPLOY_NAME]` 只读展示完整绑定配置及保存的执行状态：目录模式展开四个文件路径，精确路径模式标出各配置项及未配置项；包含实际 reload argv、单次超时、额外重试次数、最近世代/状态/次数/错误。不会读取证书私钥内容、发布文件、执行reload或访问CA；已吊销或没有当前版本的绑定仍可检查。与 list 的摘要不同，show 是明确查看配置的入口，会显示配置中的 reload 命令和参数。人类输出使用公共 field/颜色，JSON 输出 certificate、deployment完整配置与observation=saved local state。

裸 show 在终端先选择证书再选择部署；只给CERT_NAME时选择部署，即使只有一个绑定也会询问；脚本/JSON必须同时给两个名字，不猜测。show 不增加 -n 别名，第三个位置参数/发布选项/--verify 拒绝。非空 list 底部以 Tips 指向 `cert deploy show CERT_NAME DEPLOY_NAME`；remove 仍只有简短成功确认。

## 展示与退出

人类输出由命令级 `common/session::OutputSession` 管理 stdout/stderr、交互/进度状态和一次最终写入；克隆会话共享状态。`common/output::MessageKind` 统一标签与样式，time/log/table/terminal 负责具体呈现。执行层返回 `CommandReport`，渲染层接收显式 `Format`，不探测终端或写流；main 根据报告决定退出码并完成唯一一次输出。进度、确认上下文和 tracing 写 stderr，最终报告写 stdout，执行错误写 stderr。只有实际发生人类输出/交互才在最终结果前分隔一行；写入失败不尝试追加第二份 JSON。

时间为 YYYY-MM-DD HH:MM:SS UTC；JSON/TOML 保存 RFC3339 原精度。stdout/stderr 分别依据 TTY、NO_COLOR、TERM=dumb 决定配色，提示与日志使用 stderr 配色。JSON 禁用交互、人类进度和 tracing；批量及账户列表部分失败保留一份结构化报告并退出非零。

0 表示命令成功执行；cert issue 的 action_required 同样为 0，脚本必须检查 status，不能将其误认为 completed。一般错误为 1，Clap 解析错误沿用 2，交互取消为 130。远端查询失败不标为 verified。

续期计划、ARI 查询/重试与吊销状态契约见 [证书生命周期](certificate-lifecycle.md)。`daemon run-once`执行一个非交互维护周期，`daemon run`在前台持续运行；仅`webroot`、`standalone`、`tls_alpn`自动准入，人工方法报告为跳过。常驻周期默认间隔60秒，可由`config.daemon_interval`或`--interval`覆盖（1–86400秒）。同一data-dir只允许一个常驻daemon，Unix支持Ctrl-C/SIGTERM协作退出；Windows使用Ctrl-C。人类日志沿用签发的带时间戳级别格式，常驻`--json`为JSON Lines，`run-once --json`仍为单份JSON。`run-once`仍可由cron触发。

cert show 的核验按资源区分：JSON 使用 ca_query.order_refreshed / authorizations_refreshed，吊销依据使用 revocation_source，不用整条记录 verified/source。人类输出为 CA query 与 Revocation source，不暗示此次执行已检查 OCSP/CRL。account show 同样使用 CA query，JSON 为 ca_query.account_refreshed；不将本地密钥、联系人或停用意图标为本次远端核验结果。

证书密钥和吊销原因共用库/协议枚举产生 CLI 选项；支持算法与 RFC 原因码、CA 可拒绝边界见生命周期契约。账户 register/rotate-key 同样支持 -k/--key-type，但独立于证书选项；普通账户操作沿用已保存密钥。

--now只在cert renew提前执行，不隐含--yes。DNS跳过及force参数已移除，无别名；issue/renew共享RunArgs，续期不允许定义覆盖。账户list JSON按ca_query记录查询证据，remove只描述本次CA请求。

批量入口为 cert renew --all，与NAME/--name互斥；顺序检查托管身份，not_due/待办/跳过/完成/失败分开计数，单项失败继续，Ctrl-C停止整个批次。批量不弹TXT确认，首次新TXT仍yield。JSON一次输出完整汇总：失败退出1，取消130，待办无失败退出0；不会再追加第二份错误JSON。细节见生命周期契约。

cert issue --resume缺省名称在终端选择未完成申请，显示名称/SAN摘要/UTC时间/状态；脚本提供名称或完整operation ID，不猜最新。完成版本不参与签发恢复选择，DNS预检仅建议，JSON不输出人类日志。

新建 cert issue 在终端补全缺失域名、验证方式、方法配置：域名输入后选择 manual_dns/manual_http/webroot/standalone/tls_alpn，webroot 询问现有目录，standalone/TLS-ALPN 询问带默认值的监听地址。通配符菜单只提供 manual_dns，显式 webroot/listen 参数约束可选方式，冲突参数直接拒绝。显式参数跳过对应询问；无效输入原地重试，取消在账户/配置/密钥/网络副作用前返回。脚本/JSON必须 -c 与 -d，webroot 必须 -w；listener 仍可使用默认80/443。--yes不默认选择验证方式，也不跳过输入。resume与challenge互斥，renew不暴露challenge覆盖，均沿用已保存方式。--yes在issue/renew中自动接受所有操作确认，并非manual_dns专用开关；独立ToS仍要求--accept-terms，名称选择/输入不属于肯定确认。

仅在实际存在证书前台进度时与最终结果之间留一空行；无进度的全未到期批次及单次not_due不加开头空行（JSON不加分隔）；批量标题/计数使用INFO/WARN/ERROR标签，表格复用公共对齐和Style，待办/取消黄色、失败红色、完成绿色、未到期青色。

批量结果表使用 NAME / STATUS / NEXT RENEWAL (UTC)，未到期或本次完成续期的记录显示下次续期时间；待办、失败、跳过和取消不猜测时间，具体说明放在表后。批量不输出重复计划表或逐项Checking日志；有续期/恢复工作时只先报告任务数和未到期数，实际事务持锁复核。仅实际执行项输出进度和Using CA；全未到期时只保留结果表及检查数量总结，其他汇总只展示非零计数。JSON完整计数不变。

每个命令的 `CommandContext` 持有一个惰性 `HttpPool`，批量续期和账户逐项查询共用它；纯本地命令不构造 HTTP 客户端。`AcmeClient` 自己保留池句柄，调用操作无需额外传池。User-Agent 和请求总期限逐请求设置，不改变池或其他账户；CA directory 和 Replay-Nonce 仍归各自 ACME 客户端。共享池不保证代理/服务器始终保留 TCP 连接。


## 账户密钥算法与帮助入口

账户与证书共用 `crypto::key_algorithm::KeyAlgorithm` 和 CLI 解析器，分别选择自己的密钥。`account register -k/--key-type` 接受 ecdsa-p256、ecdsa-p384、ecdsa-p521、ed25519、rsa-2048、rsa-3072、rsa-4096、rsa-8192；新账户缺省 P-256，已有身份缺省沿用，显式不同类型拒绝复用。`account rotate-key -k` 选择新钥；不指定时新轮换沿用原类型，恢复时沿用已暂存的新钥，显式冲突拒绝且不改文件。recover/show/list 等命令不接受算法覆盖。账户 TOML 必须保存实际 `key_algorithm`，加载按真实 PKCS#8/指纹交叉检查；未发布格式直接更新，不读旧格式或增加迁移。

`-h`、`--help`、`help <command>` 共用 common/help 的产品版本、宽度和配色。不增加参数改写：`account help rotate-key` 与 `account rotate-key --help` 为标准入口，`account rotate-key help` 中的 help 仍是账户名。帮助不读取配置、不初始化 HTTP、不生成密钥。


## 意外 panic

仅可执行入口安装 Forge panic alpha.2，使用已解析的数据根；不额外增加 CLI 参数。panic 诊断写 stderr，JSON 沿用单个 `{error:{message,hint}}` 对象，进程退出1；已完成输出不追加第二文档。提示含私有报告位置或不可用原因的安全指引，不包含原始 panic、私钥/凭据或回溯。crash.log 仅 panic 时产生，0600、追加、上限1MiB，原始 Message 移除；不改变已保存申请和密钥，不自动重试远端操作。help/version 与正常执行不创建 crash.log。


## 方法驱动签发及相似请求

新申请显式 -c 或交互选择 manual_dns/manual_http/webroot/standalone/tls_alpn，协议方法由ACME的ChallengeKind决定；webroot要求-w/--webroot PATH或终端输入目录，manual方式不能带此参数。HTTP不接受通配符。resume/renew不允许修改保存的验证实现、协议方法或规范绝对webroot路径。HTTP manual首次脚本先输出URL/path/content待办，显式resume --yes确认已部署；webroot自动发布，不因JSON/批量模式额外要求人工确认。方法、实现配置及类型化材料是当前未发布格式，无旧格式读取/迁移。

本地DNS预检固定限5秒，仅建议：不存在TXT、系统解析器失败和查询超时均WARN后继续CA。用户取消/整体deadline仍终止。DNS skip/force参数已删除，无别名。`--yes`只接受操作确认，不补填验证方式、名称或条款；恢复人工材料才可提交确认。

--if-similar-order 与--resume/--name互斥。新请求没有显式名称时，完整定义匹配库返回的未完成候选；终端默认选择恢复或新建。脚本不带该参数且存在匹配则失败并输出精确恢复命令；带该参数时唯一匹配恢复、零匹配新建、多匹配失败。--yes不承担目标选择。创建已提交而缺少订单URL的记录也是候选，避免静默重复；选中后库仍返回CreationUncertain而不重发newOrder。已过期、invalid及明确CSR拒绝不自动恢复。

Creating ACME order日志同时带实现ID和协议名；创建密钥/CSR日志带托管名称。列表纯文本对齐后着色，至少保留两列空格，恢复命令保留可直接复制的空格。


## Debug诊断

--debug是跨命令诊断选项，可放根命令或具体子命令后。它只打开产品target的安全DEBUG事件，时间/配色/转义复用common/log和输出会话。显示检查点phase、new_order_intent_saved、是否保存order URL、请求类别、HTTP状态/耗时及有限nonce重试序号；不记录私钥、CSR/JWS正文、响应正文、nonce值或带凭据的原始URL。JSON模式仍关闭人类诊断并只输出一份结果/错误；需要详细人类诊断时去掉--json。未传--debug时保留RUST_LOG环境过滤机制。

```sh
aster-acme cert issue --resume <NAME> --yes --debug
```

缺少Location且已记录newOrder意图时，在访问CA directory前由库的check_recovery判断CreationUncertain；不会在公开输出里重复给出无效的“不断resume”建议。Debug无法补回先前已丢失的Location，用户需保留材料并检查后显式决定是否新建独立请求。


--max-polls适用于issue/renew，默认30、范围1–1000，每次调用/每份证书独立计数，只计算订单轮询轮次（其内可有必要授权查询），不计算directory/nonce/挑战通知/finalize。每轮显示(n/limit)，等待注明持久化期限来自Retry-After还是local polling interval；不缩短CA规定的等待，Retry-After为0仍使用100ms最小延迟防止忙循环。达到上限返回PollLimit并保留全部检查点，下次resume重新计数且不新下单。有效授权不重复查询。HTTP预检使用共享池，固定最多5秒、8192字节、最多跟随10次HTTP/HTTPS重定向（TLS证书仍校验）；缺失/错误/超时只WARN继续CA，取消/整体deadline仍停止。


## 三种独立执行限制

| CLI参数 | config.toml字段 | 内置默认 | 范围/含义 |
| --- | --- | --- | --- |
| --request-timeout | request_timeout | 30秒 | 1–300秒；单个HTTP请求连接到响应读取 |
| --operation-timeout | operation_timeout | 600秒 | 1–86400秒；单次证书签发/恢复执行预算，包含CA发现、确认、轮询及自动部署 |
| --max-polls | max_polls | 30轮 | 1–1000；每份证书每次调用的订单轮询次数 |

优先级统一为显式CLI > 配置 > 内置。CLI不写回这些单次覆盖，配置缺省可用内置默认；生成模板写明三项用途。批量续期为每份证书独立应用预算，Retry-After仍限制下次查询，不被轮数覆盖。未发布：timeout配置字段、--timeout及--wait-timeout删除，无兼容别名/自动迁移；已有timeout需由用户改成request_timeout。operation预算目前围绕实际签发执行，不包含进入执行前的账户/证书目标选择。

每轮实际等待均显示来源，取消等待日志节流以免隐藏来源变化。Retry-After未返回或无法解析时使用local polling interval；debug显示响应中解析后的retry_after和调度间隔。HTTP-01从HTTP80入口可按CA策略跳转HTTPS；本地预检最多10次跳转，共享原有时间/内容上限，仍验证HTTPS证书。CA可能采用不同证书校验策略，预检失败仍只是建议。ACME签名请求的禁跳转规则不受影响。

本地轮询默认5秒；config的`poll_interval`或`--poll-interval <SECONDS>`可覆盖（1–300秒），CLI > 配置 > 内置。有效CA Retry-After仍优先；适用于issue/resume及每份证书renew（含--all），配置缺省不写回也能使用5秒。

Webroot自动化输出：INFO逐项记录实际写入、复用、借用和清理的绝对文件路径；DEBUG展示规范webroot、公开URL和HTTP路径映射，提示服务器对/.well-known/acme-challenge/禁用认证/应用重写，HTTP80入口须可达且可按CA策略跳转HTTPS。只在成功发生文件效果后记录对应动作，用户已有/替换文件不报为已删除。

订单invalid是终态，保留供show/--verify检查，不进入恢复选择，显式resume也在CA发现前拒绝。查询首次发现invalid时保存订单，再按需读取授权challenge的problem补全细节，不重发验证。公开诊断显示类型、说明及标识符子问题，不把HTTP200资源error伪装成HTTP400；无problem明确说明未提供。

Webroot在成功签发或已保存CA明确invalid订单后清理本次拥有且内容/身份未变的验证文件及所有权凭据；复用同一cleanup入口。借用、用户替换或修改的文件不删除，站点目录、订单、密钥和CSR保留；修改/权限/保存失败保留cleanup_pending，仍以原始CA problem报告终态。取消、超时、轮询上限及不确定远端结果不触发失败清理；manual实现不自动删文件或DNS记录。既往已记录invalid的申请仍拒绝签发恢复，不以该改动隐式执行用户旧数据清理。

## HTTP standalone and TLS-ALPN

`cert issue -c standalone -d example.com`临时监听`0.0.0.0:80`，`cert issue -c tls_alpn -d example.com`临时监听`0.0.0.0:443`，均无需人工确认或现有Web服务器。仅新申请接受`--listen-address IP:PORT`（非零端口、支持显式IPv6，例如`[::]:80`），与其他验证实现或--webroot组合报错；配置保存后恢复/续期不可覆盖。TLS-ALPN仅按匹配SNI和`acme-tls/1`协商提供RFC 8737挑战证书。公网HTTP-01入口仍是80、TLS-ALPN入口仍是443；自定义本地端口必须自行转发，保留原Host/SNI并处理所有已公布A/AAAA路由。默认IPv4不承诺IPv6双栈。端口占用/权限不足保留申请并明确报错，不停止其他服务或提权。

INFO显示实际监听启动/停止，DEBUG提示转发要求；建议性公网HTTP预检保持限时非阻塞。成功、invalid、取消、总期限和轮询上限均关闭监听并回收连接；恢复重建原挑战响应但不重复ack。单次监听最多64个活动连接，每连接最多5秒，HTTP响应只提供已保存域名/路径的GET、不写文件；TLS listener只提供保存的挑战证书。服务仅存活于当前调用，所有终态关闭监听和连接。

RFC错误证据与恢复：newOrder完整错误响应保存creation_failure（实际status、problem、绝对retry_at），不伪造Order invalid；创建拒绝/408或429延后/5xx未确认均不进入无URL恢复候选，不重发newOrder。finalize badCSR按实际4xx状态保存；orderNotReady明确拒绝后先查询订单，只有再次ready才提交相同CSR，轮询预算仍约束。授权invalid/deactivated/expired/revoked及选中challenge invalid保留具体problem并拒绝恢复，已valid订单仍可下载。具体RFC映射与未覆盖能力见[错误状态核对](rfc-reference.md)。未发布finalize_rejection字段直接更新为HTTP证据结构，无旧格式兼容或用户数据回填。

## 查询筛选与写入边界

所有库存查询均为本地快照，无 HTTP 或私钥加载。账户列表用 AccountQuery（默认全部）；既有账户交互按显式 CA/usable 或 core operation 资格过滤（Update/Deactivate/RotateKey，未确认轮换仍可恢复），注册为了检查名称占用保留全部本地名称。明确名称的账户操作直接读取该身份。

| 证书入口 | 查询范围 |
| --- | --- |
| list | name 可选，Managed 投影；--history 为 All |
| show | name/operation 可选，默认 CurrentOrUnfinished；历史/精确 operation 为 All |
| issue --resume | name/operation 可选，unfinished + resumable；无候选时明确名称可再读原始错误供诊断 |
| issue 相似申请 | unfinished + 完整域名/账户/CA/密钥/solver 定义匹配及显式 now |
| renew | 单次 name 可选 + in_use；--all 为 Managed，缺当前版本仍记录 skipped |
| revoke | name/operation 可选，只选择 completed 版本 |
| remove | name/operation 可选；history 为非当前 completed，revoked 为已确认吊销，all 为 Managed；删除 scope 持锁后重新计算 |
| deploy | name 可选 + in_use + completed + 无吊销意图；添加/执行时持锁复核 |

查询不代替执行前资格验证；storage 不接受 SQL 字符串或 CLI 交互策略。默认投影先确定版本，再按状态筛选，避免被条件过滤后意外选回旧证书。

## 交互覆盖核对

| 命令 | 当前交互入口 | 仍需显式指定的部分 |
| --- | --- | --- |
| account register | 新建/继续、账户名、CA、联系人、条款和复用确认 | EAB、密钥算法等高级选项 |
| account show/switch/recover | 缺名称选择已有账户 | verify 等查询/行为开关 |
| account update-contact/rotate-key/deactivate/remove | 账户选择、联系人输入或操作确认 | key-type 等可选参数使用默认/显式值 |
| cert issue | 缺域名输入、验证方式选择、webroot目录或standalone/TLS-ALPN监听地址输入；相似申请选择、人工发布确认 | 脚本须-c/-d和必要目录；账户/密钥类型等使用显式参数或配置/内置默认 |
| cert issue --resume | 缺名称选未完成申请，多版本选择 | 脚本必须精确指明歧义目标 |
| cert show/revoke/remove/renew | 缺名称选证书，必要时选版本；危险操作确认 | revoke reason、renew --now 等行为选项 |
| cert deploy add | 选证书、名称建议可确认/修改、输入现有目录、可选 reload；脚本缺省部署名自动生成 | 四种精确文件路径只能显式传入 |
| cert deploy run/list/remove | 选证书；remove 缺名可选绑定；run 缺名默认全部 | 部署名仅通过 -n/--name 或既定交互/默认行为 |
| account list、cert list、version、help、cert renew --all | 直接输出/按既定范围执行，无需选择 | 不添加无意义的输入流程 |

顶层及 account/cert/deploy 命令组仍需显式选择子命令，不提供动作菜单；JSON/非TTY按设计完全不交互。除了 deploy show 的证书/部署名两个位置参数，其余业务命令最多一个位置参数，由解析测试递归验证；子命令路径和选项值不计为业务位置参数。

构建标识的dirty仅描述Git已跟踪文件修改，不包含未跟踪文件；归档构建不会借用父目录仓库revision。Windows存储成功不承诺掉电后的rename目录项持久性，进程重启恢复与断电恢复分开。

`cert deploy show`是操作者显式查看本地配置的入口，按请求展示保存的reload命令与参数；与普通列表、执行摘要不输出argv的边界不同。调用方应按敏感配置保护其输出，工具不按参数名猜测和破坏原始配置。

CAA建议性检查：issue/renew在首次newOrder前按directory的meta.caaIdentities核对所有域名及通配符；多个CA身份任选匹配，不要求全部配置。各域名按RFC8659取首个非空有效CAA集合，不混合各层记录；检查issue/issuewild及RFC8657参数。CAA阶段全部域名共用5秒预算，DNS失败、不匹配、未知属性和超时均只提示并继续；没有caaIdentities时无法判断且不猜测身份。CAA结果仅明确匹配或无适用限制使用INFO，未匹配、未知、不可用、失败、超时和未检查均使用WARN；等级不改变建议性语义。恢复已有订单不重查，不修改DNS或保存请求状态。取消／整体deadline仍停止。TXT与HTTP预检移至同一precheck层，但在挑战发布后执行，不提前读取尚不存在的材料。

预检为编译期可选能力：CLI的默认precheck feature启用CAA/TXT/HTTP建议性观察，`--no-default-features`构建不调用这些预检，仍保留CA正式验证与正常签发。嵌入者直接使用库的feature-gated Runner与检查器，不需要CLI，也不会由IssueService隐式增加DNS/HTTP观察请求。

`cert remove NAME --failed`清理该名称下明确失败且不可恢复的未签发申请；终端省略NAME时只从失败候选中选择，非交互必须给出名称。creation明确4xx拒绝（排除408/429）、固定CSR被拒、order/authorization终态和订单过期可匹配；已签发、in_use、可恢复以及远端结果未知的申请保留。筛选由IssueRecord规则与storage查询提供，执行持锁重验；需确认或--yes，不访问CA，也不自动删除DNS/webroot材料或部署副本。

人工验证确认复用其他命令相同的inquire::Confirm：默认否，y/yes和n/no、退格编辑、可见输入，由控件恢复终端模式。Esc/Ctrl-C即时结束；当前inquire没有外部中断接口，整体期限或程序取消在用户结束输入后复核，不再执行后续CA操作。
