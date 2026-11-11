# CLI 参数与交互契约

本文件是 account、cert 及后续命令的共同约定。参数来自实际 Clap 声明；新命令复用 `common/args.rs` 的存储/输出和 HTTP 参数组，只暴露自己用得上的能力。

## 确认、输入、输出分别控制

| 参数 | 统一含义 | 不包含的权限 |
| --- | --- | --- |
| `-y / --yes` | 自动接受当前命令所有操作确认 | 不选目标、不填写缺失输入、不自动同意条款、不绕过校验、不强制重放 mutation |
| `--accept-terms` | 注册时同意所选 CA 当前实际公布的条款 | 不确认复用已有账户，不作为永久自动接受配置 |
| `--skip-dns-check` | 在 cert issue/renew 跳过本地 DNS 可见性检查 | 不免除 CA 验证，不忽略过期/身份/密钥/CSR/证书检查，不覆盖用户文件 |
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
| `cert remove` | 确认所选申请或显式 --history/--revoked/--all 的本地清理范围；不会吊销 CA 证书 |
| `cert revoke` | 永久吊销所选版本；多版本仍需明确选择，超时后显式重试沿用原原因 |
| `cert issue --resume <NAME>` | 跳过“Have you published these TXT values?”，然后正常检查 DNS |

首次手动 DNS 自动化申请必须先让用户/脚本取得新 TXT 值；即使传 --yes/--skip-dns-check 也返回 action_required，不因“确认”假设记录已发布。首次终端申请未带 --yes 时仍可以现场输入和继续。发布后 resume，仍由 CA 完成实际验证。没有 --yes 的非 TTY/JSON resume 也不弹提示，按已有脚本行为直接检查 DNS；--yes 是显式确认语义，保持非终端一律不提示的统一规则。

--yes 不出现在 list/show/switch/recover/version；这些命令没有相同的危险操作确认。issue/renew及后续验证实现均按这里的通用确认语义扩展，不让 --yes 获得额外隐式权限。

## 名称与选择

- account 的单账户命令支持位置 `[NAME]` 和 `-n/--name`，互斥；名称统一为 1–64 位 ASCII 字母、数字、下划线或连字符。
- `cert issue -n/--name` 设置长期证书名称，缺省为首个规范化域名加随机后缀；自动名称碰撞换串重试，仅用户指定的已存在名称拒绝；`-a/--account` 使用与账户命令一致的名称校验。
- `cert list -n/--name` 筛选证书；`cert show [NAME]` 和 `cert show -n/--name NAME` 等价且互斥。
- `cert issue --resume NAME` 从证书名称恢复，不与创建用的 -d/-n/-a 混用。`--operation` 接受完整申请 ID，恢复时必须与 --resume 一起使用。
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
| `-c` | `--challenge` | 验证实现，目前只有 manual_dns |
| `-m` | `--contact` | account register/update-contact 的邮箱，可重复 |
| `-y` | `--yes` | 上述命令的操作确认 |
| — | `--skip-dns-check` | cert issue 的本地 DNS 检查覆盖 |

其他参数保留明确长名称，不为每个选项硬配短字母。删除的 order、--solver、-c dns-01、--config 不保留兼容别名。

## 命令参数范围

所有 account/cert 命令共用 --data-dir / --json；下表列出其余业务参数。不是全局参数的选项，不向无关子命令泄漏。

| 命令 | 业务参数 |
| --- | --- |
| account list | --verify；--user-agent / --timeout 仅在 verify 时可用 |
| account show | [NAME] / -n；--verify；已有账户 CA 选择；HTTP 参数要求 verify |
| account switch | [NAME] / -n；仅本地操作，无 CA/HTTP/注册参数 |
| account register | [NAME] / -n、-m、-k/--key-type、--ca / --ca-directory、--accept-terms、HTTP、-y、成对 EAB |
| account recover | [NAME] / -n、已有账户 CA 选择、HTTP；不创建新密钥/新 CA 账户 |
| account update-contact | [NAME] / -n、-m 或 --clear-contacts、已有账户 CA 选择、HTTP、-y |
| account rotate-key | [NAME] / -n、-k/--key-type、已有账户 CA 选择、HTTP、-y |
| account deactivate | [NAME] / -n、已有账户 CA 选择、HTTP、-y |
| account remove | [NAME] / -n、-y；仅本地操作 |
| cert renew | [NAME] / -n 或 --all；--now、-y、--skip-dns-check、HTTP、--wait-timeout；定义固定，未到期返回 not_due |
| cert issue | -n、重复 -d、-a、-c manual_dns、-k/--key-type；或 --resume NAME / --operation ID；-y、--skip-dns-check、HTTP、--wait-timeout |
| cert list | -n 筛选；默认每个托管证书一行，--history 展开版本；不访问 CA |
| cert show | [NAME] / -n、--operation 或 --history、--verify；默认 in_use，HTTP 参数要求 verify |
| cert revoke | [NAME] / -n、--operation、可选 --reason、-y、HTTP；不删除本地文件 |
| cert remove | [NAME] / -n、--operation 或 --history/--revoked/--all、-y；纯本地，无 HTTP 参数 |
| version | 仅 --json，不读取配置或初始化状态 |

已有账户的显式 CA 选择只用于匹配其绑定，不能修改绑定。--name 表示当前子命令的目标；--account 专门表示证书申请使用的账户，避免两个名字含混。

## 参数组及互斥

- `--data-dir PATH`：唯一状态根覆盖；配置固定为其中的 config.toml。所有账户/证书操作共用；version/help 不加载状态。
- `--ca` 与 `--ca-directory` 互斥；内置只有公开生产提供商 letsencrypt/zerossl/google。已有账户始终绑定原 CA，显式不同 CA 拒绝，不因选项换成新账户。
- `--user-agent` 与 `--timeout`：只在确实需要 HTTP 的命令暴露。show/list 的这些参数要求 --verify。timeout 为单请求 1–300 秒；wait-timeout 为签发前台总预算 1–86400 秒，与 CA expires 独立。
- 显式 register User-Agent 保存为账户偏好；其他命令覆盖只影响本次。内置默认值不落盘，config 不拥有全局 User-Agent。
- `--contact` 是完整替换列表，`--clear-contacts` 明确清空，二者互斥；缺省输入不当作清空。
- `--eab-kid` 与 `--eab-key-file` 必须成对且只属于注册。秘密从文件读取，不直接放 CLI 参数中。

## 展示与退出

人类输出由命令级 `common/session::OutputSession` 管理 stdout/stderr、交互/进度状态和一次最终写入；克隆会话共享状态。`common/output::MessageKind` 统一标签与样式，time/log/table/terminal 负责具体呈现。执行层返回 `CommandReport`，渲染层接收显式 `Format`，不探测终端或写流；main 根据报告决定退出码并完成唯一一次输出。进度、确认上下文和 tracing 写 stderr，最终报告写 stdout，执行错误写 stderr。只有实际发生人类输出/交互才在最终结果前分隔一行；写入失败不尝试追加第二份 JSON。

时间为 YYYY-MM-DD HH:MM:SS UTC；JSON/TOML 保存 RFC3339 原精度。stdout/stderr 分别依据 TTY、NO_COLOR、TERM=dumb 决定配色，提示与日志使用 stderr 配色。JSON 禁用交互、人类进度和 tracing；批量及账户列表部分失败保留一份结构化报告并退出非零。

0 表示命令成功执行；cert issue 的 action_required 同样为 0，脚本必须检查 status，不能将其误认为 completed。一般错误为 1，Clap 解析错误沿用 2，交互取消为 130。远端查询失败不标为 verified。

续期计划、ARI 查询/重试与吊销状态契约见 [证书生命周期](certificate-lifecycle.md)。周期 ARI 刷新由后续 daemon 唤醒；本轮只有首次签发查询、显式 verify 时到期刷新和嵌入接口。

cert show 的核验按资源区分：JSON 使用 ca_query.order_refreshed / authorizations_refreshed，吊销依据使用 revocation_source，不用整条记录 verified/source。人类输出为 CA query 与 Revocation source，不暗示此次执行已检查 OCSP/CRL。account show 同样使用 CA query，JSON 为 ca_query.account_refreshed；不将本地密钥、联系人或停用意图标为本次远端核验结果。

证书密钥和吊销原因共用库/协议枚举产生 CLI 选项；支持算法与 RFC 原因码、CA 可拒绝边界见生命周期契约。账户 register/rotate-key 同样支持 -k/--key-type，但独立于证书选项；普通账户操作沿用已保存密钥。

--now 只在 cert renew 提前执行，不隐含 --yes/--skip-dns-check。--force/-f 已移除，无兼容别名。issue/renew 共享 RunArgs，但续期不暴露定义覆盖参数。账户list JSON使用ca_query.requested/refreshed/failed，remove仅描述本次ca_request_performed。

批量入口为 cert renew --all，与NAME/--name互斥；顺序检查托管身份，not_due/待办/跳过/完成/失败分开计数，单项失败继续，Ctrl-C停止整个批次。批量不弹TXT确认，首次新TXT仍yield。JSON一次输出完整汇总：失败退出1，取消130，待办无失败退出0；不会再追加第二份错误JSON。细节见生命周期契约。

cert issue --resume 不带名称时在真实终端选择未完成申请，选择行包含名称/SAN摘要/UTC申请时间/状态；--resume NAME继续直接定位，脚本/JSON需提供名称或--operation完整ID，不猜最新。只筛选未完成记录，完成版本不进入恢复选择。DNS未就绪的人类日志提示--skip-dns-check只跳本地查询，CA仍验证；JSON不增加人类日志。

新建 cert issue 必须显式 -c/--challenge，无默认验证方式；终端可在 -c 已指定时引导域名输入。--yes不补填验证方式。resume与challenge互斥，renew不暴露challenge覆盖，均沿用已保存方式。--yes在issue/renew中自动接受所有操作确认，并非manual_dns专用开关；独立ToS仍要求--accept-terms，名称选择/输入不属于肯定确认。

仅在实际存在证书前台进度时与最终结果之间留一空行；无进度的全未到期批次及单次not_due不加开头空行（JSON不加分隔）；批量标题/计数使用INFO/WARN/ERROR标签，表格复用公共对齐和Style，待办/取消黄色、失败红色、完成绿色、未到期青色。

批量结果表使用 NAME / STATUS / NEXT RENEWAL (UTC)，未到期或本次完成续期的记录显示下次续期时间；待办、失败、跳过和取消不猜测时间，具体说明放在表后。批量不输出重复计划表或逐项Checking日志；有续期/恢复工作时只先报告任务数和未到期数，实际事务持锁复核。仅实际执行项输出进度和Using CA；全未到期时只保留结果表及检查数量总结，其他汇总只展示非零计数。JSON完整计数不变。

每个命令的 `CommandContext` 持有一个惰性 `HttpPool`，批量续期和账户逐项查询共用它；纯本地命令不构造 HTTP 客户端。`AcmeClient` 自己保留池句柄，调用操作无需额外传池。User-Agent 和请求总期限逐请求设置，不改变池或其他账户；CA directory 和 Replay-Nonce 仍归各自 ACME 客户端。共享池不保证代理/服务器始终保留 TCP 连接。


## 账户密钥算法与帮助入口

账户与证书共用 `crypto::key_algorithm::KeyAlgorithm` 和 CLI 解析器，分别选择自己的密钥。`account register -k/--key-type` 接受 ecdsa-p256、ecdsa-p384、ecdsa-p521、ed25519、rsa-2048、rsa-3072、rsa-4096、rsa-8192；新账户缺省 P-256，已有身份缺省沿用，显式不同类型拒绝复用。`account rotate-key -k` 选择新钥；不指定时新轮换沿用原类型，恢复时沿用已暂存的新钥，显式冲突拒绝且不改文件。recover/show/list 等命令不接受算法覆盖。账户 TOML 必须保存实际 `key_algorithm`，加载按真实 PKCS#8/指纹交叉检查；未发布格式直接更新，不读旧格式或增加迁移。

`-h`、`--help`、`help <command>` 共用 common/help 的产品版本、宽度和配色。不增加参数改写：`account help rotate-key` 与 `account rotate-key --help` 为标准入口，`account rotate-key help` 中的 help 仍是账户名。帮助不读取配置、不初始化 HTTP、不生成密钥。
