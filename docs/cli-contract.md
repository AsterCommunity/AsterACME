# CLI 参数与交互契约

本文件是 account、cert 及后续命令的共同约定。参数来自实际 Clap 声明；新命令复用 `common/args.rs` 的存储/输出和 HTTP 参数组，只暴露自己用得上的能力。

## 确认、输入、输出分别控制

| 参数 | 统一含义 | 不包含的权限 |
| --- | --- | --- |
| `-y / --yes` | 对当前命令已经明确的操作作肯定确认 | 不选目标、不填写缺失输入、不自动同意条款、不绕过校验、不强制重放 mutation |
| `--accept-terms` | 注册时同意所选 CA 当前实际公布的条款 | 不确认复用已有账户，不作为永久自动接受配置 |
| `-f / --force` | 目前仅在 cert issue 跳过本地 DNS 可见性检查 | 不免除 CA 验证，不忽略过期/身份/密钥/CSR/证书检查，不覆盖用户文件 |
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
| `cert issue --resume <NAME>` | 跳过“Have you published these TXT values?”，然后正常检查 DNS |

首次手动 DNS 自动化申请必须先让用户/脚本取得新 TXT 值；即使传 --yes/--force 也返回 action_required，不因“确认”假设记录已发布。首次终端申请未带 --yes 时仍可以现场输入和继续。发布后 resume，仍由 CA 完成实际验证。没有 --yes 的非 TTY/JSON resume 也不弹提示，按已有脚本行为直接检查 DNS；--yes 是显式确认语义，保持非终端一律不提示的统一规则。

--yes 不出现在 list/show/switch/recover/version；这些命令没有相同的危险操作确认。后续 renew/revoke/remove 等命令按这里的确认语义扩展，不让 --yes 获得额外隐式权限。

## 名称与选择

- account 的单账户命令支持位置 `[NAME]` 和 `-n/--name`，互斥；名称统一为 1–64 位 ASCII 字母、数字、下划线或连字符。
- `cert issue -n/--name` 设置长期证书名称，缺省为第一个规范化后的 -d 域名；`-a/--account` 使用与账户命令一致的名称校验。
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
| `-c` | `--challenge` | 验证实现，目前只有 manual_dns |
| `-m` | `--contact` | account register/update-contact 的邮箱，可重复 |
| `-y` | `--yes` | 上述命令的操作确认 |
| `-f` | `--force` | cert issue 的本地 DNS 检查覆盖 |

其他参数保留明确长名称，不为每个选项硬配短字母。删除的 order、--solver、-c dns-01、--config 不保留兼容别名。

## 命令参数范围

所有 account/cert 命令共用 --data-dir / --json；下表列出其余业务参数。不是全局参数的选项，不向无关子命令泄漏。

| 命令 | 业务参数 |
| --- | --- |
| account list | --verify；--user-agent / --timeout 仅在 verify 时可用 |
| account show | [NAME] / -n；--verify；已有账户 CA 选择；HTTP 参数要求 verify |
| account switch | [NAME] / -n；仅本地操作，无 CA/HTTP/注册参数 |
| account register | [NAME] / -n、-m、--ca / --ca-directory、--accept-terms、HTTP、-y、成对 EAB |
| account recover | [NAME] / -n、已有账户 CA 选择、HTTP；不创建新密钥/新 CA 账户 |
| account update-contact | [NAME] / -n、-m 或 --clear-contacts、已有账户 CA 选择、HTTP、-y |
| account rotate-key | [NAME] / -n、已有账户 CA 选择、HTTP、-y |
| account deactivate | [NAME] / -n、已有账户 CA 选择、HTTP、-y |
| account remove | [NAME] / -n、-y；仅本地操作 |
| cert issue | -n、重复 -d、-a、-c manual_dns；或 --resume NAME / --operation ID；-y、-f、HTTP、--wait-timeout |
| cert list | -n 筛选；不访问 CA |
| cert show | [NAME] / -n、--operation、--verify；HTTP 参数要求 verify |
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

人类输出复用 common/output、time、log、table。时间为 YYYY-MM-DD HH:MM:SS UTC；JSON/TOML 保存 RFC3339 原精度。NO_COLOR/非终端不着色，JSON 不输出人类进度。

0 表示命令成功执行；cert issue 的 action_required 同样为 0，脚本必须检查 status，不能将其误认为 completed。一般错误为 1，Clap 解析错误沿用 2，交互取消为 130。远端查询失败不标为 verified。
