# 账户协议测试与 staging 验收

## 规范依据

账户实现对照 RFC 8555 §6.2（flattened JWS 与 jwk/kid 互斥）、§6.3（空 payload 的 POST-as-GET）、§6.4（精确 URL）、§6.5（nonce）、§6.6–6.7（限流及 problem）、§7.1.1–7.1.2（directory/账户）、§7.2（newNonce）、§7.3–7.3.4（创建、找回、条款变化和 EAB）。签名格式遵守 RFC 7515、RFC 7518 ES256 R||S 与 RFC 7638 canonical JWK thumbprint。

条款变化对应 §7.3.3，EAB 对应 §7.3.4。账户更新、密钥轮换和停用分别对应 §7.3.2、§7.3.5 和 §7.3.6；下方历史分轮记录保留各自当时的验收范围。

## 本地测试

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
python3 scripts/check-workspace-deps.py
```

本地 mock 使用实际 HTTP 请求、签名构造和验证，覆盖：

- PKCS#8 往返、错误密钥、JWK thumbprint、原始 ES256 签名及篡改拒绝。
- jwk/kid 互斥、精确签名 URL、POST-as-GET 空 payload、HS256 EAB 签名与响应确认。
- 显式条款、EAB 必需、联系人 URI 边界及输入上限。
- 新账户先持久化 intent、只读找回、CA 明确 not-found 才注册、注册响应丢失后的恢复。
- 请求超时、任务取消保留 pending；坏 nonce 使用错误响应的新值重签且有次数上限。
- 8 个并发请求的 nonce 唯一性、签名有效性；非法/重复 nonce 拒绝。
- 429/503/未知 problem、Retry-After、非 JSON、响应超限和禁止自动重定向。
- CA/账户名称隔离、重启加载、锁等待/超时/释放、损坏/丢失密钥拒绝、schema/尺寸/权限及链接边界。

测试不是所有故障的穷尽证明。当前没有断电文件系统故障注入、跨主机分布式锁测试或 Windows ACL 验收。常规 CI 不调用公网 CA。

## Let's Encrypt staging

官方说明：[测试环境](https://letsencrypt.org/zh-cn/docs/staging-environment/)。Directory：`https://acme-staging-v02.api.letsencrypt.org/directory`。Staging 和生产账户独立；只使用独立测试数据目录，不安装 staging 根证书到系统信任库。

2026-11-10，在用户明确接受当前 directory 返回的条款后，最终文件实现通过下列独立 CLI 进程验收：

| 操作 | 结果 |
| --- | --- |
| account register + 明确接受条款（当时使用 URL 参数；当前为 `--accept-terms`） | valid，创建测试账户 |
| account recover | 同一 URL，recovered=true |
| account show（当时默认联网；现在需 `--verify`） | 同一 URL，valid，recovered=false |
| 再次 account register（无新 consent） | 查询已注册身份，同一 URL，未新建 |

最终账户 URL：`https://acme-staging-v02.api.letsencrypt.org/acme/acct/368234863`。测试目录：`/private/tmp/asteracme-staging-account-20261110`；其中私钥不进入仓库。临时目录可能被系统清理，不作为长期账户备份。早期测试身份文件消失后只读恢复正确报错；最终使用新测试身份重新验收。

本次不申请证书，不验证 DNS/HTTP challenge，不验证生产 CA，不验证真实 CA 的 EAB（EAB 由本地测试验证）。Pebble 尚未运行；真实 staging 交互和本地故障模拟是两层独立证据。

CLI 新参数另以原有 staging 账户完成 `account show --user-agent`（当时默认联网；现在需 `--verify`） 和本地 `account switch default` 验收，未创建新账户。当前本地测试共 59 项，新增默认目录、选择持久化/竞争/超时/损坏、条款变更和 User-Agent 传输覆盖；CLI 进程检查验证缺失密钥时的可操作文本、JSON stderr 和退出码。

配置自动初始化增加并发首写一致性、既有注释/格式及损坏配置不覆盖、显式配置路径、64 KiB 边界、链接拒绝与初始化锁超时测试；当前共 63 项本地测试。CLI 进程验收另确认 `--help` 不落盘，缺失密钥时仍完成首次配置初始化，重复调用保留用户注释。此项不需要新增真实 CA 账户。

CLI 组织调整后增加 show-only 的 `--verify` 解析、key-only/pending/registered 全部本地阶段零连接且不改写元数据、显式验证发起连接且失败保留密钥、16 个并发首次密钥初始化复用同一身份等回归测试。TOML 覆盖 pending 可选字段和 registered 完整记录往返、损坏/未知版本/超限。当前共 67 项测试。

2026-11-10，复用上述 staging 账户私钥，通过独立 CLI 进程验收 `recover`（valid，重新生成 TOML 元数据）、默认 `show`（source=local、verified=false、status=null、local_state=registered）、`show --verify`（source=remote、verified=true、valid）和 `switch default`。账户及选择文件均由独立 TOML 解析器确认 version=1，没有读取或迁移旧 JSON，没有新建远端账户。

目录收拢后，新增单账户只有一个子目录且私钥/元数据共置、名称索引损坏/未知版本/超限/丢失、有效 DER 被替换但指纹不符的拒绝测试。邮箱增加 CLI/配置优先级、plain/mailto 一致性、数量/长度/注入边界测试。当前共 72 项测试；旧 staging 目录属于先前布局，未迁移，不作为新布局验收证据。

当前具名布局为 `accounts/<name>/`，默认账户改为配置内持久化，无旧格式迁移。新测试覆盖根版本与 config/account 表、托管注释及空行、配置并发定点编辑/未知版本拒绝、统一 TOML 锁超时与失败不改写、注册网络失败前保存显式邮箱、CA contact 省略/空/非空三种响应与本地输入分离、switch 更新配置且遵循账户绑定 CA。当前测试总数见最终运行输出；历史 staging 记录不代表新布局实测。

注册复用确认增加交互默认否/确认/取消、JSON 和非终端不提示、显式 --yes、已有 pending 身份拒绝时文件不变且零连接、确认后才尝试 HTTP 的测试。独立 CLI 进程验证 JSON 错误、退出码、无 stdout 泄漏及三个本地文件字节不变。当前共 76 项测试；本轮未调用公网 CA，也未自动操作真实用户终端。

交互式注册增加可注入提示接口的邮箱跳过/输入/非法值/取消，以及条款当前 URL、旧 URL、缺失条款、显式同意、默认拒绝、JSON/非交互不提示的测试。当前共 78 项测试。实际 PTY 子进程对 staging directory GET 验收：跳过邮箱、显示当前条款 URL、拒绝后退出 130，pending 密钥保留且未保存 accepted_terms_url；本轮不创建远端账户。

参数和配置本轮收敛：所有命令按 Local/Target/Network/Register 参数组组合，无关参数由 Clap 直接拒绝；show 的网络参数要求 --verify。仅 --data-dir 定位，移除 --config 和配置 data_dir，配置验证非法名称/版本/超时/URL/邮箱、CA 选择互斥。--ca 内置 letsencrypt/zerossl/google，与 --ca-directory 互斥，默认生产 Let's Encrypt；无测试预设，无按 debug/release 切换。测试 CA 必须手动传 --ca-directory。

当前 87 项本地测试通过。实际 PTY 验证 show 选账户后离线呈现、switch 选已注册 fixture 并保存配置、recover 选账户后只访问显式 loopback、register 取消退出 130；没有访问生产 CA 账户端点。生成配置解析与 CLI 二进制扫描确认无内置 staging URL，switch help 无注册/网络选项。公开只读目录验证：Let's Encrypt 与 ZeroSSL 返回 directory，ZeroSSL externalAccountRequired=true；Google directory 沙箱内外均超时，保留官方 URL 预设但不宣称实连通过。

版本命令和帮助顺序：当前共 88 项本地测试。独立进程验证 version 文本/JSON、根帮助 account 在 version 前、register 参数按声明顺序、无 display_order 和 --config；空工作目录运行版本命令不创建文件。独立执行 build-script 验证 revision/time 显式覆盖、SOURCE_DATE_EPOCH=0、非法版本/时间拒绝和无 Git 归档的 unknown 回退。

register 的无名称交互改为先选择新建/继续，默认新建，仅继续时列已有账户；无可用本地账户直接进入新建。回归测试确认新建分支不会显示账户列表、继续分支经过动作选择和账户选择；现有 recover/show/switch 共用的账户列表保持不变。CLI focused tests 与严格 Clippy 通过。

账户 list/deactivate 与协议抽离当前实现：list 离线列举/默认标记/无需密钥/空列表；停用精确 kid+status 签名、已确认重复零 POST、非法身份/缺失 URL/非活跃/意图保存失败零 POST、超时/429/503/坏响应不重放、取消和保存失败保留 pending、401 不推断成功、badNonce 有界重签。CLI JSON/PTY 验证默认拒绝、退出 130、文件字节不变、待对账重复拒绝、confirmed 只读结果。未停用真实 CA 账户。

协议抽离新增 5 项 wire 契约测试，验证字段省略、contact 缺省/空值、身份互斥、EAB 无 nonce、扩展/嵌套 problem、自定义 URL 精确保持；客户端新增 directory 自定义路径与 Location/query 端点签名验收，不假定 /account 路径。当前共 105 项测试。测试 fixture 仍可构造原始 JSON 来独立验证线上边界和非法响应，产品请求/响应和 CLI 输出不使用 json! 拼装。

生产 CA provider/URL 表迁入 protocol，新增 Provider 名称、Serde、URL 和未知值边界测试；CLI 只验证输入适配与冲突规则。当前共 106 项测试。账户命令帮助顺序为 list/show/switch/register/recover/deactivate，依声明排列无 display_order。

自动化与 CLI 收尾（当前 116 项测试）：单账户 register/recover/show/switch/deactivate/remove 统一位置 NAME 与 --name，冲突/非法名称在解析阶段拒绝。list 的 --verify/HTTP 参数组合、失败后继续、结构化逐项结果与非零退出码有测试；默认列表无需密钥/HTTP，NAME 标记列、Unicode 可见宽度补齐和默认高亮有呈现测试。deactivate 确认详情分行，问题简短；修改类成功摘要、异常状态保留、show/JSON 完整字段均验证。

remove 覆盖取消/无 --yes 不改数据、只删目标/其他账户不变、坏钥可删、锁超时/未知文件/隐藏清理目录碰撞拒绝、符号链接目标不变，以及默认配置条件清理/保留其他选择。独立 CLI/PTY 进程逐命令以 stdin=DEVNULL 或明确终端输入验收，测试地址仅显式 loopback，无真实 CA mutation：list 部分验证失败时仍输出两项结果并退出 1；deactivate 默认否退出 130 且上下文分行；confirmed 重复只读返回单行；remove 的 JSON 结果、私钥/目录删除和默认清理验证通过。workspace 包名/目录改为下划线，可执行文件仍为 aster-acme，旧包名不保留。

时间与显式账户状态机（当前 123 项测试）：core 新增账户注册/停用/选择的纯动作决策，覆盖 pending 对账限制、inactive/unknown 拒绝、confirmed 本地幂等返回和权威观察转换。客户端通过注入 AccountClock 验证 UTC 归一、首次确认不变、成功查询/停用更新时间、403 和本地重复返回不改时间；存储验证 RFC3339 往返、未知值省略及非法日期拒绝；CLI 检查 UTC分钟表格、未知 —、JSON 完整精度。独立 CLI 进程以 loopback 失败注册确认未知时间未伪造，随后读取受控 fixture 验证离线 list/show 不改变文件。未执行真实 CA mutation。

账户更新/轮换与 Forge HTTP（当前 140 项本地测试）：对照 RFC 8555 §7.3.2 和 §7.3.5 原文检查请求字段、精确账户 URL、内层新钥 jwk/无 nonce/kid、外层旧钥 kid/nonce、相同 keyChange URL、200 空 body 成功。新增真实 ES256 内层验签、联系人替换/清空/非法状态与保存失败、非 200/坏响应/超时无自动重放、badNonce 保持相同内层及新钥；文件事务覆盖取消后新钥对账、超时保留双钥、401/403 不推断成功、合法 409 problem 保留旧身份、缺失端点/新钥/同钥拒绝、未确认/改身份提交拒绝，以及 confirmed 部分本地换钥在重启后不发 keyChange 直接完成。注入文件系统每一个断电点、真实硬件签名器与公网 CA 换钥尚未验收。

User-Agent 验证显式注册值写账户 TOML、缺省不写、配置无全局字段、重启继承、本次覆盖不改账户和非法值在持久化前拒绝；loopback HTTP 验证默认/显式 header 传输。HTTP 构造与执行使用固定 Forge rev，协议错误/重定向/超时/badNonce 回归通过。短请求超时测试的 directory fixture 使用独立较长设置，随后重建为被测请求 deadline，避免把并行 setup 延迟误判成 mutation 超时。

本轮 `cargo test --workspace --locked` 默认并发和 `--test-threads=4` 均通过；严格 Clippy、格式、workspace 依赖策略和 diff whitespace 检查通过。`cargo doc --workspace --no-deps --locked` 无 bin/lib 输出目录冲突；CLI bin 禁止 rustdoc，库文档保留。独立 CLI 子进程验证新命令帮助/互斥参数、JSON、无确认时零 mutation、显式 UA 落盘及离线 show；所有数据位于独立临时目录，未修改真实 CA 账户。本轮验证使用独立 CARGO_TARGET_DIR，避免占用用户 target 构建锁。

## 账户多算法与标准帮助入口（2026-11-11）

共享 `crypto::key_algorithm::KeyAlgorithm` 覆盖账户/证书八种选择；账户 JWS 按 RFC 7518/8037 选择 ES256/ES384/ES512/EdDSA/RS256。测试分别检查全部选择的 PKCS#8 往返、算法/位数不匹配、损坏/截断/尾部多余字节、规范 EC/RSA/OKP JWK/指纹、kid/jwk 请求、原始签名验签和 HS256 EAB。独立 Python cryptography/OpenSSL 公开测试钥及签名覆盖 P-384/P-521/Ed25519/RSA-2048 互操作；RSA-1024、secp256k1、Ed448 为合法编码但不支持的负例。

真实文件租约与 loopback CA 测试覆盖跨算法连续轮换、缺省沿用原类型、暂存钥重启恢复、显式冲突不写文件、取消后新算法对账且不重发 keyChange、主钥已换而元数据尚未提交的跨算法崩溃恢复。普通 save 不得改变算法，提交后主钥/指纹/算法一致，账户 ID 保持不变。双层 JWS 单独验证外层旧算法及内层新算法、同 URL、内层无 nonce/kid。

工作区 315 项测试通过；后续帮助/呈现调整的 125 项 CLI 测试及跨算法部分提交恢复专项通过，严格 Clippy 零 warning。实际二进制在临时目录检查四种算法注册后的持久化/离线详情/列表、显式不匹配保留原钥，以及各级标准帮助入口。`rotate-key help` 保持位置账户名，不增加参数改写。未访问公网 CA，未验证各公开 CA 对所有算法的接受范围。
