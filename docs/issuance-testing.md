# 手动 DNS-01 签发验收

## 规范与能力边界

实现对照 RFC 8555 原文 §7.1.3（订单与 expires）、§7.1.4–7.1.5（授权/challenge）、§7.4（newOrder、finalize 与 CSR）、§7.4.2（PEM 链下载）、§7.5.1（通知与轮询）、§8.4（TXT 摘要），并复用 §6 的精确 URL、kid/JWS、nonce、POST-as-GET 和错误策略。证书/CSR 采用 PKCS#8、PKCS#10 和 X.509/SAN。

当前实现manual_dns/manual_http/webroot/standalone/tls_alpn。CLI负责人工/文件/TLS发布，ACME负责方法和材料及CA状态推进；DNS预检建议性限2秒，不覆盖取消/整体期限，人工首次脚本仍返回待办。普通测试只使用数字 loopback HTTP/TLS 显式测试策略，不改生产默认 CA，也不安装任何测试根。

TLS-ALPN专项覆盖：默认443及自定义监听地址、每域名单独证书、单DNS SAN、critical `id-pe-acmeIdentifier` DER摘要、SNI/`acme-tls/1`门控、重复/混合材料拒绝、恢复重建及终态释放。普通Rustls客户端拒绝未知critical扩展是预期行为，ACME验证器应按RFC8737读取该扩展。

端到端 TLS-ALPN loopback CA 测试通过真实TLS握手检查SNI、ALPN及challenge证书摘要后才把mock订单转为ready，完成固定CSR finalize和下载；轮询上限后重启会重建挑战证书且不重复ack/newOrder。Resolver测试还覆盖新SAN增量加入、同摘要复用、冲突摘要不覆盖已发布证书，以及占用端口、取消、过期及活动连接关闭。IANA Error Types 在线映射由每周GitHub Actions读取官方CSV，不保存注册表快照；脚本单测使用内存CSV验证增删差异，不依赖网络。

TLS-ALPN使用真正的loopback TLS握手推进mock ACME订单，覆盖两域名证书选择、增量加入域名、冲突摘要不覆盖旧挑战、恢复已ack challenge不重复POST、验证后finalize/download/in_use、取消和监听释放；IANA Error Types另由`scripts/check-iana-acme-errors.py`在线检查，专用workflow每周一运行并在相关PR运行，常规脚本单测不依赖网络。

## 本地证据

文件适配器与真实签名 transport 连接 loopback CA，覆盖完整新建→两条同名 TXT 待办→重启恢复→通知两个 challenge→授权 valid→订单 ready→固定 CSR finalize→valid→PEM 下载/检查→in_use 切换。校验世代只创建一次，私钥/CSR 字节不变，同名多值不会覆盖；最终 SAN/公钥与申请一致，清理提示保留。

边界包括：过期订单与授权（force 也不能继续）、pending 必需 expires 缺失、非法 RFC3339、重复授权 URL、错误域名、创建响应丢失后禁止重下单、保存 Location 后坏响应可诊断、badNonce 同一申请重签、submitted finalize 的 ready 只轮询、取消/deadline、材料损坏/链接/未知版本/权限/锁竞争、同名多个世代、错误私钥/SAN/PEM 不更新 in_use。只读 inspect 验证不发 challenge/finalize。DNS 检查验证单 RR 分片拼接、多 RR 共存，以及建议性预检不忽略取消/期限。

CLI 解析/选择测试验证 -d/-a/-n/-c/-f、resume 与新申请参数互斥、operation 仅用于恢复、order 无写命令、JSON 多候选不猜最新、申请时间输出。独立 CLI/PTY 进程验收结果以最终执行记录为准，不把库测试声称为人工公网 DNS 验证。

## 尚未验收

未执行真实 CA staging 证书签发、Pebble、DNS provider 自动写入、完整公网传播、真实断电注入、Windows ACL 或硬件密钥。相邻证书签名验证不代表公众信任路径验证；客户端不会将 staging 根加入系统。ARI续期计划、TLS-ALPN-01和账户签名吊销有本地mock/存储/loopback TLS验收；周期调度、自动DNS和外部CSR尚未实现。

部署专项使用临时目录、真实证书产物与 Rust 测试子进程，覆盖当前版本发布、同版本幂等跳过、续期后新版本/密钥发布及绑定保留、多目标失败继续、非零退出有界重试、启动失败、超时/取消检查点和不自动重放、发布失败后显式恢复、租约与续期/移除互斥、移除绑定保留发布文件。渲染测试覆盖空列表、全部状态配色与可见宽度对齐、控制字符转义、单次及批量 JSON/退出码和命令参数不回显；存储测试覆盖目录/精确路径、非法参数和链接拒绝。PTY 另验证无名称选择（Enter）和取消（Escape）；这些均不代表真实 nginx/systemd 或 Windows 服务 reload 验收。

## 常规验证

```sh
python3 scripts/check-workspace-deps.py
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
```

并发开发时设置独立 CARGO_TARGET_DIR，避免占用用户构建目录。短超时回归用例给 nonce/请求到达留出调度余量，再以超过请求预算的服务端延迟验证超时；不依赖几十毫秒的 CPU 调度速度证明 mutation 是否已发送。

2026-11-11 初始签发阶段验收：159 项 workspace 测试通过，严格 Clippy、workspace 依赖/独立 package.version 策略、格式和 whitespace 检查通过。独立 CLI/PTY 进程验证短参数、参数冲突、只读 list/show、expiry 文本与 JSON、多申请显示不同申请时间、脚本歧义拒绝，以及取消退出 130 且 journal 字节不变。所有进程使用独立临时 data dir，未操作真实 CA。

嵌入式会话另覆盖同一 IssueSession 连续调用两次 manual action_required：读取最新 durable journal，维持同一 operation/order/TXT，不重复创建订单。run/inspect 独占借用 session；文件会话的异步 I/O 队列将已启动的阻塞写许可随任务持有，取消后下一次读取会等待前次持久化，避免旧快照或未结束写入越过恢复边界。CLI 成功输出实际 fullchain 与 PKCS#8 DER 私钥路径；人工恢复提示默认使用证书名称，JSON 提供带精确 operation ID 的脚本恢复命令。

人工发布等待期间订单或授权也可能过期：通知 challenge 和提交 finalize 之前，在持久化 intent 后再次核对期限。新增延迟 publication 回归验证等待中跨过 expires 后，即使 force=true 也不会通知 CA。


后续统一与修复验收：当前 194 项 workspace 测试通过。CLI 入口收敛为 cert issue/list/show，-c manual_dns 是唯一验证实现选择，没有旧 order/--solver/dns-01 参数兼容。新增回归覆盖无名称引导、三列简短选择、重复标签的独立行身份、account/cert 彩色且值对齐的统一详情、离线/verify 字段一致与准确 source/verified、固定 UTC 秒级时间、蓝色 Tips、WARN/DONE、人类进度事件与 JSON 静默。测试文件审查合并为每文件一个末尾 tests 模块，测试 helper/import 不混入生产实现。

实际 staging 授权只读诊断发现 tls-alpn-01、dns-persist-01、dns-01、http-01 同时返回；dns-persist-01 无 token、带 issuer-domain-names，原模型因此报 missing field token。按 RFC 8555 §7.1.5 与 §8.4，将方法字段留在 protocol 扩展数据中，只有选中的 DNS-01 必须有合法 token。protocol 测试保留未知对象字段和非常规 token 类型，签发回归验证扩展共存时正常完成且选中的 token 缺失/非法时零通知。dns-persist-01 依据 draft-ietf-acme-dns-persist-02，仅保留不执行；规范状态和 LE 部署状态不是同一件事。未重新对真实 CA 下单或完成新验证；用户自行签发的终端记录与本地验收分开。

新增完整产物集合测试验证 fullchain/leaf/CA 拆分、PEM/DER 私钥同一性、叶子单独返回时空 CA 文件、文件权限和任何导出失败不切换 in_use。布局为时间加随机后缀，与 in_use 相对 symlink 同级；覆盖两次切换保留历史、暂存链接崩溃恢复、外部 symlink/用户同名 in_use/临时文件碰撞拒绝、不读取旧 generations 目录。额外普通文件、目录和未识别链接不阻止列举；对已识别托管 journal 继续拒绝损坏或不安全链接。账户删除有额外内容时仅移除托管资料并保留原目录/锁和用户文件。

账户/config 回归覆盖七个已有账户命令缺失身份时在确认/HTTP/建账户目录前拒绝、结构化 Hint 包含 --name/--data-dir、切换缺省 default_account 安全插入、重复切换不变、注册成功后条件补回默认、移除默认再补回、已有并发选择不覆盖、缺省 contact 写入、注释/格式保留、未知版本/错误表类型/损坏文件拒绝且文本不改、并发联系人/默认更新。toml_edit 用户文档读改写集中到同一个锁内 edit helper，可选字段用 get/insert，不用索引读取缺失字段。

密码学后端统一 rustls + AWS-LC；独立公开标量测试钥和外部 cryptography 生成的 PKCS#8/ES256 签名验证标准互操作，HS256/JWK/换钥/签发全量回归通过。依赖统计（同一 macOS target normal+build 口径）由 277 降到 258，Cargo.lock 全平台/测试条目由 355 到 334。没有 native-tls/openssl-sys，CI 增加 TLS 后端守卫；Cargo.lock 中平台根证书探测组件不等于 OpenSSL TLS。


本轮参数和依赖验证：200 项 workspace 测试通过（在同一候选版本上运行），包括 cert -y/--yes 的短/长参数、终端确认跳过、DNS checker 仍调用、force 不被隐含、首次 yes+force 仍返回待办、取消/期限，以及全部现有命令确认/强制/条款选项的作用域矩阵。common/args 共享参数、-m 联系人、cert show 位置/命名目标互斥与非法输入边界均覆盖。Forge/AsterFs registry 切换与 base64 0.23.1 后重跑签名、EAB、CSR、换钥、签发、恢复与存储测试；测试不访问公网 CA。


Registry/参数与 release 收尾：200 项 workspace 测试和严格 Clippy 通过。以 opt-level=z、lto=true、codegen-units=1、debug=0、panic=unwind、strip=debuginfo 构建实际 macOS arm64 release CLI 成功；version --json 确认 profile=release，nm 确认函数符号保留。二进制约 7.6 MB（7,605,024 字节，此构建/平台样本，不作为跨平台体积保证）。--help 和 cert issue --help 的 release 进程确认产品版本与 -y/--yes；本轮仍无公网 CA mutation。

## ARI 与证书吊销验收（2026-11-11）

本轮 228 项 workspace 测试通过，严格 Clippy、workspace 依赖/TLS 策略、格式和文档构建通过。新增覆盖 RFC 9773 附录证书的 DER 序列号前导零、原有效期 2/3 回退、窗口随机边界/相同窗口不重抽、Retry-After delta/date/缺省及限值、无端点/无 AKI、短请求超时和 5xx 有限指数退避、取消和重启后请求期限保留。真实文件会话验证 fallback/ARI 选时落 TOML、重新打开保持计划和密钥，首次网络失败不撤回产物。

吊销测试核验账户 kid/精确 URL/nonce/真实 ES256 签名、DER 叶子和可选 reason、200 空 body/alreadyRevoked、未签发/身份不符/无端点/保存失败零提交、明确拒绝、未知状态/5xx/超时/取消/确认写失败保留 pending，显式重试保留原原因、已确认重复不请求。文件集/in_use 不变，confirmed 不再查询 ARI 或恢复签发。CLI 检查名称/ID、原因和参数作用域、JSON、缺失目标零账户/证书写入；人工输出统一 Next renewal，吊销后 disabled、未确认 suspended。Nonce 回归确认成功 POST 缺少/非法 Replay-Nonce 仍保存结果，下一次 HEAD 取新 nonce。

没有执行真实 CA 吊销或新的公网签发，不声称周期唤醒/实际自动续期已完成；daemon 和 newOrder.replaces 留给后续实现。

## 托管身份与删除范围验收

默认名称改为主域名加八位随机后缀，显式重名拒绝，自动分配只对 NameAlreadyExists 换串重试。存储竞争测试证明同名并发只有一次成功声明；CLI 分配测试实际制造名称碰撞，并核对另一名称被分配、原文件不变及权限错误不触发重试。极限域名只截短管理名称前缀，不改原 SAN。

续期存储入口固定从 cert.toml 定义读取域名/账户/CA/验证配置，拒绝不匹配账户；新版本固定独立密钥/CSR且失败保留旧 in_use。默认列表每个托管证书一行，默认 show 选 in_use，不将历史当作当前；历史可显式展开并保留完整 SAN，只有 in_use 的计划参与活跃查询/调度。分别测试单次/history/revoked/all 清理、未确认吊销不匹配、保留 pending、清空 in_use 不回退、无匹配零副作用、未知文件/链接/锁 inode 保留和中断标记。历史证书仍可按精确 ID 查询订单，但不因此激活其续期计划。

本轮全量 252 项测试通过；不含公网 CA 请求。250 ms 的 HTTP 超时测试在并行负载下出现请求尚未到达 loopback server 就超时的调度问题，已改为一秒请求预算与三秒服务端延迟，仍严格验证三次有界重试或 mutation 不重放。本轮不声称 CLI renew/daemon 已实现，旧存储 schema 不自动兼容或迁移。

## Forge HTTP alpha.2 feature 边界验收

HTTP 单独升级到 registry 的 =0.1.0-alpha.2，utils/macros 保持 alpha.1。workspace 只启用 json、rustls-aws-lc-rs、system-proxy；直接 reqwest 依赖关闭默认且不另选 features，HttpClient 显式选择 TlsBackend::Rustls。生产 normal/build feature 图确认无 form/query/multipart/stream/charset/http2/default 入口；系统代理与 rustls 平台根行为保留。

同一 macOS target、normal+build、去重包口径从 258 降至 246；全平台/测试 Cargo.lock 条目从 334 降至 326。被移除的可选依赖包括 encoding_rs、mime_guess、serde_urlencoded 和 wasm-streams。252 项 workspace 测试及严格 Clippy 通过，TLS 守卫继续拒绝 native-tls/OpenSSL；没有真实 CA mutation。

## 证书密钥与吊销原因扩展验收

本轮 261 项 workspace 测试通过：八种 KeyAlgorithm 均实际生成 PKCS#8/CSR，并用独立 AWS-LC 验证器核验 CSR 签名（P-521 SHA-512 单独选择其验证算法），校验证书公钥/SAN、PEM 与 DER 私钥一致、错钥拒绝。真实文件会话逐项完成落盘、重启打开、固定 CSR 不变、算法不可篡改、续期准备保留类型并生成新密钥；digest 未变但保存算法不符也拒绝。包含实际 RSA 8192 生成，无 OpenSSL 或新密码学依赖。

CLI 枚举驱动八种 key-type 解析、默认 ecdsa-p256、短参数 -k、resume/显式 key-type 互斥、未知算法拒绝，issue 新建/恢复输出实际选择，列表/详情/JSON 显示一致字段。十种 RFC5280 已分配原因逐项核验 struct→JSON 数字编码；7/越界/负值拒绝，CA badRevocationReason 保留且不冒报吊销成功。账户签名仍 ES256。没有真实 CA 签发/吊销，本地生成能力不等于所有公开 CA 接受。

固定CSR拒绝恢复回归实际模拟 P521 badCSR、P384 共享相同 order 成功、P521 重启后返回原错误且零额外请求，原钥/CSR不变且不写错误产物。ProblemKind 覆盖RFC8555的24项标准值及未知URI往返，线上URI序列化不变；公共CLI诊断测试覆盖badCSR、badRevocationReason、未知问题、限流和identifier子问题。此前没有持久化的真实失败原因不可从后来的valid订单还原，本轮不猜测补写或重放真实CA操作。

最终收尾：266 项 workspace 测试、严格 Clippy、workspace 依赖/TLS 策略、格式、文档构建及 whitespace 检查通过；新增公共 problem 诊断正常/未知/子问题/限流回归。所有运行使用独立构建目标目录，真实申请数据仅只读核对；没有提交新订单、重新 finalize 或吊销真实证书。

## 单次续期、全库状态检查与 in_use 命名验收

本轮283项workspace测试通过（79客户端、102 CLI、77存储、13 core、10 protocol、2 validation），严格Clippy、格式、依赖/TLS策略和whitespace检查通过。续期覆盖到期边界、--now独立语义、not_due无产物/订单/HTTP、变更in_use及未确认吊销拒绝、同predecessor续期恢复、固定密钥/CSR、取消后旧in_use保留、无ARI省略replaces、有ARI真实JWS payload及回显检查、缺失/错误回显不重下单，以及旧结果禁止覆写后来改变的选用版本。常规测试不访问公网CA。

账户/证书删除在根.locks保持原inode，成功清理无用户内容的对象目录；用户额外文件和失败标记边界仍覆盖。全库状态路径检查将结果JSON改为ActionRequired/Completed/NotDue标签枚举，not_due不再冒充错误；移除account remove对未查询远端状态的断言，account list提供实际刷新/失败计数，通配符授权与裸域名分开显示。统一选择器行使用ChoiceLabel（名称/摘要/UTC时间/状态/标记）和同一terminal索引身份。默认不显示重复标记，版本视图In use: yes/no。内部、字段、symlink路径统一in_use，无current别名或旧格式迁移。

独立CLI子进程使用临时目录验证默认in_use/历史/精确operation视图、歧义脚本拒绝、history/revoked/all清理、保留pending/用户文件、外置锁；version --json为0.1.0-alpha.1，renew帮助不暴露域名/账户/密钥覆盖参数。所有六个workspace包独立声明该版本，未发布任何包、未操作真实CA或用户数据。

## 批量续期验收

cert renew --all 本轮全量292项测试通过（79客户端、111 CLI、77存储、13core、10protocol、2validation），严格Clippy、格式、依赖/TLS策略、文档构建与whitespace通过。新增参数范围/名称互斥、顺序执行、单项失败继续、手动待办后继续、空库存、无in_use跳过、预取消/进行中取消、提交成功同时取消仍保留完成项、实际证书锁超时后继续，以及批量汇总JSON的完成/待办/失败/取消与逐项结果一致性测试。

真实本地账户/证书适配器回归核验not_due零新版本/密钥/HTTP、缺失账户不阻塞其他证书、--now时loopback连接失败保留原in_use和待恢复版本。独立CLI子进程使用临时目录与本机TLS阻塞监听器，验证空批次、混合失败/未到期/无选用版本结果、stdout单个JSON且stderr无第二份错误、失败退出1、SIGINT退出130及剩余项不执行。现有人工DNS首次yield和恢复、ARI/replaces、超时/重试/取消/原子产物等库回归继续通过。

本轮未访问公网CA、未修改真实账户或证书、未扩展账户密钥算法、未启动daemon。全量库存损坏在安全枚举阶段整体失败；不能宣称能跳过任意损坏目录继续处理。

恢复交互收尾：112项CLI测试及严格workspace Clippy通过；--resume未带名称使用类型化Choose/Named意图，终端仅枚举未完成申请，JSON/脚本不猜目标。独立PTY/JSON进程验收确认选择包含UTC申请时间、完成申请被排除、取消退出130且journal字节不变、不创建账户；DNS未就绪/解析器错误/超时仅WARN后继续CA，取消仍终止。全部使用临时目录，不发公网CA请求。

批量输出精简验收：114项CLI测试、严格Clippy、格式/依赖/TLS/whitespace检查通过。移除重复计划表与Checking renewal逐项日志，保留有工作时的数量简报，最终表按名称顺序输出；全未到期一句总结，其他人类计数仅非零，JSON完整不变。独立CLI子进程验证两项全未到期stderr无进度、结果只有一个有序表与总结，--now两项loopback失败仅一条数量简报、失败计数不混入零项；原JSON/取消/部分失败进程验收继续通过。只使用临时目录及本机拒绝连接地址，未操作真实CA。

## 方法驱动HTTP与恢复诊断（2026-11-11）

当前工作区363项通过：ACME库86、CLI163、storage88、core14、protocol10、validation2；严格macOS/Windows GNU all-targets Clippy零warning，工作区文档构建及依赖/feature策略检查通过。Windows结果为交叉构建检查，不代表本轮完成Windows原生HTTP运行验收。

新增loopback CA流程使用真正账户签名、固定CSR和与保存密钥匹配的证书：manual_http先返回精确URL/path/content并在重开会话后复用原order；webroot无人工提示签发、清理，并以保存定义完成真正的第二次续期。包含方法不匹配、token改变/缺失/非法、CA未提供HTTP、授权已过期、发布后取消并恢复、清理时文件被用户修改但证书仍保留成功、保存方法/config被篡改时open/save拒绝。

webroot文件边界检查既有同内容借用、不同内容不覆盖、独占所有权硬链接重启恢复、文件替换或修改不删除、同级目录/文件symlink拒绝、过长token/内容和控制字符、只有新文件/目录设置Unix公开读取权限而既有用户权限不变。私钥/CSR不进入webroot。

相似定义匹配覆盖域名无序集合、账户/CA/指纹、方法/实现/config、算法及所有未完成阶段；创建意图已提交但URL缺失仍是可见候选，却不重发newOrder。明确CSR拒绝、过期和invalid排除。实际CLI脚本/PTY验证默认脚本阻止隐式复用、唯一匹配opt-in、多个匹配拒绝、交互包含UTC时间且取消130、显式独立名称及不新增或修改旧材料。

DNS建议性预检覆盖有/无TXT、系统解析器错误、独立短超时均可继续；取消和总deadline仍停止。删除skip/force参数并有解析拒绝测试，--yes不选择目标、不替代首次人工待办。日志测试覆盖托管名称、创建时验证实现/方法、STATUS与ORDER STATUS有色/无色独立对齐。

--debug实际二进制验证：已有unconfirmed创建在CA directory发现前失败，输出安全creation_submitted/has_order_url检查点；可恢复请求的传输失败输出请求类别、耗时和错误分类。RUST_LOG=trace加--json仍只有一个错误JSON，key/CSR/journal字节不变，无crash.log副作用。诊断日志不包含私钥、CSR/JWS正文、HTTP正文或nonce值，不能补回以前已丢失的Location。

本轮未对公网CA或真实用户DNS/账户执行修改；用户提供的staging终端结果与上述本地证据分开记录。未增加旧schema读取、参数别名或自动迁移。

HTTP跳转与等待来源收尾：实际用户staging记录表明HTTP80入口302到HTTPS后可签发；本地建议性预检调整为最多10次HTTP/HTTPS跳转，并共享2秒预算及8192字节上限，HTTPS仍执行正常TLS校验，不采用CA可能使用的跳过证书策略。回归覆盖重定向到正确内容、循环11次请求上限、无Location/非法scheme、内容不匹配/超限；ACME签名请求禁跳转测试保持。每次等待不再被进度节流隐藏，debug输出响应解析后的Retry-After及调度来源；CA未提供有效值时仍显示本地间隔。2项transport专项和168项CLI测试、严格Clippy通过，本轮不重新对公网CA下单。

Invalid订单与webroot日志补齐：376项工作区测试通过（88 library、174 CLI、88 storage、14 core、10 protocol、2 validation）；本机和Windows GNU all-targets严格Clippy零warning。loopback CA验证invalid订单顶层problem保存、无顶层error时challenge error补查保存、第二次恢复零CA请求；CLI真实子进程human/JSON展示原始问题说明，不输出resume建议，key/CSR/journal字节不变，离线show仍保留problem。首次invalid的HTTP查询成功不伪装成HTTP400。无problem明确告知CA未提供，不猜实际失败原因。用户ftp.esaps.net记录只读检查发现order invalid但未存problem，未执行公网刷新或重下单。

Webroot实际文件操作返回FileAction区分Published/Reused/Borrowed/Removed/Retained/Missing，INFO逐项输出绝对路径，DEBUG展示公开URL和配置映射指引（HTTP80入口、可允许HTTPS跳转、避免认证/应用重写）。测试核验不会把借用/替换文件记录为已删除；公开验证材料不涉及私钥。

Webroot终态清理补齐：CA明确invalid时与成功签发共用cleanup_publication，只清理本次拥有且身份/内容未变的文件与所有权凭据。专项覆盖owned正常删除、borrowed保留、changed保留并维持cleanup_pending、replaced同内容不同身份保留；取消后的材料先保留，随后从loopback CA取得invalid才清理，原始418/unauthorized问题、私钥和CSR均保留。工作区377项通过；重构测试fixture后175项CLI及严格Clippy通过。没有自动清理既往用户invalid记录，也没有向公网CA发送新请求。

用户在本轮确认webroot路径已实际成功签发；这是用户提供的真实环境验收记录，与本地loopback测试分开，不据此推断所有反向代理配置或所有平台均已通过。

## HTTP standalone 本地验收（2026-11-12）

本轮 workspace 392项测试通过（ACME88、CLI190、storage88、core14、protocol10、validation2）。新增15项覆盖standalone参数/保存配置、精确Host/path及多域名token、错误方法/请求体/绝对URI/重复Host、超长HTTP头、IPv4/IPv6、端口占用、幂等发布、所有权释放、每连接期限和64条并发上限。Loopback CA真正通过TCP获取挑战内容后才推进签发；已ack后轮询上限→关闭→重新打开申请→恢复监听，不重复newOrder/ack/finalize，续期保留socket定义。取消、总期限和明确invalid均释放端口并保留固定密钥/CSR，原始CA problem不被关闭行为替换。

严格原生及Windows GNU all-targets Clippy、rustdoc、workspace依赖/TLS/生产feature策略及格式/whitespace检查通过。Hyper等组件已存在于依赖树，未新增解析包，只增加直接引用和HTTP/1 server功能；HTTP/2/full等不必要feature由策略拒绝。原生CLI build/help/参数冲突单独验证。此为本地模拟CA/真实socket证据，不代表standalone公网CA或Windows原生运行验收；此前用户报告webroot真实签发成功，与本轮standalone证据分开。

## RFC 错误证据与恢复验收（2026-11-12）

Workspace 399项测试通过（ACME89、CLI191、storage93、core14、protocol10、validation2）。新增错误矩阵覆盖newOrder rejectedIdentifier/unsupportedIdentifier/compound/unauthorized/userActionRequired、ARI409 alreadyReplaced、429 rateLimited、503 serverInternal、未知problem及无problem响应，保存真实HTTP/problem/扩展/子问题/绝对Retry-After；重新打开不发HTTP、不重复下单，固定key/CSR字节保持一致，Order未观测不显示invalid。渲染另验证非标准HTTP400 rateLimited/serverInternal按problem语义展示延后/未确认。

Finalize回归覆盖403 badCSR原状态与重启拒绝、403 orderNotReady先POST-as-GET再ready后重交同一CSR、持续拒绝被max_polls限制；429/5xx/未知错误不解除不确定提交。授权invalid/deactivated/expired/revoked及选中challenge invalid保留problem并离线拒绝恢复，既有valid订单/授权不因旧challenge失败历史而错误阻止下载，无problem终态也保持可诊断。末次边界断言调整后重跑5项storage错误用例和CLI状态渲染用例；严格原生/Windows GNU all-targets Clippy、原生build、rustdoc、依赖/TLS/feature策略和fmt/diff检查通过。

这些均为本地mock与实际存储重启验收，不是公网CA或Windows原生运行证据。不修改用户旧记录；旧记录没有保存的HTTP拒绝原因无法由本地安全还原。错误接入映射及边界见rfc-reference.md的2026-11-12核对表。

Windows CI测试假设核对（2026-11-12）：rcgen在Windows默认输出CRLF，拆分证书编码固定为LF。产物测试显式输入CRLF并检查fullchain字节保留、cert/ca规范LF及私钥一致，不依赖宿主默认换行；历史删除测试通过native Publication移除Unix链接或Windows目录副本，继续断言缺失视图时拒绝清理历史且保留世代/密钥。修订后本地storage93项测试、原生与Windows GNU严格all-targets Clippy通过。Windows原生测试仍需CI运行，交叉检查不作为Windows运行证据。此为测试修订，不单列同版本修复日志。

## CI 跨平台回归（2026-11-12）

Windows runner 报告的两个失败源于测试假设：rcgen PEM 使用平台原生 CRLF，而拆分导出的叶子/CA PEM 由客户端规范编码为 LF；跨平台测试现显式用CRLF fullchain输入，分别断言原始链保留和拆分产物格式。RFC 7468 §2 与ABNF规定解析器须接受CRLF、CR、LF，没有要求生成器必须CRLF。另一失败把Windows `in_use`完整目录副本当成Unix文件链接删除；测试现在调用平台 `Publication::remove` 移除视图，并验证托管世代密钥保留、history范围仍拒绝猜测。

修订后storage93项测试通过，workspace414项测试通过，原生及Windows GNU all-targets严格Clippy通过。Windows目标证据仅为交叉编译/Clippy，不宣称本地原生Windows运行；提交后的GitHub Windows runner仍负责复核这两个环境相关用例。

存储查询回归验证 AND 条件、projection-before-filter、默认完整范围、当前/历史/未完成、无匹配、非法 operation/name，以及 resume 终态排除。裁剪测试刻意损坏无关证书和历史 journal，确保明确名称/当前或精确 operation 不解析范围外资料；完整查询仍报告损坏。账户测试移除私钥后继续查询轻量 metadata，再损坏无关账户，验证精确名称查询不受影响。新增 guard drop 测试验证 Ctrl-C 等待任务被中止；部署 preflight 测试确认后一个路径无效时前一个现有文件不被替换。operation ID 直接使用现有安全随机源，测试验证唯一性和原有格式边界，不把 ID 当成钥匙或授权凭据。

部署子命令重构覆盖 run/add/list/remove 的参数作用域、单个位置证书名称与部署名称选项、旧语法拒绝、成对路径互斥、reload-timeout/max-retries 上下界、脚本缺失证书/目标路径无副作用，以及真实 CLI 添加两条绑定→run 全部/单个→list→remove 的产物/版本不变检查。显式 run 复用现有绑定和检查点，不再通过独立 retry/reset 路径实现；已保存 cert.toml 绑定不需要迁移。

部署 add 的补全测试覆盖：终端默认 default 确认、已有默认名改建议 deploy-N、修改名称、非法/重复名称重试；目录不存在/是文件时重试，reload 引号错误重试，Enter 跳过，取消在持久化前返回。非TTY缺目标路径错误但缺部署名自动生成；随机名称冲突16次上限、并发唯一性、32绑定上限以及无reload的首次发布/续期/精确文件地址均有测试。参数树递归测试验证除用户授权的deploy show双位置参数外，其他命令最多一个业务位置参数。

四种精确路径逐一独立可用，CLI回归穷举全部15种非空组合，核对首次部署和续期后的字节与源文件一致、未指定产物不创建。存储边界覆盖空集合、每一种相对路径及所有重复目标配对；解析测试确认四个选项没有 requires 残留，并分别与 --target 互斥。

部署可靠性回归覆盖打开/发布失败后继续下一目标、历史Deployed与本次execution_error分别报告、自动部署库存损坏时单次/批量退出失败；update只修改指定字段、清除reload、替换目标后不自动执行，非法更新不改配置。权限用例检查Unix默认0600、证书0644/私钥0640、父目录不变、update延后生效与续期沿用；非Unix明确拒绝显式mode。目标所有权测试包括同/跨证书冲突、并发争用、父目录symlink及..别名、托管控制文件保护。

真实测试进程覆盖stdout/stderr成功和退出7、双路各256KiB输出在64KiB截断且继续排空、超时保留部分输出、超时/丢弃future终止后代，以及成功父进程退出后的残留进程清理。JSON事件保留输出和错误且不混入人类日志；PTY实际验证update缺省证书/部署选择和run实时stdout/stderr展示。2026-11-12本地workspace共497项测试通过，另3项仅供子进程/PTY调用的fixture默认忽略；严格all-targets Clippy、rustdoc、Windows GNU all-targets交叉检查、依赖/feature/TLS/import策略及fmt/diff检查通过。Windows进程job原生运行和真实服务reload仍交由对应平台CI/部署验收，不把本地进程测试或交叉编译当作该证据。

新签发交互用例覆盖全部五种方式、裸issue域名和方法补全、webroot目录输入、standalone/TLS-ALPN默认及IPv6自定义地址、显式参数零提示、恢复零提示、错误输入重试、通配符/显式方法配置限定菜单、每步取消、JSON/脚本缺输入无提示且不创建data-dir；实际PTY仅运行补全，不访问真实CA或绑定公网监听端口。

部署show覆盖两个可省略位置参数解析、额外参数/非法名称拒绝；裸命令/仅证书在脚本里都拒绝缺失身份，终端支持两级选择。详情测试覆盖目录四类解析路径、精确文件15种子集、无reload、带空格argv引用、控制字符转义、JSON完整配置、所有保存执行字段。端到端只读测试删除实际证书私钥后仍可show，并验证配置/journal不变、没有发布/进程调用；吊销未确认/已吊销/缺in_use仍可检查，缺绑定报告错误。列表保留摘要与Tips，不主动泄露reload参数；show按显式查看配置的意图展示argv。
