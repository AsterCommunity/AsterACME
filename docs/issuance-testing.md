# 手动 DNS-01 签发验收

## 规范与能力边界

实现对照 RFC 8555 原文 §7.1.3（订单与 expires）、§7.1.4–7.1.5（授权/challenge）、§7.4（newOrder、finalize 与 CSR）、§7.4.2（PEM 链下载）、§7.5.1（通知与轮询）、§8.4（TXT 摘要），并复用 §6 的精确 URL、kid/JWS、nonce、POST-as-GET 和错误策略。证书/CSR 采用 PKCS#8、PKCS#10 和 X.509/SAN。

本轮只有 manual_dns：人工发布归用户/CLI，DNS 查询归 Hickory，CA 通知和状态推进归库。--force 只跳过 DNS 查询，不能免除 CA 验证、过期判断或首次非交互的待办阶段。普通测试只使用数字 loopback HTTP 显式测试策略，不改生产默认 CA，也不安装任何测试根。

## 本地证据

文件适配器与真实签名 transport 连接 loopback CA，覆盖完整新建→两条同名 TXT 待办→重启恢复→通知两个 challenge→授权 valid→订单 ready→固定 CSR finalize→valid→PEM 下载/检查→current 切换。校验世代只创建一次，私钥/CSR 字节不变，同名多值不会覆盖；最终 SAN/公钥与申请一致，清理提示保留。

边界包括：过期订单与授权（force 也不能继续）、pending 必需 expires 缺失、非法 RFC3339、重复授权 URL、错误域名、创建响应丢失后禁止重下单、保存 Location 后坏响应可诊断、badNonce 同一申请重签、submitted finalize 的 ready 只轮询、取消/deadline、材料损坏/链接/未知版本/权限/锁竞争、同名多个世代、错误私钥/SAN/PEM 不更新 current。只读 inspect 验证不发 challenge/finalize。DNS 检查验证单 RR 分片拼接、多 RR 共存、force 不绕过取消/期限。

CLI 解析/选择测试验证 -d/-a/-n/-c/-f、resume 与新申请参数互斥、operation 仅用于恢复、order 无写命令、JSON 多候选不猜最新、申请时间输出。独立 CLI/PTY 进程验收结果以最终执行记录为准，不把库测试声称为人工公网 DNS 验证。

## 尚未验收

未执行真实 CA staging 证书签发、Pebble、DNS provider 自动写入、完整公网传播、真实断电注入、Windows ACL 或硬件密钥。相邻证书签名验证不代表公众信任路径验证；客户端不会将 staging 根加入系统。ARI 续期计划与账户签名吊销已实现并有本地 mock/存储验收；周期调度、HTTP/TLS solver、外部 CSR、自动续期和部署尚未实现。

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

新增完整产物集合测试验证 fullchain/leaf/CA 拆分、PEM/DER 私钥同一性、叶子单独返回时空 CA 文件、文件权限和任何导出失败不切换 current。布局为时间加随机后缀，与 current 相对 symlink 同级；覆盖两次切换保留历史、暂存链接崩溃恢复、外部 symlink/用户同名 current/临时文件碰撞拒绝、不读取旧 generations 目录。额外普通文件、目录和未识别链接不阻止列举；对已识别托管 journal 继续拒绝损坏或不安全链接。账户删除有额外内容时仅移除托管资料并保留原目录/锁和用户文件。

账户/config 回归覆盖七个已有账户命令缺失身份时在确认/HTTP/建账户目录前拒绝、结构化 Hint 包含 --name/--data-dir、切换缺省 default_account 安全插入、重复切换不变、注册成功后条件补回默认、移除默认再补回、已有并发选择不覆盖、缺省 contact 写入、注释/格式保留、未知版本/错误表类型/损坏文件拒绝且文本不改、并发联系人/默认更新。toml_edit 用户文档读改写集中到同一个锁内 edit helper，可选字段用 get/insert，不用索引读取缺失字段。

密码学后端统一 rustls + AWS-LC；独立公开标量测试钥和外部 cryptography 生成的 PKCS#8/ES256 签名验证标准互操作，HS256/JWK/换钥/签发全量回归通过。依赖统计（同一 macOS target normal+build 口径）由 277 降到 258，Cargo.lock 全平台/测试条目由 355 到 334。没有 native-tls/openssl-sys，CI 增加 TLS 后端守卫；Cargo.lock 中平台根证书探测组件不等于 OpenSSL TLS。


本轮参数和依赖验证：200 项 workspace 测试通过（在同一候选版本上运行），包括 cert -y/--yes 的短/长参数、终端确认跳过、DNS checker 仍调用、force 不被隐含、首次 yes+force 仍返回待办、取消/期限，以及全部现有命令确认/强制/条款选项的作用域矩阵。common/args 共享参数、-m 联系人、cert show 位置/命名目标互斥与非法输入边界均覆盖。Forge/AsterFs registry 切换与 base64 0.23.1 后重跑签名、EAB、CSR、换钥、签发、恢复与存储测试；测试不访问公网 CA。


Registry/参数与 release 收尾：200 项 workspace 测试和严格 Clippy 通过。以 opt-level=z、lto=true、codegen-units=1、debug=0、panic=unwind、strip=debuginfo 构建实际 macOS arm64 release CLI 成功；version --json 确认 profile=release，nm 确认函数符号保留。二进制约 7.6 MB（7,605,024 字节，此构建/平台样本，不作为跨平台体积保证）。--help 和 cert issue --help 的 release 进程确认产品版本与 -y/--yes；本轮仍无公网 CA mutation。

## ARI 与证书吊销验收（2026-11-11）

本轮 228 项 workspace 测试通过，严格 Clippy、workspace 依赖/TLS 策略、格式和文档构建通过。新增覆盖 RFC 9773 附录证书的 DER 序列号前导零、原有效期 2/3 回退、窗口随机边界/相同窗口不重抽、Retry-After delta/date/缺省及限值、无端点/无 AKI、短请求超时和 5xx 有限指数退避、取消和重启后请求期限保留。真实文件会话验证 fallback/ARI 选时落 TOML、重新打开保持计划和密钥，首次网络失败不撤回产物。

吊销测试核验账户 kid/精确 URL/nonce/真实 ES256 签名、DER 叶子和可选 reason、200 空 body/alreadyRevoked、未签发/身份不符/无端点/保存失败零提交、明确拒绝、未知状态/5xx/超时/取消/确认写失败保留 pending，显式重试保留原原因、已确认重复不请求。文件集/current 不变，confirmed 不再查询 ARI 或恢复签发。CLI 检查名称/ID、原因和参数作用域、JSON、缺失目标零账户/证书写入；人工输出统一 Next renewal，吊销后 disabled、未确认 suspended。Nonce 回归确认成功 POST 缺少/非法 Replay-Nonce 仍保存结果，下一次 HEAD 取新 nonce。

没有执行真实 CA 吊销或新的公网签发，不声称周期唤醒/实际自动续期已完成；daemon 和 newOrder.replaces 留给后续实现。

## 托管身份与删除范围验收

默认名称改为主域名加八位随机后缀，显式重名拒绝，自动分配只对 NameAlreadyExists 换串重试。存储竞争测试证明同名并发只有一次成功声明；CLI 分配测试实际制造名称碰撞，并核对另一名称被分配、原文件不变及权限错误不触发重试。极限域名只截短管理名称前缀，不改原 SAN。

续期存储入口固定从 cert.toml 定义读取域名/账户/CA/验证配置，拒绝不匹配账户；新版本固定独立密钥/CSR且失败保留旧 current。默认列表每个托管证书一行，默认 show 选 current，不将历史当作当前；历史可显式展开并保留完整 SAN，只有 current 的计划参与活跃查询/调度。分别测试单次/history/revoked/all 清理、未确认吊销不匹配、保留 pending、清空 current 不回退、无匹配零副作用、未知文件/链接/锁 inode 保留和中断标记。历史证书仍可按精确 ID 查询订单，但不因此激活其续期计划。

本轮全量 252 项测试通过；不含公网 CA 请求。250 ms 的 HTTP 超时测试在并行负载下出现请求尚未到达 loopback server 就超时的调度问题，已改为一秒请求预算与三秒服务端延迟，仍严格验证三次有界重试或 mutation 不重放。本轮不声称 CLI renew/daemon 已实现，旧存储 schema 不自动兼容或迁移。

## Forge HTTP alpha.2 feature 边界验收

HTTP 单独升级到 registry 的 =0.1.0-alpha.2，utils/macros 保持 alpha.1。workspace 只启用 json、rustls-aws-lc-rs、system-proxy；直接 reqwest 依赖关闭默认且不另选 features，HttpClient 显式选择 TlsBackend::Rustls。生产 normal/build feature 图确认无 form/query/multipart/stream/charset/http2/default 入口；系统代理与 rustls 平台根行为保留。

同一 macOS target、normal+build、去重包口径从 258 降至 246；全平台/测试 Cargo.lock 条目从 334 降至 326。被移除的可选依赖包括 encoding_rs、mime_guess、serde_urlencoded 和 wasm-streams。252 项 workspace 测试及严格 Clippy 通过，TLS 守卫继续拒绝 native-tls/OpenSSL；没有真实 CA mutation。

## 证书密钥与吊销原因扩展验收

本轮 261 项 workspace 测试通过：八种 CertificateKeyAlgorithm 均实际生成 PKCS#8/CSR，并用独立 AWS-LC 验证器核验 CSR 签名（P-521 SHA-512 单独选择其验证算法），校验证书公钥/SAN、PEM 与 DER 私钥一致、错钥拒绝。真实文件会话逐项完成落盘、重启打开、固定 CSR 不变、算法不可篡改、续期准备保留类型并生成新密钥；digest 未变但保存算法不符也拒绝。包含实际 RSA 8192 生成，无 OpenSSL 或新密码学依赖。

CLI 枚举驱动八种 key-type 解析、默认 ecdsa-p256、短参数 -k、resume/显式 key-type 互斥、未知算法拒绝，issue 新建/恢复输出实际选择，列表/详情/JSON 显示一致字段。十种 RFC5280 已分配原因逐项核验 struct→JSON 数字编码；7/越界/负值拒绝，CA badRevocationReason 保留且不冒报吊销成功。账户签名仍 ES256。没有真实 CA 签发/吊销，本地生成能力不等于所有公开 CA 接受。

固定CSR拒绝恢复回归实际模拟 P521 badCSR、P384 共享相同 order 成功、P521 重启后返回原错误且零额外请求，原钥/CSR不变且不写错误产物。ProblemKind 覆盖RFC8555的24项标准值及未知URI往返，线上URI序列化不变；公共CLI诊断测试覆盖badCSR、badRevocationReason、未知问题、限流和identifier子问题。此前没有持久化的真实失败原因不可从后来的valid订单还原，本轮不猜测补写或重放真实CA操作。

最终收尾：266 项 workspace 测试、严格 Clippy、workspace 依赖/TLS 策略、格式、文档构建及 whitespace 检查通过；新增公共 problem 诊断正常/未知/子问题/限流回归。所有运行使用独立构建目标目录，真实申请数据仅只读核对；没有提交新订单、重新 finalize 或吊销真实证书。
