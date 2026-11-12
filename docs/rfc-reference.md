# ACME 协议规范与实现参考

本项目计划使用 Rust 实现 ACME 客户端及证书生命周期自动化。本文是规范索引和设计检查表，不表示所列能力已经实现，也不以摘要替代 RFC 原文中的 MUST、SHOULD 和 MAY。

规范目录核对日期：2026-11-10。协议解释以 RFC 原文、勘误和后续更新为准；CA 的实际支持范围另行验证。

## 1. 核心规范与阅读顺序

| 优先级 | 规范 | 范围与用途 |
| --- | --- | --- |
| 必读 | [RFC 8555 — Automatic Certificate Management Environment (ACME)](https://www.rfc-editor.org/rfc/rfc8555.html) | ACME v2 主协议：服务发现、账户、订单、授权、challenge、签发、吊销与账户密钥轮换；HTTP-01、DNS-01、External Account Binding (EAB) 均在其中 |
| 必读 | [RFC 9773 — ACME Renewal Information (ARI) Extension](https://www.rfc-editor.org/rfc/rfc9773.html) | 续期信息查询、建议续期窗口与替换证书关联；设计续期调度时一并考虑 |
| 按需 | [RFC 8737 — ACME TLS Application-Layer Protocol Negotiation (ALPN) Challenge Extension](https://www.rfc-editor.org/rfc/rfc8737.html) | TLS-ALPN-01、专用 ALPN 协议与验证证书 |
| 按需 | [RFC 8738 — ACME IP Identifier Validation Extension](https://www.rfc-editor.org/rfc/rfc8738.html) | IP 地址证书标识符与 HTTP/TLS 验证扩展；DNS-01 不用于 IP 标识符验证 |
| 注册表 | [IANA ACME protocol registry (plain text)](https://www.iana.org/assignments/acme/acme.txt) · [HTML](https://www.iana.org/assignments/acme/acme.xhtml) · [XML](https://www.iana.org/assignments/acme/acme.xml) | ACME Error Types、Validation Methods、Identifier Types、Directory Metadata 等注册项；TXT 是便于人工审查的主链接，XML 适合机器处理 |
| 诊断参考 | [RFC 8657 — CAA Record Extensions for Account URI and ACME Method Binding](https://www.rfc-editor.org/rfc/rfc8657.html) | CAA 中对 ACME 账户和验证方法的约束 |

建议顺序：RFC 8555 的术语与状态机 → JWS/JWK → 账户与订单 → DNS-01/HTTP-01 → CSR 与证书下载 → RFC 9773 → 其他扩展。

### RFC 8555 实现定位

| 章节 | 实现关注点 |
| --- | --- |
| §6 | HTTPS、JWS 请求、nonce、防重放、错误、速率限制及版本演进 |
| §7.1–7.2 | Directory、资源模型、状态转换与 newNonce |
| §7.3 | 账户创建、更新、EAB、密钥轮换与停用 |
| §7.4 | 订单创建、CSR finalize、证书下载与证书链 |
| §7.5 | 获取授权、响应 challenge、授权停用 |
| §7.6 | 证书吊销及可用签名身份 |
| §8.1 | Key authorization 计算 |
| §8.3 | HTTP-01 |
| §8.4 | DNS-01 |
| §10 | 协议安全考虑 |

## 2. 密码学、证书与传输配套规范

这些规范是 ACME 的组成基础或实现参考，不要求客户端自行实现底层密码学。

| 规范 | 用途 |
| --- | --- |
| [RFC 7515 — JSON Web Signature (JWS)](https://www.rfc-editor.org/rfc/rfc7515.html) | ACME 请求签名与 base64url 表示 |
| [RFC 7517 — JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517.html) | 账户公钥表示 |
| [RFC 7518 — JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518.html) | JOSE 签名算法与密钥参数 |
| [RFC 8037 — CFRG ECDH and Signatures in JOSE](https://www.rfc-editor.org/rfc/rfc8037.html) | Ed25519/EdDSA、OKP 公钥与规范指纹 |
| [RFC 7638 — JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html) | Key authorization 所需账户公钥指纹 |
| [RFC 2986 — PKCS #10: Certification Request Syntax Specification Version 1.7](https://www.rfc-editor.org/rfc/rfc2986.html) | CSR 结构；结合 RFC 8555 的标识符要求使用 |
| [RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280.html) | X.509、扩展及证书链基础 |
| [RFC 7468 — Textual Encodings of PKIX, PKCS, and CMS Structures](https://www.rfc-editor.org/rfc/rfc7468.html) | PEM 等文本封装 |
| [RFC 8659 — DNS Certification Authority Authorization (CAA) Resource Record](https://www.rfc-editor.org/rfc/rfc8659.html) | CAA 基础规范，替代 RFC 6844；配合 RFC 8657 阅读 |
| [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html) | HTTP 状态、Retry-After 与响应语义 |
| [RFC 9457 — Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457.html) | 现代 HTTP problem details；ACME 错误仍遵守 RFC 8555 §6.7 的具体约束与类型 |

RFC 8555 引用的是当时的 HTTP 和 problem details 规范。新基础规范不能被用于悄悄改变 ACME 的线格式或必需字段。

## 3. 其他已发布的 ACME 扩展

以下规范纳入索引，暂不作为普通 Web TLS 证书客户端的默认实现范围。

| 规范 | 用途 |
| --- | --- |
| [RFC 8739](https://www.rfc-editor.org/rfc/rfc8739.html) | Support for Short-Term, Automatically Renewed (STAR) Certificates in ACME：短期自动续期证书 |
| [RFC 9115](https://www.rfc-editor.org/rfc/rfc9115.html) | An ACME Profile for Generating Delegated Certificates：委托签发 |
| [RFC 8823](https://www.rfc-editor.org/rfc/rfc8823.html) | Extensions to ACME for End-User S/MIME Certificates：终端用户 S/MIME |
| [RFC 9444](https://www.rfc-editor.org/rfc/rfc9444.html) | ACME for Subdomains：子域名授权 |
| [RFC 9447](https://www.rfc-editor.org/rfc/rfc9447.html) | ACME Challenges Using an Authority Token |
| [RFC 9448](https://www.rfc-editor.org/rfc/rfc9448.html) | TNAuthList Profile of ACME Authority Token：电话身份相关 profile |
| [RFC 9799](https://www.rfc-editor.org/rfc/rfc9799.html) | ACME Extensions for ".onion" Special-Use Domain Names |
| [RFC 9891](https://www.rfc-editor.org/rfc/rfc9891.html) | ACME Delay-Tolerant Networking (DTN) Node ID Validation Extension |

## 4. 草案与非通用能力

以下链接指向动态更新的 Internet-Draft。草案可能变更、失效或发布为 RFC；实现前重新确认状态、版本和 CA 支持，不把草案当作所有 ACME 服务端的必需能力。

- [ACME Profiles Extension](https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/)：证书 profile 选择。
- [ACME Challenge for Persistent DNS TXT Record Validation](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/)：持久 DNS TXT 验证。
- [ACME DNS Labeled With ACME Account ID Challenge](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-account-label/)：按账户区分 DNS challenge 名称。
- [ACME Scoped DNS Challenges](https://datatracker.ietf.org/doc/draft-ietf-acme-scoped-dns-challenges/)：限定范围的 DNS challenge。

完整追踪入口：[IETF ACME 工作组文档](https://datatracker.ietf.org/wg/acme/documents/)、[ACME IANA 注册表纯文本](https://www.iana.org/assignments/acme/acme.txt)、[ACME IANA 注册表 HTML](https://www.iana.org/assignments/acme/acme.xhtml)、[ACME IANA 注册表 XML](https://www.iana.org/assignments/acme/acme.xml)、[RFC 8555 勘误](https://www.rfc-editor.org/errata/rfc8555)。人工审查优先使用 TXT，工具解析使用 XML。

## 5. 客户端设计检查表

### 协议与持久化

- 区分账户密钥与证书私钥；保留账户 URL、CA directory 和恢复所需状态。
- 实现 JWS 的 jwk/kid、nonce、url 和 POST-as-GET；区分空 payload 与 JSON 空对象。
- 正确处理 badNonce、Retry-After、速率限制、problem document 与 subproblems；重试必须考虑副作用和状态恢复。
- 按订单、授权和 challenge 各自的状态机推进，不假定一次请求即完成签发。
- 支持 SAN、DNS 通配符、EAB、账户密钥轮换和吊销，并验证 CA 的实际能力。
- ARI 可用时遵循建议窗口并分散调度；不可用或失败时有明确的本地续期策略。
- 证书原子落盘、私钥权限、部署 hook、进程重启恢复属于产品可靠性要求，需在协议之外设计。

### DNS-01 自动化

- `_acme-challenge` TXT 内容来自 key authorization 的 SHA-256 摘要及 base64url 编码，遵守 RFC 8555 §8.4。
- 处理 zone 发现及 DNS 委托；不要假定最后两个域名标签就是 zone，也不要盲目写入未经配置允许的 CNAME 目标。
- 同名 TXT 值允许并存，裸域名与通配符可能同时使用同一 challenge 名称。
- 记录创建结果和所有权；清理仅删除本次创建的记录，不能清空整个 TXT RRset，也不能删除预先存在的共享记录。
- 检查预期 TXT 值而非答案一致率；考虑权威 DNS、递归缓存、负缓存、超时和取消。
- 本地传播检查通过不代表 CA 验证成功；以授权与订单状态作为签发进度依据。

## 6. DNS provider 复用来源

参考 [AptS-1547/dns-orchestrator](https://github.com/AptS-1547/dns-orchestrator) 中独立的 `dns-orchestrator-provider` crate。调查时本地 manifest 为 0.1.2、MIT，支持 Cloudflare、阿里云、DNSPod 和华为云，并提供记录查询、创建、删除等接口。

DNSO 已不作为直接依赖。按需迁入 provider 源码并保留原 MIT 版权与许可声明；迁入时重新核验 API 签名、分页、错误与 TXT 多值语义。DNS-01 编排与迁入代码的后续维护由本项目负责。

原项目 toolbox 的传播检测统计公共解析器答案一致率，可参考查询机制，不直接作为 ACME 就绪判定。

## 7. 互操作验证方向

- 使用 [Pebble](https://github.com/letsencrypt/pebble) 验证协议交互、失败路径和 challenge 流程。
- 使用真实 CA staging 验证互操作，避免以生产签发作为开发测试循环。
- 按 CA 记录 EAB、ARI、challenge、标识符类型和草案扩展的实际支持情况。
- 分开报告本地测试、staging 签发、真实 DNS 清理及部署结果；任何单项成功均不代表全部完成。

当前 ARI 与吊销实现对照：RFC 9773 §4.1–4.3（标识、窗口、重查和错误退避）、RFC 8555 §7.6（账户 kid 签名、DER 叶子、reason 和 alreadyRevoked）；具体边界见 [生命周期契约](certificate-lifecycle.md)。RFC 9773 §5 的 replaces 已由 cert renew 接入；只向广告 renewalInfo 的 CA 提交。

密钥扩展依据 RFC 8555 §6.2（账户 JWS）与 §7.4（证书 CSR）分离；CSR 算法没有 ACME 固定枚举，客户端生成能力与 CA 接受范围不同。Let’s Encrypt 当前官方范围见 https://letsencrypt.org/docs/integration-guide/ 。吊销原因按 RFC 8555 §7.6 / RFC 5280 §5.3.1 编码，badRevocationReason 由 CA 返回。

## RFC 错误状态接入核对（2026-11-12）

对照 [IANA ACME Error Types CSV](https://www.iana.org/assignments/acme/acme-error-types.csv) 与 registry TXT/XML（last updated 2026-08-04），并检查 RFC 8555 §6.7、§7.1.6、§7.4、§7.5、§8 及 RFC 8739、RFC 9115、RFC 9773、RFC 9799 和 device-attestation draft。当前 CSV 的 32 种错误均已具名解析；`badAttestationStatement` 来自 IANA 所列 draft，并非已发布 RFC。专用 CI 每周在线下载官方 CSV 并与 `ProblemKind` 双向比较，不在仓库保存副本；增删项会使检查失败，要求核对规范并补充类型和诊断。未知类型、扩展字段和 subproblems 仍无损保留。以下区分线上资源状态、完整错误响应及未确认网络副作用，不将 HTTP 错误直接映射成 order invalid。

| 结果 | 持久化与恢复策略 |
| --- | --- |
| newOrder 201 + Location | 先保存实际URL再解析Order，坏body不丢失恢复入口 |
| newOrder完整4xx problem或非problem | 保存creation_failure的实际status、problem、绝对retry_at；通常显示creation rejected，408/429显示creation deferred，Order仍not observed；不推荐resume或重复POST |
| newOrder完整5xx/其他非成功HTTP响应 | 保留错误证据，显示creation unconfirmed，不声称永久拒绝；无Location不自动重新创建 |
| newOrder断网、取消、超时、未完整读到响应 | 保留提交意图，CreationUncertain；不能由本地重建Location |
| finalize badCSR（4xx，不限定400） | 保存完整失败证据，拒绝恢复固定CSR；Order可仍ready，不伪造invalid或HTTP400 |
| finalize orderNotReady（RFC要求403） | 保存明确未提交状态及Retry-After，按max_polls/总期限先查询Order；仅再次观察ready才提交相同CSR |
| finalize其他明确4xx Problem（含429及未知类型） | 重置未提交状态并保存Retry-After；显式恢复先查询Order，保留固定CSR/key |
| finalize 5xx/传输错误或响应丢失 | 不据此允许重复finalize；恢复只观察Order，保留固定CSR/key |
| Order invalid | 保存原Order并补充授权challenge problem，终态不恢复；清理本次拥有且未变的publication |
| Authorization invalid/deactivated/expired/revoked或选中Challenge invalid | 保存实际授权状态和原problem/subproblems，以AuthorizationFailed报告；不伪造Order invalid，不继续ack/finalize或推荐resume；已签发valid订单仍可下载 |
| badNonce | transport在有限预算内用替换nonce重签；预算耗尽不推断请求成功 |
| accountDoesNotExist | 账户查找明确不存在后才允许注册；不由任意401猜测 |
| alreadyRevoked | 吊销400+该problem可确认已吊销，文件保留；与账户停用分开 |
| alreadyReplaced | RFC9773 §5明确409，newOrder错误证据保留；不移除replaces绕过，不建议恢复不存在的Order |
| CAA、签名/公钥、联系人、EAB、用户操作、compound等 | 原type/detail/instance/子问题及现有专项提示；不为每种problem虚构一个CA资源状态，也不设置通用自动重放 |

newOrder收到明确错误后，当前策略要求用户检查原因并显式新建，不实现同操作重发或自动等待429后重下单。未发布的finalize_rejection改为带HTTP证据的结构；旧JSON/TOML字段形状不兼容、不迁移。本次不操作用户已有失败记录，也不从旧日志猜测补写证据。

CAA本地观察已接入issue/renew的新订单前预检：RFC8555 §7.1.1读取caaIdentities（任一身份可匹配）；RFC8659 §3首个非空CAA集合与别名解析、§4.1 critical位、§4.2/4.3 issue/issuewild；RFC8657 §3/4账户与验证方式参数。CA扩展支持、DNSSEC及CA多视角检查不由客户端替代，结果始终建议性。系统解析器配置和DNS视角可能与CA不同，CAA并未添加强制拒绝或DNS写入能力。
