# 签发协议与挑战发布

长期边界见[项目契约](../project-contract.md)，命令与参数见[CLI契约](../cli-contract.md)，证据见[签发测试](../issuance-testing.md)。本页描述当前实现，不提供尚未接入的builder或provider示例。

## 一个状态机，多种发布方式

IssueService接收dyn IssueSession、dyn ChallengeSolver和IssueExecution。core决定下一步动作，protocol提供wire模型，服务推导材料、保存检查点、通知CA和轮询。CLI实现manual_dns、manual_http、webroot、standalone、tls_alpn，不再维护第二套协议流程。

IssueRequest保存域名集合、账户、密钥算法及固定验证实现/配置。每个世代独立key/CSR，material.sha256绑定固定字节。恢复沿用保存的材料及配置；相似未完成查询按完整定义匹配，不按主域名猜测。

## 提交与恢复

1. newOrder前保存创建意图；201响应先保存Location再解析body。无URL且结果不确定时拒绝自动再下单。
2. 保存全部验证材料后调用ready；返回false产生action_required。人工方式首次脚本执行先展示材料，后续显式确认。
3. ack前保存Submitted。明确4xx Problem拒绝时恢复NotSubmitted供下次显式调用重试；超时/传输错误/5xx保留Submitted，不重放。
4. finalize提交固定CSR；未知结果只轮询。明确4xx Problem拒绝后保存未提交状态和Retry-After，显式恢复先查订单再按ready推进；orderNotReady在本次有界流程内继续查询；badCSR拒绝保留原HTTP证据，不能靠resume更换CSR。
5. valid后下载并检查PEM、SAN、公钥、有效期及相邻链签名，写完整产物与回退计划，再发布in_use视图、提交catalog，最后Completed。提交失败按实际catalog恢复视图。

账户ID、directory和kid绑定签发身份；轮换后的当前签名器可继续旧申请。旧thumbprint继续绑定原挑战材料，不被新密钥替换。授权/选中challenge终态保留Problem并拒绝恢复；已valid订单不会因历史challenge记录而错误阻止下载。

执行在CA发现前建立同一取消令牌/deadline，发现、确认、轮询及自动部署共享剩余预算。request_timeout只限制单次请求，max_polls限制本次订单轮询轮数。默认local poll_interval为5秒，不缩短有效Retry-After；每轮展示计数和等待来源。

只读verify不调用ready、ack、finalize或清理。IssueSession.record读取最新持久化状态；每会话IO串行，后台任务携带许可和租约到写完，即使上层等待取消也不提前解锁。

## 统一建议性预检

库 `aster_acme::precheck::Runner` 为显式调用的检查器提供每阶段默认5秒预算、取消和整体deadline，返回带输入索引的结构化Report；本地超时保留完成项，并标记TimedOut/NotChecked。检查器由应用注入：HTTP归aster_acme的precheck-http，CAA/TXT归validation的precheck-caa/precheck-dns。CLI `cert/precheck/{caa,dns,http}` 仅负责调用时机和展示；solver负责发布材料，CAA不会成为签发状态或执行资格。普通不匹配、解析错误和本地超时只提示，CA最终检查；JSON仍只输出既有业务报告，不夹杂人类预检日志。

库默认不启用预检，IssueService::run不自动调用预检；CLI默认启用自己的precheck feature，关闭后仍可正常签发。嵌入者可自行选择检查器并通过Runner::new覆盖默认预算。

issue与renew共用Foreground：directory发现后、首次newOrder前检查全部DNS标识符。恢复已有订单或已提交的创建不重复查CAA；directory未广告caaIdentities时输出无法判断，不根据CA URL猜测身份。CAA阶段所有SAN共享5秒，保留已完成观察，超时后的未检查项为未知。

`protocol::DirectoryMeta.caa_identities`对应RFC8555 §7.1.1，多个issuer是任选匹配，不要求全部发布。`core::caa`按RFC8659处理issue/issuewild、加法授权和未知critical；`validation::caa`使用系统递归解析器（包含别名跟随），只对原标识符爬父域，遇到首个非空CAA集合停止，不合并父子集合、不查询根。NODATA/NXDOMAIN与SERVFAIL等失败分开。通配符去掉*.查询，有issuewild则覆盖issue；仅iodef不限制。RFC8657账户URI/验证方式逐条匹配，CA参数支持和未知critical支持仍由CA决定，客户端结果只为建议。DEBUG可查看本地记录；INFO/WARN显示标识符、查询来源及匹配／无法判断原因。

## 人工验证与终端

DNS/HTTP本地预检共用专用时限，固定最多5秒，均为建议性，不代替CA验证。HTTP预检复用既有连接池，遵循系统／环境代理，允许内网及回环目标；不执行本地DNS过滤或固定，代理可负责域名解析。保留HTTP/HTTPS跳转次数、端口、正文和总时间限制。普通预检失败或耗尽自身预算时仅警告后继续CA验证；用户取消或整体deadline到达时立即停止执行，不继续CA验证。人工验证确认复用原生inquire::Confirm，输入/编辑/回显与其他CLI一致；默认否，Esc/Ctrl-C退出。inquire公开API不支持外部取消钩子：等待用户输入期间不强制中断控件，shutdown等待其结束，随后重新检查取消/整体期限，在失效执行中不得继续通知CA。终端raw mode由inquire管理，不跨线程强制关闭、不遗留后台提示。

## Webroot文件所有权

根目录只在新申请时规范化一次，所有SAN共用。token决定HTTP路径；操作ID与token摘要决定同级receipt。先写完整内容并sync，用独占hard_link发布，随后同步挑战目录；新建公开文件/目录使用Unix0644/0755，Windows继承权限。不把私钥或CSR写入webroot。Unix从可信根固定子目录句柄，所有创建、设权、hard_link、隔离和删除使用no-follow目录相对操作；Windows用拒绝reparse且不共享DELETE的目录句柄阻止使用中的目录被替换。后台IO任务登记到solver，shutdown等待已启动worker结束后才释放签发租约。

已有挑战目录从不自动修改权限；适配器只保证自己新建的目录为公开可遍历权限。webroot就绪后可做短时建议性HTTP读取，CA仍是最终可达性判断者；运维者需确保现有HTTP服务器能穿过既有目录层级。

已有相同内容借用，不覆盖冲突内容。拥有文件的target和receipt必须是同一对象且内容未变。终态清理先把实际路径项移入私有同级临时目录再核验；确认归属才删除，身份变化则无覆盖恢复。恢复冲突保留隔离内容并报告位置，不删除替换后的用户文件。

成功或CA明确invalid后尝试清理；失败保留cleanup_pending，不抹掉证书或原CA Problem。取消、超时、轮询上限和结果未知保留材料；manual实现只返回用户清理指令。

## 临时HTTP/TLS服务

listener统一TCP绑定、最多64条连接、每连接5秒期限、任务回收和取消。HTTP standalone复用Tokio/Hyper HTTP1，不引入Web框架或手写解析；默认0.0.0.0:80，只响应当前材料的规范Host/path GET。拒绝请求体、绝对代理URI、query、未知域名/路径和其他方法，最多8KiB/32个头，每连接一个请求。

TLS-ALPN默认0.0.0.0:443，复用rustls/AWS-LC与同一listener。每DNS标识符独立P-256挑战证书，单一SAN、critical acmeIdentifier（DER OCTET STRING中的32字节摘要）；仅SNI匹配且客户端提供acme-tls/1时选择，不复用证书私钥，不支持通配符/IP。

restore只重建临时响应服务，不重发ack；run每个返回路径await有界shutdown。宿主直接丢弃future时仍须关闭或丢弃solver，Drop负责兜底。公网端口、A/AAAA、Host/SNI转发由用户负责，不自动提权或停其他服务。
