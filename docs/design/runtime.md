# 命令输出、HTTP生命周期与构建

职责入口见[架构](../architecture.md)，参数和退出语义见[CLI契约](../cli-contract.md)，故障证据见[运行时测试](../cli-runtime-testing.md)。

## 命令输出

CommandContext拥有本次OutputSession和惰性HttpPool。执行返回报告，main统一渲染最终结果；输出、提示和tracing共享会话，JSON只返回一个结构化结果，不混入人类日志。stdout/stderr独立决定颜色，common/output、log、time、table是唯一格式边界。

用户及CA文本在终端边界转义；确认标签和值都处理控制字符，路径拼接前转义，避免换行伪造字段。诊断write/flush失败都保留在会话，不能最后仍输出成功报告。取消与deadline不同：用户取消退出130，IO/协议失败退出1。

## HTTP池和发送证据

HttpPool复用Forge/reqwest客户端和连接，AcmeClient分别拥有nonce、directory和请求策略。每请求设置UA/deadline，纯本地操作不初始化HTTP。账户UA优先级为本次参数、账户偏好、内置默认；单次覆盖不回写账户。

ACME签名请求禁跳转，HTTP-01建议性检查可有限跟随HTTP/HTTPS。CA资源URL保留合法精确字符串，拒绝会被HTTP层重新编码、导致签名目标不一致的输入。RFC 3986 §2.2/§3.4允许查询中的单引号，但当前WHATWG URL传输层会把HTTP(S)查询里的裸单引号编码为%27；按RFC 8555 §6.4不能改写CA提供的签名URL，因此只拒绝查询里的裸单引号，路径单引号及已编码%27仍可使用。请求/响应正文、nonce和签名不进入debug，诊断只记录阶段、状态、计时和Retry-After元数据。

换钥通过transport发送观察区分“确定尚未发送POST”和“请求已开始、结果可能未知”。前者可撤销本次Pending；后者保留双钥对账。badNonce仅在明确拒绝后有限重签，成功响应不因缺nonce丢失Location。

## Reload进程

process-wrap提供Unix进程组及Windows Job Object。先观察主进程退出并保留状态，再清理拥有的后代，最后排空stdout/stderr；避免后台进程继承管道把成功命令误判成超时。每路每次保留64KiB后继续排空，超时/取消清理进程，正常退出也清理残留后代。不承诺终止主动脱组的daemon。

输出按部署名、尝试次数及流标注，人类/JSON复用同一事件。外部命令输出不自动脱敏，不写入cert.toml。命令成功退出不等于服务健康已验收。

## Build identity

build.rs只在Git仓库确实管理当前源码时读取revision，嵌套源码归档不借用父仓库。监视HEAD/index/packed-refs/实际存在的分支引用及已跟踪文件，不监视不存在的loose ref，不递归监视target。dirty明确仅表示已跟踪文件变更，未跟踪文件不在其范围。

支持ASTER_BUILD_REVISION、ASTER_BUILD_TIME及SOURCE_DATE_EPOCH注入；version运行时不调用Git或网络、不加载配置。release参数在根profile，保留unwind和函数符号，不带源码调试信息。

## Panic与依赖策略

仅CLI在创建Tokio前安装发布的Forge panic hook。私有报告写统一根crash.log，正常命令不创建；Unix私有权限、无链接、有界大小及非阻塞锁，Windows继承权限。公开错误不含原始payload/回溯，panic不授权重放ACME mutation。

normal/build依赖feature由scripts策略检查，限定rustls/AWS-LC、需要的HTTP/交互/日志功能。根workspace统一版本及features，库不安装宿主hook；详细Rust规则见[Rust约定](../rust-guidelines.md)。
