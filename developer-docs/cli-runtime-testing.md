# CLI 崩溃与 feature 策略验证

Forge panic `=0.1.0-alpha.2` 的实际 hook 仅在独立测试子进程安装，避免改变工作区并发测试进程的全局 hook。覆盖人类/JSON、NO_COLOR、重定向/关闭 stderr、主线程及 Tokio worker panic、JoinError 接住后仍失败、并发 panic 单份公开文档、payload 多行移除、私有报告写失败不泄漏回溯。正常命令、help/version 通过实际二进制核验没有 crash.log 副作用；显式/默认数据根解析不读配置或密钥。

文件测试检查 0600、新文件仅在 panic 时出现、追加不截断、1MiB 上限、符号/硬链接、宽权限文件、锁占用与未知上游报告格式失败关闭。保存的密钥哨兵文件字节不变；现有账户/证书事务测试继续证明持久化、取消及固定 CSR 恢复。report writer 使用既有 Unix 权限机制，本地 macOS 测试不等于 Linux CI 或 Windows 原生运行验收。

release 专项使用仓库 `opt-level=z / lto / debug=0 / panic=unwind / strip=debuginfo`，通过报告包含 hook_child 函数符号检查无源码调试数据时的可定位性；不声称栈溢出/OOM 可恢复。

```sh
cargo test --workspace --locked
cargo test -p aster_acme_cli --release --locked common::panic::tests
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 scripts/check-workspace-deps.py
python3 scripts/check-tls-backend.py
python3 scripts/check-dependency-features.py
python3 -m unittest discover -s scripts/tests
```

feature 策略直接读取 Cargo 实际生产 normal/build 依赖图，合并后的未知 feature 一律要求审查。Python 负例注入 native TLS、ring、gzip/multipart、inquire editor、tracing local-time，验证不会因根依赖声明了 default-features=false 就放过间接启用。Forge panic 没有 feature 开关，其 chrono/clock 为上游不可选依赖；本次没有 fork 或更改 Forge 工作树。

实际 CLI 回归仅使用临时目录和 loopback：批量续期部分失败/取消单JSON与退出1/130、bare resume 的交互取消、账户密钥生成与离线展示、正常命令无报告副作用。未访问公网 CA，未对用户真实账户或证书运行修改操作。


标准库锁替换后，Unix 原有锁竞争/取消/重建锁身份测试保持；测试文件身份按 Unix dev/inode 或 Windows volume/file-index 比较。Windows 目标 all-targets 编译/Clippy 与本机运行分别记录。in_use 的复制发布模式在 Unix 主机也执行完整集、回滚、缺失源、非法 marker 与用户额外内容负例；Windows 不依赖管理员 symlink 权限。AsterFs 的生态职责见 #4，待交付文件原语见 #3，不把这些 issue 的存在视为已实现。

标准库跨进程锁专项：子进程在父进程持锁时退出73表示竞争，释放后正常退出，sentinel 内容不变；同一测试在 Windows 原生 CI 中执行。生产依赖策略禁止重新引入仅用于锁的 aster-fs/fs2/fs4；未来需要 AsterFs 新能力时必须显式审查并更新策略。

2026-11-11 本轮交付证据：macOS 工作区334项通过（85 library +135 CLI +88 storage +14 core +10 protocol +2 validation），随后 CLI 路径断言调整135项通过；macOS/Windows GNU all-targets 严格Clippy零warning，Windows GNU CLI完整链接成功。Windows原生运行及新增三平台CI尚未验收；这些结果不应被写成已完成Windows运行验收。AsterFs本轮只更新定位文档，无运行时API变更、未发布。
