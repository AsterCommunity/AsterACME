# Rust 与依赖约定

## 所有权与依赖

- Rust/Cargo 1.100+ stable、edition 2024；每个crate显式声明版本，包/目录用下划线，可执行文件为aster-acme。
- 版本、来源、features只定义在根workspace.dependencies，成员只写workspace=true；增加依赖使用cargo add，再核对根表和策略脚本。
- 禁止 `use super` / `use super::...` 隐式导入（含测试），改用 `crate::` 实际所有者路径；明确的 `super::module::Item` 路径可以保留，不做机械改写。内部API不保留旧路径转发别名。禁止生产 `unsafe`；各crate根通过 `cfg_attr(not(test), deny(...))` 禁止生产unwrap/expect/panic/unreachable/unimplemented/todo，这些不是workspace lint。
- 领域枚举分发优先穷尽match；普通条件保留if。新抽象应承担策略、转换、生命周期、所有权或测试隔离，不增加纯透传facade。
- 公开API说明失败策略，wire使用具名类型序列化；库不安装宿主panic hook。Box用于对象所有权或有证据的布局收益，不仅为压lint。
- HTTP复用Forge池和rustls/AWS-LC，生产feature统一受scripts策略约束。文件锁使用标准库，平台文件机制集中在state_file。

## Cargo 原生依赖检查与发布冷却期

根 `workspace.lints.cargo.unused_dependencies = "deny"` 由全部成员继承，普通 `cargo check --workspace --locked` 即检查生产与构建依赖；现有三平台 CI 使用同一命令，不另装依赖扫描工具。仅供测试使用的依赖放入 `dev-dependencies`。Cargo 原生 lint 暂不检查 dev-dependencies；带测试 target 的构建可能把仅在测试中使用的生产依赖视为已使用，因此保留普通 check，不能只用 `--all-targets` 代替。

本机报告未使用时，先核对所有平台的 `cfg` 与 build script，不能据此删除其他平台的依赖。仅特定平台使用的生产依赖声明在对应 `target.'cfg(...)'.dependencies`；例如 CLI 与 storage 的 `tempfile` 在非 Unix 清理路径中实际使用，归 `cfg(not(unix))` 生产依赖，各平台测试另从 dev-dependencies 取得。

[`.cargo/config.toml`](../.cargo/config.toml) 配置 `registry.global-min-publish-age = "7 days"` 和 `resolver.incompatible-publish-age = "deny"`。新增或更新依赖解析时，带 `pubtime` 的 registry 版本须发布满 7 天；没有发布时间元数据的 registry 版本不受该策略保证，path/git 依赖也不受 registry 冷却期约束。`Cargo.lock` 中已有版本继续可用，不会因冷却期自动降级或阻断锁定构建。

经核对必须立即采用的安全修复，可用 `cargo --config 'resolver.incompatible-publish-age="allow"' update -p PACKAGE --precise VERSION` 做单次显式覆盖并审查 lockfile diff；该次解析的传递依赖同样不受冷却期限制，不把覆盖写入项目配置。

配置和 lint 的官方语义见 [Cargo 发布冷却期](https://doc.rust-lang.org/cargo/reference/config.html#registryglobal-min-publish-age)与 [unused_dependencies](https://doc.rust-lang.org/cargo/reference/lints.html#unused_dependencies)。冷却期配置要求 Cargo 1.100+，根 `rust-version` 同步该最低版本，防止旧工具链忽略策略。

## 源码组织与排版

- 模块文档在前，相关use/mod/常量紧凑组织；同一概念的类型及impl相邻，主要入口在前、辅助函数按调用顺序就近。
- 相邻函数、类型、impl、trait、测试与内联mod之间留一行空行。注释/属性紧贴条目；函数体按实际阶段分段，不给每条语句机械加空行。
- 一个文件最多一个末尾cfg(test) mod tests；测试import/helper归该测试区域，外部测试模块按归属拆分，不增加重复verification模块。
- 使用stable cargo fmt；条目间距仍需审查，不全局打开会分割函数体的空行配置。
- crate拥有自己的README；内部API变化在同一变更更新声明、调用方、测试和文档。

验证入口见[测试指南](testing.md)，不在根AGENTS复制命令清单。
