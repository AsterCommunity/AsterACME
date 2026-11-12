# Rust 与依赖约定

## 所有权与依赖

- stable、edition 2024；每个crate显式声明版本，包/目录用下划线，可执行文件为aster-acme。
- 版本、来源、features只定义在根workspace.dependencies，成员只写workspace=true；增加依赖使用cargo add，再核对根表和策略脚本。
- 禁止use super（含测试）；使用crate::实际所有者路径，不保留旧路径转发别名。禁止生产unsafe和unwrap/expect/panic/unreachable/unimplemented/todo，依赖workspace严格lint。
- 领域枚举分发优先穷尽match；普通条件保留if。新抽象应承担策略、转换、生命周期、所有权或测试隔离，不增加纯透传facade。
- 公开API说明失败策略，wire使用具名类型序列化；库不安装宿主panic hook。Box用于对象所有权或有证据的布局收益，不仅为压lint。
- HTTP复用Forge池和rustls/AWS-LC，生产feature统一受scripts策略约束。文件锁使用标准库，平台文件机制集中在state_file。

## 源码组织与排版

- 模块文档在前，相关use/mod/常量紧凑组织；同一概念的类型及impl相邻，主要入口在前、辅助函数按调用顺序就近。
- 相邻函数、类型、impl、trait、测试与内联mod之间留一行空行。注释/属性紧贴条目；函数体按实际阶段分段，不给每条语句机械加空行。
- 一个文件最多一个末尾cfg(test) mod tests；测试import/helper归该测试区域，外部测试模块按归属拆分，不增加重复verification模块。
- 使用stable cargo fmt；条目间距仍需审查，不全局打开会分割函数体的空行配置。
- crate拥有自己的README；内部API变化在同一变更更新声明、调用方、测试和文档。

验证入口见[测试指南](testing.md)，不在根AGENTS复制命令清单。
