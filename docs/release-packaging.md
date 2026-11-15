# Release packaging

`Cargo.toml` 的 release profile 保持 `panic = "unwind"`，不在 profile 中改变符号或 panic 语义。发布二进制完成 release 构建后，使用脚本将发行文件与诊断符号文件分开：

```bash
cargo build --release -p aster_acme_cli --locked
python3 scripts/package-release-binary.py \
  target/release/aster-acme \
  release-artifacts/aster-acme-${VERSION}
```

macOS 会在原路径 strip 二进制，归档完整副本 `aster-acme.symbols`，并将 `dwarfdump --uuid` 输出保存为 `aster-acme.uuid`。按版本保存 `.symbols` 和 `.uuid`，用户提供地址与偏移后，用对应符号副本运行 `atos` 解析；符号文件不属于 deploy 载荷。

Linux 会使用 `objcopy --only-keep-debug` 生成 `aster-acme.debug`，再用 `strip --strip-all` 去除发行二进制中的符号并写入 GNU debug link。`.debug` 文件必须与对应版本一起归档，不随 deploy 发布。

Windows 的 PDB 生成和二进制配对流程尚未确定，脚本会拒绝处理 Windows 二进制，避免发布无法可靠配对的符号文件。

脚本不修改 release profile，也不改变 deploy 的“发布普通文件并 reload”语义。
