# 容器镜像与运行

镜像随版本 tag 发布到 `ghcr.io/astercommunity/aster-acme`，并同步 Docker Hub 与 GitHub Release；覆盖 linux/amd64 和 linux/arm64。`latest` 只跟随稳定版本 tag，预发布只保留版本 tag。镜像经 cosign keyless 签名并附带 SBOM/provenance 证明：

```sh
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/AsterCommunity/AsterACME/\.github/workflows/' \
  ghcr.io/astercommunity/aster-acme:latest
```

## 数据目录

镜像把 CLI 的数据根固定为 `/data`（`ASTER_ACME_DATA_DIR`），对齐 `--data-dir` 语义。`config.toml`、`accounts/`、`certs/`、`providers/` 与 `.locks/` 都在该目录下，容器必须持久化挂载 `/data`。

## 运行

默认 entrypoint 是常驻维护 daemon（`daemon run`），前台运行、随 `restart` 策略拉起：

```sh
docker run -d --name aster-acme -v aster-acme-config:/data \
  ghcr.io/astercommunity/aster-acme:latest
```

`docker run` 带参数时作为 `aster-acme` 子命令执行（`docker run --rm 镜像 cert list`）。`docker exec` 不经过 entrypoint，所以镜像为每个顶层子命令内置同名 shim，exec 后直接跟命令即可：

```sh
docker exec -it aster-acme version
docker exec aster-acme cert list
docker exec aster-acme provider add cloudflare --backend cloudflare
```

shim 覆盖 `account`、`cert`、`daemon`、`help`、`provider`、`version`，必须与 CLI 顶层 `Command` 枚举同步（`crates/aster_acme_cli/src/app.rs`，见 Dockerfile 注释）。需要完整 shell 时 `docker exec -it aster-acme sh`。

## Compose

可复制示例见 [`examples/docker/docker-compose.yml`](../examples/docker/docker-compose.yml)：bind 目录分别暴露数据目录和发布产物。宿主目录由 compose 以 root 创建而镜像默认用户是 uid 10001，示例因此显式 `user: "0:0"`；保留镜像默认用户时先 `chown 10001:10001` 宿主目录。文件权限仍由 CLI 按[存储契约](design/storage.md)收紧，root 运行不放松密钥文件权限。

## 部署与 reload 边界

`cert deploy` 的目标目录必须挂载进容器（示例中的 `/ssl`），绑定与权限随部署发布。reload 命令在容器内执行，要求镜像内存在对应可执行文件；操作宿主服务的脚本由用户自行挂载。容器挂载与 reload 更新服务的语义由用户负责，产品边界见[项目契约](project-contract.md#验证续期与部署)。
