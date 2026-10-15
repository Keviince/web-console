# 构建与发布

## 本地构建

需要 Go 1.26、Node.js 22、Python 3.10+：

```bash
python scripts/release.py --version v0.1.0
```

脚本构建前端并交叉编译 Linux amd64、arm64，生成 `dist/v0.1.0/` 下的两份安装包、干净源码 ZIP 与 `checksums.txt`。可用 `--arch amd64` 或 `--arch arm64` 仅构建一种架构；已有最新前端时可加 `--skip-frontend`。

每份安装包包含可执行程序 `web-console`、`web/dist`、配置示例、文档及许可证。请一起部署这些文件。源码 ZIP 使用明确的文件清单，排除本地配置、数据库、密钥、编译缓存和部署记录；上传 GitHub 应使用这份源码。

Dockerfile 使用构建机执行 Node 和 Go 构建，再交叉编译目标架构；最终 scratch 镜像仅包含程序、CA 证书和前端，以 root（UID/GID 0）运行，自带程序健康检查。Compose 将宿主机 `./data` 挂载到 `/app/data`。

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=v0.1.0 -t ghcr.io/keviince/web-console:0.1.0 --push .
```

仅本地构建可以指定单架构并使用 `--load`。离线分发用 `docker save` 导出镜像，接收端使用 `docker load -i` 载入，然后将 `.env` 中 `WEBCONSOLE_IMAGE` 改为相应的本地标签。

## GitHub Actions

1. 在 GitHub 创建 `Keviince/web-console`，解压源码 ZIP 后上传其内容，包含隐藏的 `.github` 目录。
2. 启用 Actions，允许 GITHUB_TOKEN 写入仓库和 Packages；无需额外 registry 密钥。
3. 提交触发 CI：Go vet / race、前端构建、浏览器回归和双架构交叉编译。
4. 推送版本标签，例如 `v0.1.0`。Release 工作流重新运行检查，全部通过后上传 Linux 安装包、源码 ZIP 与校验文件；Docker 工作流验证 Go 测试后发布 GHCR 多架构镜像。
5. 首次发布后，将 GHCR 包设为 Public，供匿名拉取。镜像标签包括 `0.1.0`、`0.1`，稳定版本另有 `latest`；预发布版本不会覆盖 latest。

自动发布需要实际上传仓库和推送标签才会执行，本地构建不会创建远程仓库或发布任何内容。
