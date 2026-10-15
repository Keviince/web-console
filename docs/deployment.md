# 部署与维护

## DNS、HTTPS 与反向代理

将 `console.example.com` 和 `*.console.example.com` 指向反向代理，转发到同一 web-console 后端并保留浏览器 `Host`。证书必须覆盖两个名称；`*.example.com` 无法覆盖 `device.console.example.com`。参考 `deploy/nginx.conf.example`。

代理需要转发 WebSocket Upgrade、关闭流量缓冲，并为 KVM 长连接和固件上传设置足够的超时与体积上限。不缓存认证响应；避免在访问日志中记录 `/auth/callback` 和 `/__webconsole/start` 的查询参数。

`PORTAL_URL` 不带路径。`DEVICE_DOMAIN` 可以是门户本身或独立后缀，但门户不能处于它的下级。容器必须能访问设备内网和 Authentik 的 discovery、token、JWKS 端点。

## Authentik subject 与排障

使用 provider 实际 discovery 中的 issuer。首次不清楚 subject 时，可保留 `.env.example` 的占位值，用自己的账号登录一次；此时访问会被拒绝。在日志中查找 `reason=subject_not_allowed` 的已验签 `subject`，将它写入 `OIDC_ALLOWED_SUB` 后重建服务：

```bash
docker compose logs --tail=100 web-console
docker compose up -d --force-recreate web-console
```

subject 是账号标识，不能直接假定为用户名、邮箱或用户 ID。修改 Authentik subject mode 后须同步更新。HS256 要求与 provider 一致的 Client Secret；公钥签名要求容器可达 JWKS。更改签名配置后重启以重新读取 discovery。不支持加密 JWE 身份令牌。

认证失败页面和 `X-WebConsole-Request-ID` 响应头提供参考编号，可与日志 `request_id` 对照：

| reason | 排查方向 |
| --- | --- |
| `signature_invalid` | Client Secret / Signing Key |
| `issuer_mismatch` / `audience_mismatch` | issuer / Client ID |
| `jwks_fetch_failed` | 容器网络、TLS、端点是否被验证页拦截 |
| `token_expired` / `token_not_yet_valid` | 各端系统时间 |
| `browser_cookie_mismatch` / `nonce_mismatch` | 从相同浏览器门户重新登录 |
| `token_invalid_grant` | 授权码过期、重复使用、回调地址及 PKCE |
| `subject_not_allowed` | 个人 subject 白名单 |

设备连接失败同样有参考编号。`tls_certificate_invalid` 需要核对 CA、主机名和 SAN；`certificate_pin_mismatch` 需要重新核对设备证书；`https_required` 需要将地址改为最终 HTTPS 地址。不会自动关闭 TLS 验证或跨主机提交凭据。

可使用保存的设备配置建立临时登录会话进行诊断：

```bash
docker compose exec -T web-console /usr/local/bin/web-console -test-device <设备子域名标识>
```

该命令检查连接与登录状态，不修改设备设置。日志不记录密码、原始令牌或上游响应正文。门户退出只撤销本应用会话，Authentik 全局 SSO 仍由 Authentik 管理。

## 数据与密钥

容器以 root（UID/GID 0）运行，将 Compose 文件旁的宿主机 `./data` 目录挂载到 `/app/data`，不使用命名卷，也不需要将目录所有者设为 UID 10001。首次部署执行 `mkdir -p data secrets && chmod 700 data secrets`，两个 secret 文件设为 0600；二进制部署时也应确保运行用户能读取 secret 并写入数据目录。

Dockerfile 和 Compose 均不指定运行用户，使用新镜像默认的 root 用户。升级时需拉取包含此修改的新镜像，或从源码重新构建；旧镜像仍可能默认使用 UID 10001。

Compose 中的 `volumes:` 服务字段用于声明目录挂载，`./data:/app/data` 是 bind mount，不会创建 Docker 命名卷。`read_only`、`tmpfs`、`cap_drop` 和 `security_opt` 都是可选安全加固，默认配置已移除：只读根文件系统仍允许写入 data 挂载目录；`tmpfs` 仅提供临时目录；`cap_drop: ALL` 会让 root 无法绕过旧文件的所有者权限；`no-new-privileges` 阻止进程通过执行文件获取新权限。按部署需要可自行启用。

不要更换已有数据库的加密密钥。备份前停止服务，完整备份 `data/` 及 `.env`、两个 secret；不要仅复制运行中的 `.db` 而忽略 WAL。

```bash
mkdir -p backups
docker compose stop web-console
sudo tar czf backups/web-console-data.tgz -C data .
docker compose start web-console
```

将 `.env` 和 `secrets/` 另行备份到受保护的离线位置。恢复时停止服务，将归档解压到空的 `./data` 目录，执行 `sudo chown -R 0:0 data && sudo chmod 700 data`，恢复原密钥与 OIDC 配置后启动。

从已有命名卷或旧 WebConsole / WebControl 迁移时，先在旧配置下停止服务并核实原实际卷名（例如 `web-console_data` 或 `webconsole_webconsole_data`），再将全部数据复制到空的 `./data` 目录：

```bash
docker compose stop web-console
docker volume ls
mkdir -p data
# 将 <实际卷名> 替换为已核实的卷名；data 必须是空目录。
docker run --rm \
  --mount type=volume,source=<实际卷名>,target=/old-data,readonly \
  --mount "type=bind,source=$PWD/data,target=/new-data" \
  alpine:3.23 sh -c 'cp -a /old-data/. /new-data/ && chown -R 0:0 /new-data && chmod 700 /new-data'
# 替换 compose.yaml 为新的目录挂载配置，删除 .env 中的 DATA_VOLUME。
docker compose up -d --force-recreate web-console
```

保留原密钥、OIDC 配置与域名；验证数据正常后再考虑清理旧卷。新程序兼容 `webconsole.db` 与 `webcontrol.db`。不要同时让两个实例使用同一数据目录。协议路径 `/__webconsole/*` 和诊断响应头保持兼容。

## 本地开发

完整认证流需要 OIDC。仅开发时可以设置 `PORTAL_URL=http://console.localhost:8080`、`DEVICE_DOMAIN=console.localhost`、`DEV_HTTP=true`。前端 `npm run dev` 的 Vite 代理用于界面开发，真实 OIDC 流须使用与 `PORTAL_URL` 相同的 origin。
