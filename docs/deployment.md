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

容器以 UID 10001 运行，数据保存在 `/app/data`。`secrets` 目录建议 0700，Compose 的 secret 文件可设 0444，让非 root 容器读取；二进制部署的 secret 可设为运行用户可读的 0600。

不要更换已有数据库的加密密钥。备份前停止服务，完整备份数据卷及 `.env`、两个 secret；不要仅复制运行中的 `.db` 而忽略 WAL。

```bash
mkdir -p backups
docker compose stop web-console
# 将 <实际卷名> 替换为已通过 docker volume ls 核实的卷名。
docker run --rm -v <实际卷名>:/data:ro -v "$PWD/backups:/backup" alpine:3.23 \
  tar czf /backup/web-console-data.tgz -C /data .
docker compose start web-console
```

将 `.env` 和 `secrets/` 另行备份到受保护的离线位置。恢复时停止服务，将归档解压到新卷，保留 UID 10001，恢复原密钥与 OIDC 配置，设置 `DATA_VOLUME` 为新卷名后启动。

从旧 WebConsole / WebControl 迁移时先停止旧服务，将新 `.env` 的 `DATA_VOLUME` 设置为原实际卷名（例如旧默认 `webconsole_webconsole_data`），保留原密钥、OIDC 配置与域名。新程序兼容 `webconsole.db` 与 `webcontrol.db`。不要同时让两个实例使用同一数据卷。协议路径 `/__webconsole/*` 和诊断响应头保持兼容。

## 本地开发

完整认证流需要 OIDC。仅开发时可以设置 `PORTAL_URL=http://console.localhost:8080`、`DEVICE_DOMAIN=console.localhost`、`DEV_HTTP=true`。前端 `npm run dev` 的 Vite 代理用于界面开发，真实 OIDC 流须使用与 `PORTAL_URL` 相同的 origin。
