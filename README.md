# DingTalk OIDC Gateway (钉钉 OIDC 标准化网关)

这是一个基于 FastAPI 构建的轻量级、无状态的 OIDC (OpenID Connect) 协议转换网关。它将钉钉企业内部微应用的非标准 OAuth 登录流程，无缝转换为标准的 OIDC 协议。

通过本网关，你可以零代码将 **Grafana、Proxmox VE (PVE)、Gitlab** 等支持标准 OIDC 的开源/商业中间件直接接入钉钉企业单点登录 (SSO)。

## ✨ 核心特性

* **标准的 OIDC 协议支持**：完整实现 `/.well-known/openid-configuration` 自动发现端点，支持 RS256 非对称加密与动态 JWKS (`/keys`)。
* **无状态凭证透传 (Stateless Proxy)**：网关自身**不保存**任何钉钉的 `AppKey` 或 `AppSecret`。下游系统共用同一套钉钉应用凭证，网关仅负责协议转换，极大提升安全性。
* **动态声明转换 (Dynamic Claim Transformation)**：彻底解决不同系统对 `email` 格式的严苛校验与撞号问题。网关可根据回调地址 (`redirect_uri`) 动态下发定制化的伪装邮箱或属性。
* **富权限透传 (RBAC Ready)**：自动解析钉钉用户字典，向 OIDC Payload 中注入 `is_admin`、`groups`、`dept_id_list` 等扩展声明，完美支持下游系统的动态角色映射。

## 🚀 部署指南

推荐使用 Docker 与 Docker Compose 进行容器化部署。

### 1. 环境准备

在项目根目录创建一个 `.env` 文件（请勿提交到版本库）：

```ini
# 服务端配置 (必填：必须是下游系统能访问到的本网关完整公网/内网 URL，末尾不带斜杠)
OIDC_ISSUER=https://oidc.yourdomain.com

# 监听端口与日志
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
LOG_LEVEL=INFO

# 默认授予的组织组名称
GRAFANA_ORGANIZATIONS=Main Org

# 【核心】动态邮箱属性分配策略
# 钉钉不要求强制验证邮箱，但大部分系统要求邮箱，因此支持用多种方式生产假邮箱。
# 格式: "回调URL特征词|策略; 特征词2|策略2"
# 支持策略: email, org_email, userid_email, unionid_email, name_email, name_uri_email, userid, unionid, name, name_uri

CLIENT_EMAIL_MAPPING="grafana.domain.com|userid_email; dify.domain.com|email; pve.domain.com|unionid_email"

```

### 2. 策略映射说明 (`CLIENT_EMAIL_MAPPING`)

由于很多系统共用一对钉钉 AppID，网关通过识别下游系统传来的 `redirect_uri`（回调地址）包含的关键词，来决定在 JWT 的 `email` 字段中返回什么格式的数据：

* `grafana.domain.com|userid_email`: 当回调地址包含 `grafana.domain.com` 时，返回 `[userid]@userid.dingtalk`（避免 Grafana 真实邮箱冲突）。
* `pve.domain.com|name_uri_email`: 返回 URI 编码后的姓名邮箱 `%E5%BC%A0%E4%B8%89@name.dingtalk`（解决部分老旧系统不支持中文邮箱的问题）。

### 3. Docker Compose 启动

```yaml
services:
  dingtalk-oidc:
    build: .
    container_name: dingtalk-oidc-gateway
    restart: always
    ports:
      - "8000:8000"
    env_file:
      - .env
    volumes:
      # 重要：持久化生成的 RSA 私钥和 UserInfo 缓存
      - ./data:/opt/fastapi-app/data

```

运行 `docker-compose up -d` 即可启动服务。

```

## 🔒 安全须知

1. 本网关在首次启动时会自动在 `./data/` 目录下生成 `oidc_rsa.pem`（用于签发 JWT 的私钥）。请务必保护好该目录的宿主机读取权限。
2. 虽然配置了 `CLIENT_EMAIL_MAPPING`，但下游系统在获取到虚假邮箱后，应**尽量避免**向该邮箱发送真实邮件通知。