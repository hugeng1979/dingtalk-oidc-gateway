import logging
import time
import os
import json
import base64
from urllib.parse import parse_qs, quote, urlencode
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
import jwt
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import httpx
from colorama import Fore, Style, init
import pickle
from config import settings

init(autoreset=True)
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format=f'{Fore.BLUE}level={Fore.RESET}%(levelname)s {Fore.BLUE}ts={Fore.RESET}%(asctime)s {Fore.BLUE}caller={Fore.RESET}%(filename)s:%(lineno)d {Fore.BLUE}msg={Fore.RESET}%(message)s',
    encoding='utf-8',
    datefmt='%Y-%m-%dT%H:%M:%S'
)

# 生产环境默认关闭 Swagger 文档，仅本地调试通过 DOCS_ENABLED=true 开启
app = FastAPI(
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
)


def _issuer() -> str:
    """获取去除末尾斜杠的 issuer 标准值（discovery 与 JWT 签发/校验共用）"""
    return settings.oidc_issuer.rstrip('/')


# --- 敏感信息脱敏工具（用于日志输出） ---
SENSITIVE_KEYS = {"accesstoken", "refreshtoken", "access_token", "refresh_token",
                  "clientsecret", "client_secret", "mobile", "email", "sessionid"}


def _mask(value: str, keep: int = 4) -> str:
    """脱敏字符串：保留首尾各 keep 位，中间以 *** 代替"""
    if not value or not isinstance(value, str) or len(value) <= keep * 2:
        return "***"
    return f"{value[:keep]}***{value[-keep:]}"


def _mask_payload(data: dict) -> dict:
    """递归脱敏字典中的敏感字段"""
    result = {}
    for key, value in (data or {}).items():
        if isinstance(value, dict):
            result[key] = _mask_payload(value)
        elif isinstance(value, str) and key.lower() in SENSITIVE_KEYS:
            result[key] = _mask(value)
        else:
            result[key] = value
    return result


class OAuthTokenError(Exception):
    """Token 端点标准 OAuth2 错误异常"""

    def __init__(self, error: str, description: str, status_code: int = 400):
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description)


# --- RSA 密钥管理 (用于 RS256 和 JWKS) ---
class KeyManager:
    def __init__(self, key_path=settings.rsa_key_path):
        self.key_path = key_path
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        self.private_key, self.public_key = self._load_or_generate_key()
        self.kid = "dingtalk-oidc-key-1"

    def _load_or_generate_key(self):
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
        else:
            logging.info(f"{Fore.GREEN}正在生成新的 RSA 密钥对...{Style.RESET_ALL}")
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(self.key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
        return private_key, private_key.public_key()

    def get_jwks(self):
        """生成 JWKS 用于公开访问"""
        jwk = json.loads(RSAAlgorithm.to_jwk(self.public_key))
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}


key_manager = KeyManager()


# --- 数据持久化 (Pickle 版本，仅缓存 UserInfo) ---
class UserTokenCache:
    def __init__(self, file_path=settings.cache_file_path):
        self.file_path = file_path
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

    def _read_data(self):
        """读取 pickle 二进制数据"""
        try:
            with open(self.file_path, 'rb') as file:
                return pickle.load(file)
        except (FileNotFoundError, EOFError, pickle.UnpicklingError):
            return {}

    def _write_data(self, data):
        """写入 pickle 二进制数据"""
        with open(self.file_path, 'wb') as file:
            pickle.dump(data, file)

    def set_user_info(self, unionid, user_info: dict):
        data = self._read_data()
        data[unionid] = {
            "user_info": user_info,  # 仅存储从钉钉拉回的用户大字典
            "updated_at": int(time.time())
        }
        self._write_data(data)

    def get_valid_user_info(self, unionid):
        """获取有效的用户信息，如果过期返回 None"""
        data = self._read_data().get(unionid, {})
        user_info = data.get('user_info')
        updated_at = data.get('updated_at', 0)

        if user_info:
            if time.time() - updated_at > settings.user_token_cache_expire:
                logging.info(f"{Fore.YELLOW}本地缓存的用户信息已过期。{Style.RESET_ALL}")
                return None
            else:
                logging.info(f"命中本地文件缓存，用户: {Fore.CYAN}{user_info.get('name')}{Fore.RESET}")
                return user_info
        return None


# --- 钉钉与 OIDC 业务处理 ---
class DingTalkHandler:
    def __init__(self):
        self.cache_manager = UserTokenCache()
        self._app_token_cache = {}

    def _get_app_access_token(self, client_id: str, client_secret: str):
        current_time = time.time()
        app_cache = self._app_token_cache.get(client_id, {"token": None, "expires_at": 0})

        if app_cache["token"] and current_time < app_cache["expires_at"] - 60:
            return app_cache["token"]

        logging.info(
            f"{Fore.YELLOW}App AccessToken 过期或不存在，正在使用 ClientID [{client_id[:6]}...] 请求钉钉 API...{Style.RESET_ALL}")
        resp = httpx.post(
            "https://api.dingtalk.com/v1.0/oauth2/accessToken",
            json={"appKey": client_id, "appSecret": client_secret}
        ).json()
        logging.debug(f"钉钉 accessToken 接口原始响应: {_mask_payload(resp)}")

        token = resp.get('accessToken')
        expire_in = resp.get('expireIn', 7200)

        if token:
            self._app_token_cache[client_id] = {
                "token": token,
                "expires_at": current_time + expire_in
            }
            return token

        logging.error(f"获取 App AccessToken 失败: {_mask_payload(resp)}")
        raise OAuthTokenError("server_error", "钉钉 App AccessToken 获取失败，请检查 AppKey/AppSecret", 502)

    def _get_user_info_from_dingtalk(self, unionid: str, client_id: str, client_secret: str):
        app_token = self._get_app_access_token(client_id, client_secret)

        userid_resp = httpx.post(
            f"https://oapi.dingtalk.com/topapi/user/getbyunionid",
            params={"access_token": app_token},
            json={"unionid": unionid}
        ).json()
        logging.debug(f"钉钉 getbyunionid 接口原始响应: {_mask_payload(userid_resp)}")
        userid = userid_resp.get('result', {}).get('userid')

        if not userid:
            logging.error(f"无法根据 UnionId 获取 UserId: {_mask_payload(userid_resp)}")
            return None

        user_info_resp = httpx.post(
            f"https://oapi.dingtalk.com/topapi/v2/user/get",
            params={"access_token": app_token},
            json={"userid": userid}
        ).json()
        logging.debug(f"钉钉 user/get 接口原始响应: {_mask_payload(user_info_resp)}")
        return user_info_resp.get('result', {})

    @staticmethod
    def _get_dynamic_email(user_info: dict, redirect_uri: str) -> str:
        """根据 redirect_uri 的特征关键词解析邮箱策略"""
        rule_str = getattr(settings, 'client_email_mapping', '').strip()
        strategy = "email"  # 默认策略为真实邮箱

        # 关键词匹配逻辑 (例如 .env 中配置 CLIENT_EMAIL_MAPPING="grafana|userid;dify|name_uri")
        if rule_str and redirect_uri:
            redirect_uri_lower = redirect_uri.lower()
            for rule in rule_str.split(';'):
                parts = [p.strip() for p in rule.split('|') if p.strip()]
                if len(parts) >= 2:
                    keyword = parts[0].lower()
                    if keyword in redirect_uri_lower:
                        strategy = parts[1].lower()
                        break

        userid = user_info.get('userid', '')
        unionid = user_info.get('unionid', '')
        name = user_info.get('name', 'Unknown')

        if strategy == 'email':
            # 真实邮箱优先，钉钉资料缺失时回退合成邮箱，保证下游 email 字段必存在
            return user_info.get('email') or f"{userid}@userid.dingtalk"
        elif strategy == 'org_email':
            return user_info.get('org_email') or f"{userid}@userid.dingtalk"
        elif strategy == 'userid_email':
            return f"{userid}@userid.dingtalk"
        elif strategy == 'unionid_email':
            return f"{unionid}@unionid.dingtalk"
        elif strategy == 'name_email':
            return f"{name}@name.dingtalk"
        elif strategy == 'name_uri_email':
            return f"{quote(name)}@name.dingtalk"
        elif strategy == 'userid':
            return userid
        elif strategy == 'unionid':
            return unionid
        elif strategy == 'name':
            return name
        elif strategy == 'name_uri':
            return quote(name)
        else:
            return ''

    @staticmethod
    def _generate_oidc_token(user_info: dict, client_id: str, redirect_uri: str):
        now = int(time.time())

        userid = user_info.get('userid', '')
        unionid = user_info.get('unionid', '')
        name = user_info.get('name', 'Unknown')

        # === 核心：传入 redirect_uri 获取专属于该系统的邮箱 ===
        dynamic_email = DingTalkHandler._get_dynamic_email(user_info, redirect_uri)

        roles = []
        role_list = user_info.get('role_list', [])
        if isinstance(role_list, list):
            for r in role_list:
                if isinstance(r, dict) and 'name' in r:
                    roles.append(r['name'])

        groups = [settings.grafana_organizations]
        if roles:
            groups.extend(roles)

        is_admin = (user_info.get('admin') == 'true') or (user_info.get('boss') == 'true')
        app_role = 'Admin' if is_admin else 'Viewer'

        payload = {
            'iss': _issuer(),
            'sub': userid,  # 强烈建议用 userid 或 unionid 作为全局唯一标识
            'aud': client_id,
            'exp': now + settings.user_token_cache_expire,
            'iat': now,

            'name': name,
            'preferred_username': name,

            # === 将伪装后的邮箱直接覆盖掉标准 email 声明 ===
            'email': dynamic_email,

            'picture': user_info.get('avatar', ''),
            'phone_number': user_info.get('mobile', ''),

            'unionid': unionid,
            'title': user_info.get('title', ''),
            'is_admin': is_admin,
            'job_number': user_info.get('job_number', ''),
            'dept_id_list': user_info.get('dept_id_list', []),

            'organizations': [settings.grafana_organizations],
            'groups': groups,
            'role': app_role
        }

        return jwt.encode(
            payload,
            key_manager.private_key,
            algorithm="RS256",
            headers={"kid": key_manager.kid}
        )

    async def process_login(self, code: str, grant_type: str, client_id: str, client_secret: str, redirect_uri: str):
        """透传 ClientID, ClientSecret, 和 RedirectURI 处理登录"""
        user_access_resp = httpx.post(
            "https://api.dingtalk.com/v1.0/oauth2/userAccessToken",
            json={
                "clientId": client_id,
                "clientSecret": client_secret,
                "code": code,
                "grantType": grant_type
            }
        ).json()
        logging.debug(f"钉钉 userAccessToken 接口原始响应: {_mask_payload(user_access_resp)}")

        user_access_token = user_access_resp.get('accessToken')
        if not user_access_token:
            logging.error(f"Code 换取 Token 失败: {_mask_payload(user_access_resp)}")
            raise OAuthTokenError("invalid_grant", "钉钉授权码换取用户 Token 失败，授权码无效或已过期")

        me_resp = httpx.get(
            "https://api.dingtalk.com/v1.0/contact/users/me",
            headers={"x-acs-dingtalk-access-token": user_access_token}
        ).json()
        logging.debug(f"钉钉 users/me 接口原始响应: {_mask_payload(me_resp)}")
        unionid = me_resp.get('unionId')
        if not unionid:
            logging.error(f"获取用户 unionId 失败: {_mask_payload(me_resp)}")
            raise OAuthTokenError("server_error", "钉钉用户信息接口返回异常，缺少 unionId", 502)

        # 1. 尝试从缓存提取完整 UserInfo
        user_info = self.cache_manager.get_valid_user_info(unionid)
        if not user_info:
            # 2. 缓存中没有，去钉钉拉取
            user_info = self._get_user_info_from_dingtalk(unionid, client_id, client_secret)
            if not user_info:
                raise OAuthTokenError("server_error", "无法根据 UnionId 获取钉钉用户详情", 502)
            self.cache_manager.set_user_info(unionid, user_info)

        # 3. 动态签发（携带回调地址用于策略判断）
        oidc_token = self._generate_oidc_token(user_info, client_id, redirect_uri)

        logging.info(
            f"用户 {Fore.GREEN}{user_info.get('name')}{Fore.RESET} 登录完成。分配邮箱: {self._get_dynamic_email(user_info, redirect_uri)}")

        return {
            'access_token': oidc_token,
            'id_token': oidc_token,
            'token_type': 'Bearer',
            'expires_in': settings.user_token_cache_expire,
            'refresh_token': user_access_resp.get('refreshToken')
        }


dingtalk_handler = DingTalkHandler()


# --- 路由配置 ---
# 同时注册根路径与 /dingtalk 前缀两套路由：
# - Nginx 对 /dingtalk/ 去前缀转发时命中根路径路由（当前生产模式，见 docs/nginx-gateway.conf）
# - Nginx 原样转发时命中 /dingtalk 前缀路由（兼容历史下游直连）
@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    """OIDC 自动发现端点：所有对外地址基于 OIDC_ISSUER 拼接"""
    issuer = _issuer()
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/keys",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat",
            "name", "preferred_username", "email", "picture",
            "groups", "organizations", "unionid",
        ],
    }


@app.get("/keys")
@app.get("/dingtalk/keys")
async def jwks():
    """提供公钥供第三方应用验证 Token"""
    return key_manager.get_jwks()


@app.get("/oauth")
@app.get("/dingtalk/oauth")
async def dingtalk_oauth(redirect_uri: str, response_type: str, client_id: str, scope: str = "openid", state: str = ""):
    """引导至钉钉登录：透传 client_id/redirect_uri/state，scope 归一化为钉钉支持的 openid"""
    logging.info(f"授权跳转请求: client_id={client_id} scope={scope} redirect_uri={redirect_uri}")
    params = {
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "client_id": client_id,
        # 钉钉授权端点仅支持 openid，下游传入的 email/profile 等一律丢弃
        "scope": "openid",
        "prompt": "consent",
    }
    if state:
        params["state"] = state
    # 必须 urlencode，避免 scope 空格、回调地址中的特殊字符破坏跳转 URL
    return RedirectResponse(
        url=f"https://login.dingtalk.com/oauth2/auth?{urlencode(params)}",
        status_code=302)


@app.post("/token")
@app.post("/dingtalk/token")
async def dingtalk_token(request: Request):
    """Token 交换端点：兼容 Form 与 Basic 两种凭证方式，失败返回标准 OAuth2 错误"""
    body = await request.body()
    params = parse_qs(body.decode('utf-8'))

    client_id = params.get('client_id', [None])[0]
    client_secret = params.get('client_secret', [None])[0]
    # 提取回调地址，交给业务层做邮箱分配策略判断
    redirect_uri = params.get('redirect_uri', [''])[0]

    # 兼容从 HTTP Basic Auth 中获取 (authentik 默认以 Basic 方式传递凭证)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Basic '):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
            basic_id, basic_secret = decoded.split(':', 1)
            if basic_id:
                client_id = basic_id
            if basic_secret:
                client_secret = basic_secret
        except Exception as e:
            logging.warning(f"解析 Basic Auth 失败: {e}")

    code = params.get('code', [None])[0]
    grant_type = params.get('grant_type', [None])[0]

    logging.info(f"收到 Token 请求: client_id={client_id} grant_type={grant_type} redirect_uri={redirect_uri}")

    if grant_type != 'authorization_code':
        logging.warning(f"拦截: 不支持的授权类型 {grant_type}")
        return JSONResponse(status_code=400, content={
            "error": "unsupported_grant_type",
            "error_description": f"仅支持 authorization_code，收到: {grant_type}",
        })

    if not client_id or not client_secret:
        logging.warning(f"{Fore.RED}拦截: 请求未包含合法的 Client 凭证{Style.RESET_ALL}")
        return JSONResponse(status_code=401, content={
            "error": "invalid_client",
            "error_description": "缺少 client_id/client_secret（支持表单或 Basic Auth 方式）",
        }, headers={"WWW-Authenticate": "Basic"})

    if not code:
        return JSONResponse(status_code=400, content={
            "error": "invalid_request",
            "error_description": "缺少 code 参数",
        })

    try:
        return await dingtalk_handler.process_login(code, grant_type, client_id, client_secret, redirect_uri)
    except OAuthTokenError as e:
        logging.error(f"{Fore.RED}Token 请求处理失败: {e.error} - {e.description}{Style.RESET_ALL}")
        return JSONResponse(status_code=e.status_code, content={
            "error": e.error,
            "error_description": e.description,
        })


@app.get("/userinfo")
@app.get("/dingtalk/userinfo")
async def dingtalk_userinfo(request: Request):
    """返回用户信息：无效或缺失 Token 时返回 401，避免下游误将错误体当作用户信息解析"""
    token_header = request.headers.get('Authorization')
    if not token_header or not token_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={
            "error": "invalid_token",
            "error_description": "缺少 Bearer Token",
        })

    token = token_header.split(' ')[1]
    try:
        # 透传模式下，不同客户端拥有不同的 aud，关闭 verify_aud，只验证签名和签发者
        payload = jwt.decode(
            token,
            key_manager.public_key,
            algorithms=["RS256"],
            issuer=_issuer(),
            options={"verify_aud": False}
        )
        logging.info(f"UserInfo 请求成功: sub={payload.get('sub')} name={payload.get('name')}")
        return payload
    except jwt.PyJWTError as e:
        logging.error(f"Token 解析失败: {e}")
        return JSONResponse(status_code=401, content={
            "error": "invalid_token",
            "error_description": "Token 无效或已过期",
        })


if __name__ == "__main__":
    import uvicorn

    logging.info(f"{Fore.GREEN}启动 OIDC 网关，监听地址: {settings.server_host}:{settings.server_port}{Style.RESET_ALL}")

    uvicorn.run(
        "main:app",
        host=settings.server_host,
        port=settings.server_port,
        log_level=settings.log_level.lower(),
        reload=False
    )
