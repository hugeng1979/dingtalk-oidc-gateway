import logging
import time
import os
import json
from urllib.parse import parse_qs
from fastapi import FastAPI, Request, Form
from fastapi.responses import RedirectResponse
import jwt
from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import httpx
from colorama import Fore, Style, init
from pydantic_settings import BaseSettings, SettingsConfigDict
import pickle

# --- 配置管理 ---
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    dt_client_id: str
    dt_client_secret: str
    grafana_organizations: str

    # OIDC 签发者 URL，例如你的服务外网地址 "https://sso.yourdomain.com"
    oidc_issuer: str = "http://localhost:8000"
    user_token_cache_expire: int = 60 * 60 * 24 * 7


settings = Settings()
init(autoreset=True)
app = FastAPI()

logging.basicConfig(
    level=logging.INFO,
    format=f'{Fore.BLUE}level={Fore.RESET}%(levelname)s {Fore.BLUE}ts={Fore.RESET}%(asctime)s {Fore.BLUE}caller={Fore.RESET}%(filename)s:%(lineno)d {Fore.BLUE}msg={Fore.RESET}%(message)s',
    encoding='utf-8',
    datefmt='%Y-%m-%dT%H:%M:%S'
)


# --- RSA 密钥管理 (用于 RS256 和 JWKS) ---
class KeyManager:
    def __init__(self, key_path='user/oidc_rsa.pem'):
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


# --- 数据持久化 (Pickle 版本) ---
class UserTokenCache:
    def __init__(self, file_path='user/userinfo.pkl'):
        # 将默认后缀改为 .pkl
        self.file_path = file_path
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

    def _read_data(self):
        """读取 pickle 二进制数据"""
        try:
            with open(self.file_path, 'rb') as file:
                return pickle.load(file)
        except (FileNotFoundError, EOFError, pickle.UnpicklingError):
            # 捕获 EOFError 和 UnpicklingError 防止文件损坏导致程序崩溃
            return {}

    def _write_data(self, data):
        """写入 pickle 二进制数据"""
        with open(self.file_path, 'wb') as file:
            pickle.dump(data, file)

    def set_user_token(self, unionid, name, token):
        data = self._read_data()
        data[unionid] = {
            "name": name,
            "token": token,
            "updated_at": int(time.time())
        }
        self._write_data(data)

    def get_valid_token(self, unionid):
        """获取有效的 Token，如果过期返回 None"""
        data = self._read_data().get(unionid, {})
        name = data.get('name')
        token = data.get('token')
        updated_at = data.get('updated_at', 0)

        if name and token:
            if time.time() - updated_at > settings.user_token_cache_expire:
                logging.info(f"{Fore.YELLOW}本地缓存的用户 {name} Token 已过期。{Style.RESET_ALL}")
                return None, None
            else:
                logging.info(f"命中本地文件缓存，用户: {Fore.CYAN}{name}{Fore.RESET}")
                return name, token
        return None, None


# --- 钉钉与 OIDC 业务处理 ---
class DingTalkHandler:
    def __init__(self):
        self.cache_manager = UserTokenCache()
        self._app_token_cache = {"token": None, "expires_at": 0}

    def _get_app_access_token(self):
        # ... (与原代码完全一致) ...
        current_time = time.time()
        if self._app_token_cache["token"] and current_time < self._app_token_cache["expires_at"] - 60:
            return self._app_token_cache["token"]

        resp = httpx.post(
            "https://api.dingtalk.com/v1.0/oauth2/accessToken",
            json={"appKey": settings.dt_client_id, "appSecret": settings.dt_client_secret}
        ).json()
        token = resp.get('accessToken')
        if token:
            self._app_token_cache = {"token": token, "expires_at": current_time + resp.get('expireIn', 7200)}
            return token
        raise Exception("DingTalk App Token Error")

    def _get_user_info_from_dingtalk(self, unionid):
        # ... (与原代码完全一致) ...
        app_token = self._get_app_access_token()
        userid_resp = httpx.post(
            f"https://oapi.dingtalk.com/topapi/user/getbyunionid",
            params={"access_token": app_token},
            json={"unionid": unionid}
        ).json()
        userid = userid_resp.get('result', {}).get('userid')
        if not userid: return None

        user_info_resp = httpx.post(
            f"https://oapi.dingtalk.com/topapi/v2/user/get",
            params={"access_token": app_token},
            json={"userid": userid}
        ).json()
        return user_info_resp.get('result', {})

    @staticmethod
    def _generate_oidc_token(user_name):
        """生成符合 OIDC 规范的 RS256 JWT"""
        now = int(time.time())
        payload = {
            'iss': settings.oidc_issuer,
            'sub': user_name,  # 通常是唯一ID，这里按原逻辑用 name
            'aud': settings.dt_client_id,
            'exp': now + settings.user_token_cache_expire,
            'iat': now,

            # 自定义 Claims (针对各类系统及中间件)
            'name': user_name,
            'preferred_username': user_name,
            'email': f"{user_name}@dingtalk.local",  # Grafana 等系统通常需要 email
            'organizations': [settings.grafana_organizations],
            'groups': [settings.grafana_organizations],
            'role': 'Viewer'
        }

        return jwt.encode(
            payload,
            key_manager.private_key,
            algorithm="RS256",
            headers={"kid": key_manager.kid}
        )

    async def process_login(self, code: str, grant_type: str):
        # 1. 换取钉钉侧 Token
        user_access_resp = httpx.post(
            "https://api.dingtalk.com/v1.0/oauth2/userAccessToken",
            json={
                "clientId": settings.dt_client_id,
                "clientSecret": settings.dt_client_secret,
                "code": code,
                "grantType": grant_type
            }
        ).json()
        user_access_token = user_access_resp.get('accessToken')
        if not user_access_token: return {}

        # 2. 获取 UnionId
        me_resp = httpx.get(
            "https://api.dingtalk.com/v1.0/contact/users/me",
            headers={"x-acs-dingtalk-access-token": user_access_token}
        ).json()
        unionid = me_resp.get('unionId')

        # 3. 缓存校验及 OIDC Token 生成
        user_name, oidc_token = self.cache_manager.get_valid_token(unionid)
        if not oidc_token:
            user_info = self._get_user_info_from_dingtalk(unionid)
            user_name = user_info.get('name') if user_info else None
            if not user_name: return {}

            oidc_token = self._generate_oidc_token(user_name)
            self.cache_manager.set_user_token(unionid, user_name, oidc_token)

        # 返回标准的 OIDC Token 响应
        return {
            'access_token': oidc_token,
            'id_token': oidc_token,  # OIDC 必须返回 id_token
            'token_type': 'Bearer',
            'expires_in': settings.user_token_cache_expire,
            'refresh_token': user_access_resp.get('refreshToken')
        }


dingtalk_handler = DingTalkHandler()


# --- OIDC 标准路由 ---

@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    """OIDC 自动发现端点"""
    issuer = settings.oidc_issuer.rstrip('/')
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/dingtalk/oauth",
        "token_endpoint": f"{issuer}/dingtalk/token",
        "userinfo_endpoint": f"{issuer}/dingtalk/userinfo",
        "jwks_uri": f"{issuer}/dingtalk/keys",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email", "groups", "organizations"],
        "scopes_supported": ["openid", "profile", "email"]
    }


@app.get("/dingtalk/keys")
async def jwks():
    """提供公钥供第三方应用验证 Token"""
    return key_manager.get_jwks()


@app.get("/dingtalk/oauth")
async def dingtalk_oauth(redirect_uri: str, response_type: str, client_id: str, scope: str = "openid", state: str = ""):
    # 引导至钉钉登录
    return RedirectResponse(
        url=f"https://login.dingtalk.com/oauth2/auth?"
            f"redirect_uri={redirect_uri}"
            f"&response_type={response_type}"
            f"&client_id={client_id}"
            f"&scope={scope}"
            f"&state={state}"
            f"&prompt=consent",
        status_code=302)


@app.post("/dingtalk/token")
async def dingtalk_token(request: Request):
    """Token 交换端点"""
    # 兼容处理 x-www-form-urlencoded 格式
    body = await request.body()
    params = parse_qs(body.decode('utf-8'))

    code = params.get('code', [None])[0]
    grant_type = params.get('grant_type', [None])[0]

    if grant_type == 'refresh_token':
        return {"error": "unsupported_grant_type"}

    if code and grant_type:
        return await dingtalk_handler.process_login(code, grant_type)
    return {"error": "invalid_request"}


@app.get("/dingtalk/userinfo")
async def dingtalk_userinfo(request: Request):
    """返回用户信息"""
    token_header = request.headers.get('Authorization')
    if not token_header or not token_header.startswith("Bearer "):
        return {"error": "Unauthorized"}

    token = token_header.split(' ')[1]
    try:
        # 使用动态生成的 RSA 公钥验证，强制校验受众和签发者
        payload = jwt.decode(
            token,
            key_manager.public_key,
            algorithms=["RS256"],
            audience=settings.dt_client_id,
            issuer=settings.oidc_issuer
        )
        return payload
    except jwt.PyJWTError as e:
        logging.error(f"Token 解析失败: {e}")
        return {"error": "Invalid Token"}