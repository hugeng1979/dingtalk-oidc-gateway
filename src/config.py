import logging
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from colorama import Fore, Style

class Settings(BaseSettings):
    # --- 钉钉 OIDC 配置 ---
    # dt_client_id: str
    # dt_client_secret: str

    # --- 服务端配置 ---
    oidc_issuer: str = "http://localhost:8000"
    grafana_organizations: str = "Main Org"
    server_host: str = "0.0.0.0"  # 容器内建议监听 0.0.0.0
    server_port: int = 8000       # 新增端口配置

    # --- 安全与缓存配置 ---
    user_token_cache_expire: int = 60 * 60 * 24 * 7
    cache_file_path: str = "data/userinfo.pkl"
    rsa_key_path: str = "data/oidc_rsa.pem"

    # --- 日志配置 ---
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

@lru_cache()
def get_settings() -> Settings:
    # 注意：此时 main.py 可能还没执行 init(autoreset=True)
    print(f"{Fore.GREEN}正在加载系统环境变量与配置中心...{Style.RESET_ALL}")
    return Settings()

settings = get_settings()