import os
from dataclasses import dataclass
from dotenv import load_dotenv

# Load environment variables from centralized /etc/uisp path
ENV_PATH = "/etc/uisp/uisp.env"
if os.path.exists(ENV_PATH):
    load_dotenv(ENV_PATH)


@dataclass
class AppConfig:
    env: str
    bind_ip: str
    port: int
    log_level: str
    uisp_base_url: str
    uisp_app_key: str
    telegram_token: str
    telegram_chat_id: str
    nas_config_path: str


def load_config() -> AppConfig:
    """Load configuration from .env and environment variables."""
    env = os.getenv("ENV", "production")
    bind_ip = os.getenv("BIND_IP", "0.0.0.0")
    port = int(os.getenv("PORT", "8001"))
    log_level = os.getenv("LOG_LEVEL", "info")

    uisp_base_url = os.getenv("UISP_BASE_URL", "https://uisp-ros1.afrieta.com/")
    uisp_app_key = os.getenv("UISP_APP_KEY", "")
    telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    nas_config_path = os.getenv("NAS_CONFIG_PATH", "/etc/uisp/nas_config.json")

    return AppConfig(
        env=env,
        bind_ip=bind_ip,
        port=port,
        log_level=log_level,
        uisp_base_url=uisp_base_url,
        uisp_app_key=uisp_app_key,
        telegram_token=telegram_token,
        telegram_chat_id=telegram_chat_id,
        nas_config_path=nas_config_path,
    )
