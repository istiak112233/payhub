from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    admin_password: str = "admin123"
    admin_email: str = "admin@gmail.com"
    public_base_url: str = "http://127.0.0.1:8000"
    admin_bot_token: str = ""
    admin_telegram_id: str = ""
    default_coin: str = "USDT"
    invoice_expire_minutes: int = 30
    session_secret: str = "payhub-secret-change-me"
    db_path: str = "data/payhub.db"

@lru_cache
def get_settings() -> Settings:
    return Settings()
