from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

    app_name: str = "Real-Time Threat Monitoring & Analysis Platform"
    mongo_uri: str = Field(default="mongodb://localhost:27017", alias="MONGO_URI")
    mongo_db: str = Field(default="threat_platform", alias="MONGO_DB")
    jwt_secret: str = Field(default="change-me", alias="JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=60, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    cors_origins: str = Field(default="http://localhost,http://localhost:3000,http://localhost:4173", alias="CORS_ORIGINS")
    webhook_url: str | None = Field(default=None, alias="WEBHOOK_URL")
    smtp_host: str | None = Field(default=None, alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_username: str | None = Field(default=None, alias="SMTP_USERNAME")
    smtp_password: str | None = Field(default=None, alias="SMTP_PASSWORD")
    alert_email_from: str | None = Field(default=None, alias="ALERT_EMAIL_FROM")
    alert_email_to: str | None = Field(default=None, alias="ALERT_EMAIL_TO")
    rate_limit_login: int = Field(default=10, alias="RATE_LIMIT_LOGIN")
    rate_limit_logs: int = Field(default=120, alias="RATE_LIMIT_LOGS")
    anomaly_enabled: bool = Field(default=True, alias="ANOMALY_ENABLED")
    anomaly_contamination: float = Field(default=0.08, alias="ANOMALY_CONTAMINATION")
    seed_default_users: bool = True

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
