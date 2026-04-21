from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

    app_name: str = "Real-Time Threat Monitoring & Analysis Platform"
    database_path: str = Field(
        default_factory=lambda: str(Path(__file__).resolve().parents[2] / "data" / "app_state.json"),
        alias="DATABASE_PATH",
    )
    jwt_secret: str = Field(default="change-me", alias="JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=60, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    cors_origins: str = Field(
        default=(
            "http://localhost,http://localhost:3000,http://localhost:4173,http://localhost:18080,"
            "http://localhost:18081,http://127.0.0.1,http://127.0.0.1:3000,http://127.0.0.1:4173,"
            "http://127.0.0.1:4174,http://127.0.0.1:18080,http://127.0.0.1:18081"
        ),
        alias="CORS_ORIGINS",
    )
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
    enable_external_enrichment: bool = Field(default=True, alias="ENABLE_EXTERNAL_ENRICHMENT")
    enrichment_timeout_seconds: int = Field(default=6, alias="ENRICHMENT_TIMEOUT_SECONDS")
    virustotal_api_key: str | None = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    alienvault_otx_api_key: str | None = Field(default=None, alias="ALIENVAULT_OTX_API_KEY")
    ioc_watchlist: str = Field(default="", alias="IOC_WATCHLIST")
    seed_default_users: bool = Field(default=True, alias="SEED_DEFAULT_USERS")
    seed_demo_logs: bool = Field(default=True, alias="SEED_DEMO_LOGS")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def ioc_watchlist_set(self) -> set[str]:
        return {item.strip() for item in self.ioc_watchlist.split(",") if item.strip()}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
