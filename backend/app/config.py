from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "RAGShield"
    app_version: str = "0.2.0"
    database_url: str = "sqlite:///./ragshield.db"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    enable_network_targets: bool = False
    http_target_allowlist: str = ""
    allow_private_targets: bool = False
    allow_insecure_http: bool = False
    http_timeout_seconds: float = 10.0
    max_response_bytes: int = 1_000_000

    model_config = SettingsConfigDict(env_prefix="RAGSHIELD_", env_file=".env")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def http_target_hosts(self) -> set[str]:
        return {
            host.strip().casefold()
            for host in self.http_target_allowlist.split(",")
            if host.strip()
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
