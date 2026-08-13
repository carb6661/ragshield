from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "RAGShield"
    app_version: str = "0.1.0"
    database_url: str = "sqlite:///./ragshield.db"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    enable_network_targets: bool = False

    model_config = SettingsConfigDict(env_prefix="RAGSHIELD_", env_file=".env")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()

