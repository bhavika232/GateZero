"""Application configuration, loaded from environment variables (and a local .env file).

Why pydantic-settings: every value is type-checked at startup, so a typo or a missing secret
fails loudly before the server accepts traffic instead of misbehaving later.

Secrets use SecretStr so they never appear in repr(), logs, or tracebacks by accident.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GATEZERO_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "test", "production"] = "development"

    # The URL contains the DB password, so it is a secret too.
    database_url: SecretStr

    # HMAC key for API-key hashing. Without it, a stolen database dump alone is not enough
    # to verify guessed keys offline.
    api_key_pepper: SecretStr = Field(min_length=32)

    # Hard cap on the tool-call request body. Bounded so it can't be configured to "unlimited".
    max_request_bytes: int = Field(default=16_384, gt=0, le=1_048_576)


@lru_cache
def get_settings() -> Settings:
    """Load settings once per process. Tests build their own Settings instead of calling this."""
    return Settings()  # type: ignore[call-arg]  # values come from the environment
