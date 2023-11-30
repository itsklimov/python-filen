from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    email: str
    password: SecretStr
    two_factor_code: str
    model_config: SettingsConfigDict = SettingsConfigDict(
        env_file="src/config/.env", env_file_encoding="utf-8"
    )


settings = Settings()
