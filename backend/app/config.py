import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    database_url: str = os.getenv("DATABASE_URL") or "sqlite:///./dev.db"
    nvd_api_key: str | None = os.getenv("NVD_API_KEY") or None
    deepl_api_key: str | None = os.getenv("DEEPL_API_KEY") or None


settings = Settings()
