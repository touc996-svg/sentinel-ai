import os

from dotenv import load_dotenv

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "SENTINEL AI")
APP_VERSION = os.getenv("APP_VERSION", "0.1.0")
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./sentinel.db",
)
