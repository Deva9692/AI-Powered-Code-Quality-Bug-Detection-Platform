import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-fallback")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-key-fallback")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR / 'storage' / 'app_dev.db'}"
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "storage", "uploads")
    REPORT_FOLDER = os.path.join(BASE_DIR, "storage", "generated_reports")
    TEMP_FOLDER = os.path.join(BASE_DIR, "storage", "temp")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

config_by_name = {
    "development": Config,
    "default": Config,
}