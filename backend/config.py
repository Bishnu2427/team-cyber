import os
from datetime import timedelta


class Config:
    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-prod")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-secret-change-in-prod")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)

    # Databases
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/teamcyber")
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    QDRANT_HOST = os.getenv("QDRANT_HOST", "localhost")
    QDRANT_PORT = int(os.getenv("QDRANT_PORT", 6333))

    # Internal service URLs
    ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8000")
    REPORTER_URL = os.getenv("REPORTER_URL", "http://localhost:8004")

    # Uploads
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/app/uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_MB", 100)) * 1024 * 1024
