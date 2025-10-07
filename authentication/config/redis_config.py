import os
import aioredis
from dotenv import load_dotenv

load_dotenv()

DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")

# redis connection with environment variables
try:
    if DEVELOPMENT_ENV == "docker":
        REDIS_HOST = os.getenv("REDIS_HOST", "redis")
        REDIS_PORT = os.getenv("REDIS_PORT", "6379")
        REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
        redis_url = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}" if REDIS_PASSWORD else f"redis://{REDIS_HOST}:{REDIS_PORT}"
        client = aioredis.from_url(redis_url, decode_responses=True)
    else:
        REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
        REDIS_PORT = os.getenv("REDIS_PORT", "6379")
        REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
        redis_url = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}" if REDIS_PASSWORD else f"redis://{REDIS_HOST}:{REDIS_PORT}"
        client = aioredis.from_url(redis_url, decode_responses=True)
except Exception as e:
    raise ConnectionError("Failed to connect to Redis")
