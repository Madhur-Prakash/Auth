from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

load_dotenv()

# MONGO_URI = "mongodb://ec2-54-165-238-39.compute-1.amazonaws.com:27017"  # --> for aws testing

DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")

# Use environment variables for database credentials
if DEVELOPMENT_ENV == "docker":
    MONGO_USER = os.getenv("MONGO_USER", "root")
    MONGO_PASS = os.getenv("MONGO_PASS", "example")
    MONGO_HOST = os.getenv("MONGO_HOST", "mongo")
    MONGO_PORT = os.getenv("MONGO_PORT", "27017")
    MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:{MONGO_PORT}/"
else:
    MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
    MONGO_PORT = os.getenv("MONGO_PORT", "27017")
    MONGO_DB = os.getenv("MONGO_DB", "auth")
    MONGO_URI = f"mongodb://{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}"

# connect to MongoDB with error handling
try:
    mongo_client = AsyncIOMotorClient(MONGO_URI)
except Exception as e:
    raise ConnectionError("Failed to connect to MongoDB")
