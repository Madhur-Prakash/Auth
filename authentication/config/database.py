from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

load_dotenv()

# MONGO_URI = "mongodb://ec2-54-165-238-39.compute-1.amazonaws.com:27017"  # --> for aws testing

DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")

if DEVELOPMENT_ENV == "docker":
    MONGO_URI = "mongodb://root:example@mongo:27017/" # -> for docker testing
else:
    MONGO_URI = "mongodb://localhost:27017/auth" # --> for local testing

# connect to MongoDB
mongo_client = AsyncIOMotorClient(MONGO_URI)
