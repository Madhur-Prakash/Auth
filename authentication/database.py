MONGO_URI = "mongodb://localhost:27017/auth"
from motor.motor_asyncio import AsyncIOMotorClient

# connect to MongoDB
mongo_client = AsyncIOMotorClient(MONGO_URI)
