from pymongo import MongoClient
MONGO_URI = "mongodb://localhost:27017/auth"
from motor.motor_asyncio import AsyncIOMotorClient

# connect to MongoDB
conn = MongoClient(MONGO_URI)
mongo_client = AsyncIOMotorClient(MONGO_URI)
