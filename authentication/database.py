from contextlib import asynccontextmanager
MONGO_URI = "mongodb://localhost:27017/"
from motor.motor_asyncio import AsyncIOMotorClient


DATABASE_NAME = "auth"

# connect to MongoDB
client = AsyncIOMotorClient(MONGO_URI)
conn = client[DATABASE_NAME]

# Define a dependency similar to get_db
@asynccontextmanager
async def get_db():
    try:
        yield conn  # Provide the database instance
    finally:
        client.close()  # Close the client connection when done