from motor.motor_asyncio import AsyncIOMotorClient

# MONGO_URI = "mongodb://localhost:27017/auth" # --> for local testing
MONGO_URI = "mongodb://ec2-44-208-23-132.compute-1.amazonaws.com:27017/auth"  # --> for aws testing
# connect to MongoDB
mongo_client = AsyncIOMotorClient(MONGO_URI)
