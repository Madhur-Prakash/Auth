from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = "mongodb://localhost:27017/auth" # --> for local testing
# MONGO_URI = "mongodb://ec2-54-165-238-39.compute-1.amazonaws.com:27017"  # --> for aws testing

# MONGO_URI = "mongodb://root:example@mongo:27017/" # -> for docker testing
# connect to MongoDB
mongo_client = AsyncIOMotorClient(MONGO_URI)
