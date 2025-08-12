import os
import aioredis
from dotenv import load_dotenv

load_dotenv()

DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")

# redis connection
# client = aioredis.from_url('redis://default@100.26.150.73:6379', decode_responses=True) #in production

if DEVELOPMENT_ENV == "docker":
    client = aioredis.from_url('redis://redis:6379', decode_responses=True)  # in docker
else:
    client = aioredis.from_url('redis://localhost', decode_responses=True)  # in local testing
