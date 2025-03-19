import aioredis

# redis connection
client = aioredis.from_url('redis://default@44.213.131.177:6379', decode_responses=True) #in production

# client =  aioredis.from_url('redis://localhost', decode_responses=True) # in local testing
