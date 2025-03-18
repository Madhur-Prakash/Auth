import aioredis

# redis connection
# client = aioredis.from_url('redis://default@13.217.2.25:6379', decode_responses=True) #in production

client =  aioredis.from_url('redis://localhost', decode_responses=True) # in local testing
