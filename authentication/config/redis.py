import aioredis

# redis connection
# client = aioredis.from_url('redis://default@100.26.150.73:6379', decode_responses=True) #in production

client =  aioredis.from_url('redis://localhost', decode_responses=True) # in local testing
