import random
import string
from fastapi import HTTPException, status
import logging
from .database import mongo_client
from .hashing import Hash 
import os
import aioredis
from concurrent_log_handler import ConcurrentRotatingFileHandler

# redis connection
# client = aioredis.from_url('redis://default@13.217.2.25:6379', decode_responses=True) #in production

client =  aioredis.from_url('redis://localhost', decode_responses=True) # in local testing

def setup_logging():
    logger = logging.getLogger("auth_log") # create logger
    if not logger.hasHandlers(): # check if handlers already exist
        logger.setLevel(logging.INFO) # set log level

        # create log directory if it doesn't exist
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)

        # create a file handler
        file_handler = ConcurrentRotatingFileHandler(
            os.path.join(log_dir, "auth.log"), 
            maxBytes=10000, # 10KB 
            backupCount=500
        )
        file_handler.setLevel(logging.INFO) # The lock file .__auth.lock is created here by ConcurrentRotatingFileHandler

        #  create a console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # create a formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                                      datefmt="%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        #  add the handlers to the logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    return logger

logger = setup_logging()
generated_strings = set()

def generate_random_string():
    letters = string.ascii_uppercase  # Uppercase letters
    digits = string.digits  # Numbers 0-9

    first_part = ''.join(random.choices(letters, k=4))
    middle_part = ''.join(random.choices(digits, k=4))
    new_string = first_part + middle_part
    if new_string not in generated_strings:
        generated_strings.add(new_string)
        return new_string
    else:
        return generate_random_string()

# implemeting cahing using redis
async def cache(data: str, plain_password):
    user = await mongo_client.auth.patient.find_one({"$or": [{
        "email": data}, 
        {"phone_number": data}]})
    CachedData = await client.get(f'patient:{data}')
    if CachedData and user:
            hashed_password = await Hash.verify(user["password"], plain_password)
            if hashed_password:
                print("Data is cached") # debug
                print(CachedData) # debug
                return user
            logger.warning(f"login attempt with invalid credentials: {data} and {plain_password}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    elif user:
        hashed_password = await Hash.verify(user["password"], plain_password)
        if hashed_password:
            print("searching inside db") # debug
            await client.set(f"patient:{data}",data, ex=30) # expire in 30 seconds
            return user
    return None

async def cache_without_password(data: str):
    user = await mongo_client.auth.patient.find_one({"$or": [{
        "email": data}, 
        {"phone_number": data}]})
    CachedData = await client.get(f'patient:{data}')
    if CachedData:
        if user:
            print("Data is cached") # debug
            print(CachedData) # debug
            return user
        logger.warning(f"login attempt with invalid credentials: {data}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    elif user:
            print("searching inside db") # debug
            await client.set(f"patient:{data}",data, ex=30) # expire in 30 seconds
            return user
    return None