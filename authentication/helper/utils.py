import random
import string
from fastapi import Request, status
from fastapi.responses import Response
import logging
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import requests
import uuid
from fastapi.exceptions import HTTPException
from helper.hashing import Hash 
import os
import pycountry, phonenumbers
from phonenumbers.phonenumberutil import region_code_for_number
from concurrent_log_handler import ConcurrentRotatingFileHandler
from dotenv import load_dotenv

load_dotenv()


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
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(pathname)s - %(filename)s - %(lineno)d" , datefmt="%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        #  add the handlers to the logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    return logger

logger = setup_logging()
generated_strings = set()
generated_session_id = set()

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

def get_country_name(phone_number: str):
    pn = phonenumbers.parse(phone_number)

    country = pycountry.countries.get(alpha_2 = region_code_for_number(pn))
    return country.name

def create_session_id():
    new_session_id = str(uuid.uuid4())
    if new_session_id not in generated_session_id:
        generated_session_id.add(new_session_id)
        return new_session_id
    else:
        return create_session_id()


def generate_fingerprint_hash(request: Request):
    user_agaent = request.headers.get('user-agent')
    print("user_agent coming from generate_fingerprint_hash function:",user_agaent) # debug
    digits = string.digits
    num = ''.join(random.choices(digits, k=7))
    print("random number:",num)
    raw_fingerprint = f"{num}:{user_agaent}"
    fingreprint_hash = Hash.bcrypt(raw_fingerprint)
    return str(fingreprint_hash)

def create_new_log(log_type: str, message: str, head: str):
    DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")

    if DEVELOPMENT_ENV == "local":
        url ="http://127.0.0.1:8000/backend/create_new_logs"
    else:
        url = "http://logging:8000/backend/create_new_logs"

    log = {
         "log_type": log_type,
         "message": message}
    headers = {
        "X-Source-Endpoint": head}
            
    resp = requests.post(url, json=log, headers=headers)
    return resp