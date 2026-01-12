import random
import string
from fastapi import Request
import logging
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import requests
import uuid
from helper.hashing import Hash 
from helper.encryption import EncryptionHelper
import os
import pycountry, phonenumbers
from phonenumbers.phonenumberutil import region_code_for_number
from concurrent_log_handler import ConcurrentRotatingFileHandler
from dotenv import load_dotenv

load_dotenv()
encryption_helper = EncryptionHelper(os.getenv("DATA_ENCRYPTION_KEY"))

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
    if not(phone_number.startswith("+")):
        phone_number = "+" + phone_number
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
    user_agent = request.headers.get('user-agent', 'unknown')
    # Removed debug prints for security
    digits = string.digits
    num = ''.join(random.choices(digits, k=7))
    raw_fingerprint = f"{num}:{user_agent}"
    fingerprint_hash = Hash.generate_hash(raw_fingerprint)
    return str(fingerprint_hash)

def create_new_log(log_type: str, message: str, head: str):
    try:
        DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")

        if DEVELOPMENT_ENV == "docker":
            url = "http://logging:8000/backend/create_new_logs"
        else:
            url ="http://127.0.0.1:8000/backend/create_new_logs"

        log = {
             "log_type": log_type,
             "message": message}
        headers = {
            "X-Source-Endpoint": head}
                
        resp = requests.post(url, json=log, headers=headers, timeout=5)
        return resp
    except Exception as e:
        # Fallback to local logging if external service fails
        logger.error(f"Failed to send log to external service: {str(e)}")
        return None
    

def encrypt_user_data(user_data: dict):
    """
    Encrypt sensitive user data before storing.
    
    Args:
        user_data: Dictionary containing user data
        
    Returns:
        dict: Dictionary with encrypted user data
    """
    encrypted_user_data = {}
    for key, value in user_data.items():
        if key == "password":
            # Skip encryption for password as it is already hashed
            encrypted_user_data[key] = value
        encrypted_user_data[key] = encryption_helper.encrypt(value) # encrypt other fields
    return encrypted_user_data

def decrypt_user_data(encrypted_data: dict):
    """
    Decrypt sensitive user data after retrieving.
    
    Args:
        encrypted_data: Dictionary containing encrypted user data
        
    Returns:
        dict: Dictionary with decrypted user data
    """
    decrypted_user_data = {}
    for key, value in encrypted_data.items():
        decrypted_user_data[key] = encryption_helper.decrypt(value)
    return decrypted_user_data