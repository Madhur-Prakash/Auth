import random
import string
import logging
import os
from concurrent_log_handler import ConcurrentRotatingFileHandler

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
