import asyncio
from twilio.rest import Client
import random
# from .celery_app import celery
from .redis import client as redis_client
import traceback
from .utils import setup_logging
from .database import mongo_client
# Twilio Credentials (Get these from Twilio Console)
ACCOUNT_SID = 'AC9ebccb08930b46be576f7b6c3aff3041'
AUTH_TOKEN = '241333cb6cb2b9e0aaa80cdb252576f3'

TWILIO_PHONE_NUMBER = "+1 386 260 5314"  # Get this from Twilio Console

logging = setup_logging()

# Generate a 6-digit OTP
async def generate_otp(email: str):
    otp = random.randint(100000, 999999)
    otp_str = str(otp)
    await redis_client.hset(f"{email}", mapping={
        "otp": otp_str,
        "email": email
    })
    await redis_client.expire(f"{email}", 300)  # Expire in 5 minutes
    return otp

# Initialize Twilio Client
client = Client(ACCOUNT_SID, AUTH_TOKEN)

# Send OTP via SMS
async def send_otp(phone_number: str):
    try:
        otp_sent =  await generate_otp(phone_number)
        message = client.messages.create(
            body=f"Your OTP is {otp_sent}. Do not share it with anyone.",
            from_=TWILIO_PHONE_NUMBER,  # Must be your Twilio number
            to=phone_number  # Must be a verified number in trial mode
        )

        print(f"OTP Sent Successfully! Message SID: {message.sid}")

        store_opt =  await redis_client.hset(f"{phone_number}", mapping={
            "otp": otp_sent,
            "phone_number": phone_number
        })
        await redis_client.expire(f"{phone_number}", 300)  # Expire in 5 minutes
        return otp_sent
    except Exception as e:
        logging.error(f"Error sending OTP: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        print(f"Error sending OTP: {str(e)}")

# Store OTP and phone number in MongoDB
async def store_otp_in_mongo(email: str, phone_number: str, otp: int):
    document = {
        "email": email,
        "phone_number": phone_number,
        "otp": otp
    }
    await mongo_client.your_database.your_collection.insert_one(document)

