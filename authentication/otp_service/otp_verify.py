import boto3
from twilio.rest import Client
from fastapi import status
from fastapi.exceptions import HTTPException
import random
import os
from ..helper.deterministic_hash import generate_deterministic_hash
from ..config.redis_config import client as redis_client
import traceback
from ..helper.utils import setup_logging
from ..config.database import mongo_client


# Twilio Credentials (Get these from Twilio Console)
ACCOUNT_SID = os.getenv("ACCOUNT_SID")
AUTH_TOKEN = os.getenv("AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

logging = setup_logging()


#  AWS credentials
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION_NAME = os.getenv("AWS_REGION_NAME", default="us-east-1")

# aws client
sns_client = boto3.client(
    'sns',
    region_name=AWS_REGION_NAME,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

# Generate a 6-digit OTP
async def generate_otp(email: str):
    otp = random.randint(100000, 999999)
    otp_str = str(otp)
    await redis_client.hset(f"otp:{email}", mapping={
        "otp": otp_str,
        "email": email
    })
    await redis_client.expire(f"otp:{email}", 600)  # Expire in 5 minutes
    return otp_str

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

        if message:
            print(f"OTP Sent Successfully! Message SID: {message.sid}")
            hashed_phone_number = generate_deterministic_hash(phone_number)
            await redis_client.hset(f"otp:{hashed_phone_number}", mapping={
                "otp": otp_sent,
                "phone_number": hashed_phone_number
            })
            await redis_client.expire(f"otp:{hashed_phone_number}", 600)  # Expire in 5 minutes
            return otp_sent
        print("Error sending OTP")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
    except Exception as e:
        logging.error(f"Error sending OTP: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        print(f"Error sending OTP: {str(e)}")


async def send_otp_sns_during_login(phone_number: str):
    try:
        otp_sent =  await generate_otp(phone_number)
        response = sns_client.publish(
            PhoneNumber = phone_number,
            Message = (f"Your OTP for login is {otp_sent}." 
                        " Enter this code to access your SecureGate account."  
                        " Do not share this OTP with anyone."
                        " The code will expire in 10 minutes."),
            MessageAttributes={
            'AWS.SNS.SMS.SenderID': {'DataType': 'String', 'StringValue': 'SecureGate'},
            'AWS.SNS.SMS.SMSType': {'DataType': 'String', 'StringValue': 'Transactional'}
        }
        )
        if response:
            print(f"OTP Sent Successfully! Message ID: {response['MessageId']}")
            store_opt =  await redis_client.hset(f"otp:{phone_number}", mapping={
                    "otp": otp_sent,
                    "phone_number": phone_number
            })
            await redis_client.expire(f"otp:{phone_number}", 600)  # Expire in 5 minutes
            return otp_sent
        print("Error sending OTP")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
    except Exception as e:
        logging.error(f"Error sending OTP: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        print(f"Error sending OTP: {str(e)}")

async def send_otp_sns_during_signup(phone_number: str):
    try:
        otp_sent =  await generate_otp(phone_number)
        response = sns_client.publish(
            PhoneNumber = phone_number,
            Message = (f"Your OTP for phone number verification is {otp_sent}." 
                        "Please use this code to complete your signup process."
                        "Do not share this OTP with anyone."
                        "This code is valid for 10 minutes only.")
        #     MessageAttributes={
        #     'AWS.SNS.SMS.SenderID': {'DataType': 'String', 'StringValue': 'SecureGate'},
        #     'AWS.SNS.SMS.SMSType': {'DataType': 'String', 'StringValue': 'Transactional'}
        # }
        )
        if response:
            print(f"OTP Sent Successfully! Message ID: {response['MessageId']}")
            store_opt =  await redis_client.hset(f"otp:{phone_number}", mapping={
                    "otp": otp_sent,
                    "phone_number": phone_number
            })
            await redis_client.expire(f"otp:{phone_number}", 600)  # Expire in 5 minutes
            return otp_sent
        print("Error sending OTP")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
    except Exception as e:
        logging.error(f"Error sending OTP: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        print(f"Error sending OTP: {str(e)}")


