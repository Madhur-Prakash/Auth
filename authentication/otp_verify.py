from twilio.rest import Client
import random
from .database import mongo_client
# Twilio Credentials (Get these from Twilio Console)
ACCOUNT_SID = 'AC9ebccb08930b46be576f7b6c3aff3041'
AUTH_TOKEN = '241333cb6cb2b9e0aaa80cdb252576f3'

TWILIO_PHONE_NUMBER = "+1 386 260 5314"  # Get this from Twilio Console

# Generate a 6-digit OTP
otp = random.randint(100000, 999999)

# Initialize Twilio Client
client = Client(ACCOUNT_SID, AUTH_TOKEN)

# Send OTP via SMS
def send_otp(phone_number: str):
    message = client.messages.create(
        body=f"Your OTP is {otp}. Do not share it with anyone.",
        from_=TWILIO_PHONE_NUMBER,  # Must be your Twilio number
        to=phone_number  # Must be a verified number in trial mode
    )

    print(f"OTP Sent Successfully! Message SID: {message.sid}")

    store_opt = mongo_client.auth.temp.insert_one({
        "otp":str(otp),
        "phone_number":phone_number})
    return store_opt

