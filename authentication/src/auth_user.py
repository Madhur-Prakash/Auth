from fastapi import APIRouter, Request, status, HTTPException, Depends, BackgroundTasks
import traceback
from kafka import KafkaProducer
import json
from ..models import models
from ..otp_service.otp_verify import send_otp, generate_otp, send_otp_sns_during_login, send_otp_sns_during_signup
from ..config.database import mongo_client
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from ..config.redis_config import client
import os
from dotenv import load_dotenv
from ..config.rate_limiting import limiter
from ..helper.oauth2 import create_verification_token, decode_verification_token
from ..helper.hashing import Hash
from ..helper.utils import create_session_id, create_new_log, generate_fingerprint_hash, get_country_name, generate_random_string, setup_logging, encrypt_user_data
from ..helper.deterministic_hash import generate_deterministic_hash
from datetime import datetime
from ..otp_service.send_mail import send_email_ses, send_email,send_mail_to_mailhog
from ..helper import oauth2, auth_token
from config.bloom_filter import CountingBloomFilter
from ..config.security import validate_password, validate_email, sanitize_input, validate_phone_number, get_secure_cookie_settings

auth_user = APIRouter(tags=["user Authentication"]) # create a router for user
templates = Jinja2Templates(directory="authentication/templates")

logger = setup_logging() # initialize logger
load_dotenv()  # Load environment variables from .env file

# Kafka Producer
DEVELOPMENT_ENV = os.getenv("DEVELOPMENT_ENV", "local")
# Redis Keys
REDIS_USER_TWO_FACTOR_KEY = os.getenv("REDIS_USER_TWO_FACTOR_KEY")
REDIS_USER_NEW_ACCOUNT = os.getenv("REDIS_USER_NEW_ACCOUNT")
REDIS_USER_AUTH = os.getenv("REDIS_USER_AUTH")

if DEVELOPMENT_ENV == "docker":
    producer = KafkaProducer(
        bootstrap_servers=['kafka:29092'], # when using docker, it internally connects to 29092 and externally to 9092, so we need to connect to 29092
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )
else:
    producer = KafkaProducer(
        bootstrap_servers=['localhost:9092'],
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )

# implemeting cahing using redis
async def cache_with_password(hashed_data: str, plain_password):
    """
    Asynchronously verifies user credentials by checking multiple sources in order of speed and recency.
    The function attempts to authenticate a user by:
    1. Checking a Redis cache for existing user authentication data.
    2. Checking a Redis cache for newly created accounts.
    3. Querying a MongoDB database if the user is not found in the cache.
    If the credentials are verified at any stage, relevant logs are created and the function returns the user identifier or user object.
    Args:
        data (str): The user identifier, which can be an email or phone number.
        plain_password: The plain text password to verify.
    Returns:
        str or dict or None: Returns the user identifier (str) if found in cache, the user object (dict) if found in the database, or None if authentication fails.
    """

    CachedData = await client.hgetall(f'{REDIS_USER_AUTH}:{hashed_data}')
    new_account = await client.hgetall(f'{REDIS_USER_NEW_ACCOUNT}:{hashed_data}')
    if CachedData:
        hashed_password = await Hash.verify(CachedData["password"], plain_password)
        if hashed_password:
            logger.debug("Data is cached")
            # Removed sensitive data logging
            create_new_log("info", f"cache hit and credential verified for {hashed_data}", "/api/backend/Auth")
            logger.info(f"cache hit and credential verified for {hashed_data}") # log the cache hit
            return hashed_data
        
    elif new_account:
        hashed_password = await Hash.verify(new_account["password"], plain_password)
        if hashed_password:
            logger.debug("Data is cached in new_account")
            # Removed sensitive data logging
            create_new_log("info", f"cache hit and credential verified for {hashed_data}", "/api/backend/Auth")
            logger.info(f"cache hit and credential verified for {hashed_data}") # log the cache hit
            return hashed_data
            
    # user was not cached, searching in db
    user = await mongo_client.auth.user.find_one({"$or": [{
        "hashed_email": hashed_data}, 
        {"hashed_phone_number": hashed_data}]})
    if user:
        hashed_password = await Hash.verify(user["password"], plain_password)
        if hashed_password:
            logger.debug("searching inside db")
            await client.hset(f"{REDIS_USER_AUTH}:{hashed_data}",mapping={
                "data":hashed_data,
                "password":user['password']
            }) 
            await client.expire(f"{REDIS_USER_AUTH}:{hashed_data}", 432000) # expire in 5 days
            create_new_log("info", f"searched inside db and credential verified for:{hashed_data}", "/api/backend/Auth")
            logger.info(f"searched inside db and credential verified for:{hashed_data}") # log the cache hit
            return user
    return None

async def cache_without_password(hashed_data: str):
    """
    Retrieve user authentication data from cache or database without password.
    This asynchronous function attempts to fetch user authentication data (excluding the password)
    from a cache using the provided identifier (email or phone number). If the data is not found
    in the cache, it queries the MongoDB database. On a successful database hit, it caches the
    identifier for future requests. The function also logs cache hits and invalid login attempts.
    Args:
        data (str): The user's email or phone number used as an identifier.
    Returns:
        dict or str or None: Returns cached data (if found), user document from the database (if found),
        or None if no matching user is found.
    """

    CachedData = await client.get(f'{REDIS_USER_TWO_FACTOR_KEY}:{hashed_data}')
    if CachedData:
        logger.debug("Data is cached")
        # Removed sensitive data logging
        create_new_log("info", f"cache hit for {hashed_data}", "/api/backend/Auth")
        logger.info(f"cache hit for {hashed_data}") # log the cache hit
        return CachedData
  
    user = await mongo_client.auth.user.find_one({"$or": [{
        "hashed_email": hashed_data}, 
        {"hashed_phone_number": hashed_data}]})
    if user:
        logger.debug("searching inside db")
        await client.set(f"{REDIS_USER_TWO_FACTOR_KEY}:{hashed_data}",hashed_data, ex=432000) # expire in 5 days
        return user
    create_new_log("warning", f"login attempt with invalid credentials: {hashed_data}", "/api/backend/Auth")
    logger.warning(f"login attempt with invalid credentials: {hashed_data}") # log the cache hit
    return None
    
TOPIC_NAME = 'user_signups'

# Initialize bloom filters
user_email_bloom_filter = CountingBloomFilter(capacity=100000, error_rate=0.01)
user_phone_bloom_filter = CountingBloomFilter(capacity=100000, error_rate=0.01)


@auth_user.post("/user/signup", status_code=status.HTTP_201_CREATED)
async def signup(data: models.user, response: Response, request: Request):
    """Handles user signup by validating input data, checking for duplicate email and phone number using Bloom filters, Redis, and MongoDB, and performing various data processing steps. 
Steps performed:
- Validates required fields and data formats (email, phone number, password, names).
- Checks for existing email and phone number in Bloom filters, Redis cache, and MongoDB.
- Hashes the user's password.
- Generates and sets refresh and access tokens as cookies.
- Stores user data temporarily in Redis for instant login and further processing.
- Sends user data to Kafka topics for asynchronous processing and profile creation.
- Sends a welcome email to the user.
- Logs all significant events and errors.
Args:
    data (models.user): The user signup data model containing user details.
    response (Response): The FastAPI response object for setting cookies.
    request (Request): The FastAPI request object for extracting device fingerprint.
Returns:
    dict: A dictionary containing a success message, status code, token type, UID, creation timestamp, access token, and refresh token.
Raises:
    HTTPException: For various validation errors, duplicate entries, or internal server errors."""
    try:
        form_data = dict(data)
        dict_data = dict(form_data)
        dict_data["full_name"] = dict_data["first_name"] + ' ' + dict_data["last_name"]
        dict_data["created_at"] = datetime.now().isoformat()
        dict_data["UID"] = generate_random_string()
        dict_data["verification_status"] = "false"

        updated_phone_number = dict_data['country_code'] + dict_data['phone_number'] # adding country code to get country name
        country_name = get_country_name(updated_phone_number)
        country_name = country_name.lower()
        dict_data["country_name"] = country_name

        required_fields = ["first_name", "last_name", "email", "password", "phone_number", "country_code"]
        for field in required_fields:
            if field not in dict_data:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="All fields are required")
        
        # Sanitize user inputs to prevent XSS attacks
        form_data["first_name"] = sanitize_input(form_data["first_name"])
        form_data["last_name"] = sanitize_input(form_data["last_name"])
        form_data["email"] = sanitize_input(form_data["email"])
        form_data["phone_number"] = sanitize_input(form_data["phone_number"])
        form_data["country_code"] = sanitize_input(form_data["country_code"])
        form_data["password"] = sanitize_input(form_data["password"])
        
        # Validate email format
        validate_email(dict_data["email"])
        # Validate phone number format
        validate_phone_number(dict_data["phone_number"])
        # Validate password strength
        validate_password(dict_data["password"])
                
        # hash both email and phone number for bloom filter and redis/db checks
        hashed_email = generate_deterministic_hash(dict_data["email"]) # hashing email for bloom filter and redis/db checks
        hashed_phone_number = generate_deterministic_hash(dict_data["phone_number"])

        # data validation
        if not user_email_bloom_filter.contains(dict_data["email"]): # Check if email is definitely not present (Bloom filter)
            print("Email not in Bloom filter — safe to continue")
            logger.info("Email not in Bloom filter — safe to continue")
            # continue with signup
        else:
            print("Bloom filter indicates possible existence — verifying with Redis and DB")
            logger.warning("Bloom filter indicates possible existence — verifying with Redis and DB")

            # Double-check in Redis (temporary store, e.g., for recent signups or pending activation)
            email_in_redis = await client.hgetall(f"{REDIS_USER_NEW_ACCOUNT}:{hashed_email}")
            if email_in_redis:
                print("Email found in Redis")
                logger.warning("Email found in Redis")
                create_new_log("warning", f"Signup attempt with existing email: {dict_data['email']}", "/api/backend/Auth")
                logger.warning(f"Signup attempt with existing email: {dict_data['email']}")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
            else:
                print("Email not found in Redis — checking MongoDB")
                logger.info("Email not found in Redis — checking MongoDB")
                # Check in MongoDB (source of truth)
                email = await mongo_client.auth.user.find_one({"hashed_email": hashed_email})
                if email:
                    print("Email found in MongoDB")
                    logger.warning("Email found in MongoDB")
                    create_new_log("warning", f"Signup attempt with existing email: {hashed_email}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing email: {hashed_email}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
        
        print("Email is new — proceed with account creation") # At this point, email is confirmed to be new — proceed with signup
        logger.info("Email is new — proceed with account creation")

        # Phone number validation (Bloom Filter → Redis → MongoDB)
        if not user_phone_bloom_filter.contains(dict_data["phone_number"]):  # Bloom filter first check
            print("Phone number not in Bloom filter — safe to continue")
            logger.info("Phone number not in Bloom filter — safe to continue")
            # continue with signup
        else:
            print("Bloom filter indicates possible existence — verifying with Redis and DB")
            logger.warning("Bloom filter indicates possible existence — verifying with Redis and DB")

            # Check Redis for recent or pending signups
            phone_number_in_redis = await client.hgetall(f"{REDIS_USER_NEW_ACCOUNT}:{hashed_phone_number}")
            if phone_number_in_redis:
                print("Phone number found in Redis")
                logger.warning("Phone number found in Redis")
                create_new_log("warning", f"Signup attempt with existing phone number: {hashed_phone_number}", "/api/backend/Auth")
                logger.warning(f"Signup attempt with existing phone number: {hashed_phone_number}")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already in use")
            else:
                print("Phone number not found in Redis — checking MongoDB")
                logger.warning("Phone number not found in Redis — checking MongoDB")

                # Check in MongoDB (source of truth)
                phone_number = await mongo_client.auth.user.find_one({"hashed_phone_number": hashed_phone_number})
                if phone_number:
                    print("Phone number found in MongoDB")
                    logger.warning("Phone number found in MongoDB")
                    create_new_log("warning", f"Signup attempt with existing phone number: {dict_data['phone_number']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing phone number: {dict_data['phone_number']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already in use")

        print("Phone number is new — proceed with account creation")  # Safe to proceed
        logger.info("Phone number is new — proceed with account creation")
        
        if len(form_data["first_name"]) < 2 or not form_data["first_name"].replace(' ', '').isalpha():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="First name must be at least 2 characters and contain only letters")
        if len(form_data["last_name"]) < 2 or not form_data["last_name"].replace(' ', '').isalpha():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Last name must be at least 2 characters and contain only letters")
        if(form_data["email"].__len__() < 4):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email must be greater than 3 characters") 

        # Encrypting user data before storing
        encrypted_user_data = encrypt_user_data(dict_data)

        # hashing the password
        hashed_password = Hash.generate_hash(dict_data["password"])
        hashed_phone_number = generate_deterministic_hash(dict_data["phone_number"]) # hashing phone number
        hashed_email = generate_deterministic_hash(dict_data["email"]) # hashing email
        encrypted_user_data['hashed_phone_number'] = hashed_phone_number # storing hashed phone number in encrypted data
        encrypted_user_data['hashed_email'] = hashed_email # storing hashed email in encrypted data
        encrypted_user_data["password"] = hashed_password # replacing plain password with hashed password
        user_email_bloom_filter.add(dict_data["email"])
        user_phone_bloom_filter.add(dict_data["phone_number"])
        device_fingerprint = generate_fingerprint_hash(request)
        session_id = create_session_id()
        refresh_token = auth_token.create_refresh_token(data={
                                                                "sub": session_id,
                                                                "data": device_fingerprint})
        response.delete_cookie("refresh_token")  # Remove old token
        cookie_settings = get_secure_cookie_settings()
        response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, **cookie_settings) # refresh token expires in 7 days
        hashed_refresh_token = Hash.generate_hash(refresh_token)
        hashed_session_id = Hash.generate_hash(session_id)
        hashed_device_fingerprint = Hash.generate_hash(device_fingerprint)
        # Removed debug print for security

        await client.hset(f"user:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": hashed_refresh_token,
                                                            "device_fingerprint":hashed_device_fingerprint,
                                                            "data":hashed_email,
                                                            "session_id":hashed_session_id})
        await client.expire(f"user:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        # Generate a cache during signup with email as key
        cache_key = hashed_email # using hashed email as cache key
        await client.hset(f"{REDIS_USER_NEW_ACCOUNT}:{cache_key}",mapping=encrypted_user_data) # store the entire data in redis
        await client.expire(f"{REDIS_USER_NEW_ACCOUNT}:{cache_key}", 691200) # expire in 7 days
        await client.hset(f"{REDIS_USER_NEW_ACCOUNT}:{hashed_phone_number}", mapping=encrypted_user_data)
        await client.expire(f"{REDIS_USER_NEW_ACCOUNT}:{hashed_phone_number}", 691200)  # expire in 7 days

        #  for instant loggin in, after signup
        await client.set(f"{REDIS_USER_TWO_FACTOR_KEY}:{cache_key}", cache_key, ex=3600) # expire in 1 hour
        await client.set(f"{REDIS_USER_TWO_FACTOR_KEY}:{hashed_phone_number}", hashed_phone_number, ex=3600) # expire in 1 hour
        # ************* this was done previously **************
        # await client.hset(f"{REDIS_USER_NEW_ACCOUNT}:{cache_key}", mapping=dict_data)
        # await client.expire(f"{REDIS_USER_NEW_ACCOUNT}:{cache_key}", 691200)  # expire in 7 days 

        # ****************send data to kafka topic *****************
        producer.send(TOPIC_NAME, encrypted_user_data) # send data to kafka topic
        producer.flush() # flush the producer to ensure data is sent


        # await mongo_client.auth.user.insert_one(dict_data) # this will be done when kafka consumer will consume the data from topic and insert into mongodb


        create_new_log("info", f"Account for user created successfully: {hashed_email}", "/api/backend/Auth")
        logger.info(f"Account for user created successfully: {hashed_email}") # log the cache hit
        
        access_token = auth_token.create_access_token(data={"sub": hashed_email})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600, **cookie_settings)

        # html_path = "/root/SecureGate/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()

        # send email verification link
        email_sent = send_mail_to_mailhog(dict_data["email"], "Welcome to SecureGate. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

        return {"message":f"Account for user created successfully: {dict_data['email']}", "status_code":status.HTTP_201_CREATED, "UID": dict_data["UID"], "created_at": dict_data["created_at"]}


    except Exception as e:
        print(f"Error creating new user: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error creating new user: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error creating new user: {formatted_error}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
# ***********************************************************************************************************************************************


@auth_user.post("/user/signup/send_otp", status_code=status.HTTP_200_OK) # verify otp
async def send_otp_signup(data: models.verify_otp_signup):
    """Asynchronously verifies OTP (One-Time Password) for user signup via email or phone number.
    Depending on the provided data, this function either:
    - Generates an OTP for the given email, sends a verification email with the OTP, and returns an encrypted OTP.
    - Sends an OTP to the provided phone number (with country code), and returns an encrypted OTP.
    Args:
        data (models.verify_otp_signup): The signup data containing either 'email' or 'phone_number' (and 'country_code' if phone number is used).
    Returns:
        dict: A dictionary containing a success message, HTTP status code, and the encrypted OTP.
    Raises:
        HTTPException: If sending the OTP (via email or SMS) fails, or if any other error occurs during the process.
    Side Effects:
        - Sends an email or SMS with the OTP.
        - Logs success or error messages."""

    try:
        form_data = dict(data)
        email = form_data.get("email")
        phone_number = form_data.get("phone_number")
        country_code = form_data.get("country_code")
        if email:
            hashed_email = generate_deterministic_hash(email)
            otp =  await generate_otp(hashed_email)
            otp = str(otp)
        
            html_body = f"""
                            <html>
                            <body style="font-family: Arial, sans-serif; background-color: #f5f7fa; padding: 20px;">

                                    <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: auto; background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px;">
                                        <tr>
                                            <td style="padding: 20px; text-align: center;">
                                                <h2 style="color: #2c3e50; margin-bottom: 10px;">Verify Your Email</h2>
                                                <p style="color: #7f8c8d; font-size: 14px;">Hi there,</p>
                                                <p style="color: #7f8c8d; font-size: 14px; margin-bottom: 20px;">
                                                    Thank you for signing up with <strong>SecureGate</strong>! To complete your registration, please verify your email address by using the OTP below.
                                                </p>
                                                <div style="background-color: #ecf0f1; padding: 15px; border-radius: 4px; display: inline-block;">
                                                    <span style="font-size: 24px; font-weight: bold; color: #2c3e50;">{otp}</span>
                                                </div>
                                                <p style="color: #7f8c8d; font-size: 12px; margin-top: 20px;">This OTP is valid for 10 minutes. Please do not share this code with anyone.</p>
                                                <p style="color: #bdc3c7; font-size: 12px; margin-top: 40px;">&copy; 2025 SecureGate. All rights reserved.</p>
                                            </td>
                                        </tr>
                                    </table>

                                </body>
                            </html>
                            """
            # send email verification link
            email_sent = (send_mail_to_mailhog(email, "Welcome to SecureGate. Lets build your health Profile", html_body, retries=3, delay=5))
            if not email_sent:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

            print("otp sent successfuly")
            create_new_log("info", f"otp sent successfuly on {hashed_email}", "/api/backend/Auth")
            logger.info(f"otp sent successfuly on {hashed_email}") # log the cache hit
            return ({"message":f"otp sent successfuly on {hashed_email}", "status_code": status.HTTP_200_OK})
        elif phone_number:
            phone_number = country_code + phone_number # adding country code
            hashed_phone_number = generate_deterministic_hash(phone_number)
            res = await send_otp(phone_number)
            if not res:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")

            print("otp sent successfuly")
            create_new_log("info", f"otp sent successfuly on {hashed_phone_number}", "/api/backend/Auth")
            logger.info(f"otp sent successfuly on {hashed_phone_number}") # log the cache hit
            return ({"message":f"otp sent successfuly on {hashed_phone_number}", "status_code": status.HTTP_200_OK})
        
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error verifying OTP: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error verifying OTP: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        formatted_error = traceback.format_exc()
        print(f"Formatted Error: {formatted_error}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    


@auth_user.post("/user/signup/email_verify_otp", status_code=status.HTTP_200_OK) # verify otp during signup
async def verify_otp_signup_email(data: models.otp_email):
    """
    Endpoint to verify OTP (One-Time Password) during user signup via email.
    Accepts a POST request with email and OTP.
    Args:
        data (models.otp_email): The OTP data containing 'email' and 'otp'.
    Returns:
        dict: A message indicating OTP was verified successfully, or raises an HTTPException on error.
    Raises:
        HTTPException: If the OTP is invalid or any other error occurs during verification.
    """

    try:
        form_data = dict(data)
        email = form_data.get("email")
        otp_entered = form_data.get("otp")
        
        # Removed sensitive OTP logging
        if not otp_entered or len(otp_entered) != 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
        hashed_email = generate_deterministic_hash(email)
        otp_stored = await client.hgetall(f"otp:{hashed_email}")
        # Removed sensitive OTP logging
        if not otp_stored or (otp_stored.get('otp') != otp_entered):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        
        create_new_log("info", f"OTP verified successfully from {hashed_email}", "/api/backend/Auth")
        logger.info(f"OTP verified successfully from {hashed_email}")
        return {"message":f"OTP verified successfully from {hashed_email}", "status_code":status.HTTP_200_OK}
                         
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error verifying OTP: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error verifying OTP: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@auth_user.post("/user/signup/phone_verify_otp", status_code=status.HTTP_200_OK) # verify otp during signup
async def verify_otp_signup_phone(data: models.otp_phone):
    """
    Endpoint to verify OTP (One-Time Password) during user signup via phone number.
    Accepts a POST request with phone number, country code, and OTP.
    ARGS:
        data (models.otp_phone): The OTP data containing 'phone_number', 'country_code', and 'otp'.
    Returns:
        dict: A message indicating OTP was verified successfully, or raises an HTTPException on error.
    Raises:
        HTTPException: If the OTP is invalid or any other error occurs during verification.
    """
    try:
        form_data = dict(data)
        phone_number = form_data.get("phone_number")
        country_code = form_data.get("country_code")

        phone_number = country_code + phone_number # adding country code
        otp_entered = form_data.get("otp")
        print(otp_entered)
        if not otp_entered or len(otp_entered) != 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
        hashed_phone_number = generate_deterministic_hash(phone_number)
        otp_stored = await client.hgetall(f"otp:{hashed_phone_number}")
        if not otp_stored or (otp_stored.get('otp') != otp_entered):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        
        create_new_log("info", f"OTP verified successfully from {hashed_phone_number}", "/api/backend/Auth")
        logger.info(f"OTP verified successfully from {hashed_phone_number}") # log the cache hit
        return {"message":f"OTP verified successfully from {hashed_phone_number}", "status_code":status.HTTP_200_OK}

    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error verifying OTP: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error verifying OTP: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# async def login(response: Response, request: Request, form_data: OAuth2UserRequestForm = Depends(), auth_token: OAuth2PasswordBearer = Depends(oauth2.oauth2_scheme)): -> for locking the route use this instead of below
# ***************** login through email/phone_number and otp ****************************************************
@auth_user.post("/user/login/send_otp", status_code=status.HTTP_200_OK) # login using email 
async def send_otp_login(data: models.login_otp):
    """Endpoint to log in a user using OTP (One-Time Password) via email or phone number.
Accepts a POST request with either an email or a phone number (and country code for phone).
- If an email is provided and found in the cache, generates an OTP, sends it via email, and returns a success message.
- If a phone number is provided and found in the cache, generates an OTP, sends it via SMS, and returns a success message.
- If neither is provided, or credentials are invalid, returns an appropriate error.
Args:
    data (models.login_otp): The login data containing either 'email' or 'phone_number' (with 'country_code').
Returns:
    dict: A message indicating OTP was sent successfully, or raises an HTTPException on error.
Raises:
    HTTPException: 
        - 400 if neither email nor phone number is provided.
        - 401 if credentials are invalid.
        - 500 if there is an error sending OTP or any other internal error."""
    try:
        form_data = dict(data)

        email_provided = form_data.get("email", None)
        phone_number_provided = form_data.get("phone_number", None)
        country_code = form_data.get("country_code", None)

        # check if email or phone number is provided
        if not email_provided and not phone_number_provided:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or phone number is required")
        
        else:
            # login using email and password
            if email_provided:
                # Generate a cache key based on login identifier
                hashed_email = generate_deterministic_hash(email_provided)
                cached_data = await cache_without_password(hashed_email)
                if cached_data:
                    otp = await generate_otp(hashed_email)

                    html_body = f"""
                                    <html>
                                        <body style="font-family: Arial, sans-serif; background-color: #f5f7fa; padding: 20px;">

                                            <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: auto; background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px;">
                                                <tr>
                                                    <td style="padding: 20px; text-align: center;">
                                                        <h2 style="color: #2c3e50; margin-bottom: 10px;">Login to SecureGate</h2>
                                                        <p style="color: #7f8c8d; font-size: 14px;">Hello,</p>
                                                        <p style="color: #7f8c8d; font-size: 14px; margin-bottom: 20px;">
                                                            You requested an OTP to log in to your <strong>SecureGate</strong> account. Please use the code below to proceed.
                                                        </p>
                                                        <div style="background-color: #ecf0f1; padding: 15px; border-radius: 4px; display: inline-block;">
                                                            <span style="font-size: 24px; font-weight: bold; color: #2c3e50;">{otp}</span>
                                                        </div>
                                                        <p style="color: #7f8c8d; font-size: 12px; margin-top: 20px;">This OTP will expire in 10 minutes. For your safety, do not share this code with anyone.</p>
                                                        <p style="color: #bdc3c7; font-size: 12px; margin-top: 40px;">&copy; 2025 SecureGate. All rights reserved.</p>
                                                    </td>
                                                </tr>
                                            </table>

                                        </body>
                                    </html>
                                    """
                    # send otp via email
                    email_sent = (send_email(form_data["email"], "Login to SecureGate using the provided otp", html_body, retries=3, delay=5))
                    if not email_sent:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")
                    create_new_log("info", f"otp sent successfuly on {hashed_email}", "/api/backend/Auth")
                    logger.info(f"otp sent successfuly on {hashed_email}") # log the cache hit
                    return {"message": f"OTP sent successfully on {hashed_email}", "status_code":status.HTTP_200_OK}

                    
                print("cache data returned none") # debug
                create_new_log("warning", f"login attempt with invalid credentials: {form_data['email']}", "/api/backend/Auth")
                logger.warning(f"login attempt with invalid credentials: {form_data['email']}") # log the cache hit
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

            # login using phone_number and password
            elif phone_number_provided:
                # Generate a cache key based on login identifier
                hashed_phone_number = generate_deterministic_hash(phone_number_provided)
                cached_data = await cache_without_password(hashed_phone_number)
                if cached_data:
                    print("cache data returned", cached_data) # debug
                    phone_number_provided = country_code + phone_number_provided # adding country code
                    res = await send_otp(phone_number_provided) #  sending otp
                    if not res:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
                    create_new_log("info", f"otp sent successfuly on {hashed_phone_number}", "/api/backend/Auth")
                    logger.info(f"otp sent successfuly on {hashed_phone_number}") # log the cache hit
                    return {"message": f"OTP sent successfully on {phone_number_provided[:5]+'x'*6+phone_number_provided[13:]}", "status_code":status.HTTP_200_OK} # masking the phone number for security

                print("cache data returned none") # debug
                create_new_log("warning", f"login attempt with invalid credentials: {form_data['phone_number']}", "/api/backend/Auth")
                logger.warning(f"login attempt with invalid credentials: {form_data['phone_number']}") # log the cache hit
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
                
    except Exception as e:
        print(f"login attempt failed: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"login attempt failed: {formatted_error}", "/api/backend/Auth")
        logger.error(f"login attempt failed: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
# ***************************************************************************************************************************************************************

@auth_user.post("/user/login/email_verify_otp", status_code=status.HTTP_200_OK) 
async def verify_otp__login_email(data: models.otp_email, response: Response, request: Request):
    """
    Asynchronously verifies a one-time password (OTP) for user authentication.
    Args:
        data (models.otp_email): The OTP and email data submitted by the user.
        response (Response): The HTTP response object for setting cookies.
        request (Request): The HTTP request object for accessing cookies, headers, and query parameters.
    Raises:
        HTTPException: 
            - 400 if the OTP is missing or invalid in format.
            - 401 if the OTP does not match the stored value.
            - 500 for any other internal errors.
    Returns:
        dict: A dictionary containing a success message, HTTP status code, token type, email, access token, and refresh token.
    Side Effects:
        - Sets and deletes access and refresh tokens as HTTP-only cookies.
        - Stores encrypted refresh token and device fingerprint in Redis.
        - Logs authentication events and errors.
    """
    
    try:
        form_data = dict(data)
        email = form_data.get("email")
        otp_entered = form_data.get("otp")
        incoming_refresh_token = request.cookies.get("refresh_token") or request.headers.get("refresh_token") or request.query_params.get("refresh_token") 
        # Removed sensitive OTP logging
        if not otp_entered or len(otp_entered) != 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
        hashed_email = generate_deterministic_hash(email)
        otp_stored = await client.hgetall(f"otp:{hashed_email}")
        # Removed sensitive OTP logging
        if not otp_stored or (otp_stored.get('otp') != otp_entered):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        
        device_fingerprint = generate_fingerprint_hash(request)
        hashed_device_fingerprint = Hash.generate_hash(device_fingerprint) # encrypting device fingerprint
        session_id = create_session_id()
        hashed_session_id = Hash.generate_hash(session_id) # encrypting session id
        # access_token
        access_token = auth_token.create_access_token(data={"sub": hashed_email})
        # Removed access token logging for security
        response.delete_cookie("access_token")  # Remove old token
        cookie_settings = get_secure_cookie_settings()
        response.set_cookie(key="access_token", value=access_token, max_age=3600, **cookie_settings)

        # refresh token
        refresh_token = auth_token.create_refresh_token(data={
                                                                "sub": session_id,
                                                                "data": device_fingerprint})
        response.delete_cookie("refresh_token")  # Remove old token
        response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
        hashed_refresh_token = Hash.generate_hash(refresh_token)
        if incoming_refresh_token:
            await client.delete(f"user:refresh_token:{incoming_refresh_token[:106]}")
        await client.hset(f"user:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": hashed_refresh_token,
                                                            "device_fingerprint":hashed_device_fingerprint,
                                                            "data":hashed_email,
                                                            "session_id":hashed_session_id})
        await client.expire(f"user:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        print(f"{email} logged in succesfully")  # Return success message
        create_new_log("info", f"{email} logged in successfully", "/api/backend/Auth")
        logger.info(f"{email} logged in successfully") # log the cache hit
        return {"message":f"OTP verified successfully from {email}", "status_code":status.HTTP_200_OK, "email": hashed_email}
                         
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error verifying OTP: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error verifying OTP: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@auth_user.post("/user/login/phone_verify_otp", status_code=status.HTTP_200_OK)
async def verify_otp__login_phone(data: models.otp_phone, response: Response, request: Request):
    """
    Verifies the OTP (One-Time Password) for a user's phone number and manages authentication tokens.
    Args:
        data (models.otp_phone): The OTP and phone number data submitted by the user.
        response (Response): The HTTP response object for setting cookies.
        request (Request): The HTTP request object for accessing cookies, headers, and query parameters.
    Raises:
        HTTPException: 
            - 400 if the OTP is missing or invalid.
            - 401 if the OTP does not match the stored value.
            - 500 for any other internal errors.
    Returns:
        dict: A dictionary containing a success message, status code, token type, phone number, access token, and refresh token.
    Side Effects:
        - Sets and deletes authentication cookies (access_token, refresh_token).
        - Stores and deletes refresh tokens in Redis.
        - Logs authentication events and errors.
    """

    try:
        form_data = dict(data)
        phone_number = form_data.get("phone_number")
        country_code = form_data.get("country_code")
        incoming_refresh_token = request.cookies.get("refresh_token") or request.headers.get("refresh_token") or request.query_params.get("refresh_token") 

        phone_number = country_code + phone_number # adding country code
        otp_entered = form_data.get("otp")
        if not otp_entered or len(otp_entered) != 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
        hashed_phone_number = generate_deterministic_hash(phone_number)
        otp_stored = await client.hgetall(f"otp:{hashed_phone_number}")
        if not otp_stored or (otp_stored.get('otp') != otp_entered):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        
        device_fingerprint = generate_fingerprint_hash(request)
        hashed_device_fingerprint = Hash.generate_hash(device_fingerprint) # encrypting device fingerprint
        session_id = create_session_id()
        hashed_session_id = Hash.generate_hash(session_id) # encrypting session id

        # access_token
        access_token = auth_token.create_access_token(data={"sub": hashed_phone_number})
        # Removed access token logging for security
        response.delete_cookie("access_token")  # Remove old token
        cookie_settings = get_secure_cookie_settings()
        response.set_cookie(key="access_token", value=access_token, max_age=3600, **cookie_settings)

        # refresh token
        refresh_token = auth_token.create_refresh_token(data={
                                                                "sub": session_id,
                                                                "data": device_fingerprint})
        response.delete_cookie("refresh_token")  # Remove old token
        response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
        hashed_refresh_token = Hash.generate_hash(refresh_token)
        if incoming_refresh_token:
            await client.delete(f"user:refresh_token:{incoming_refresh_token[:106]}") # delete old refresh token from redis -> email
        await client.hset(f"user:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": hashed_refresh_token,
                                                            "device_fingerprint":hashed_device_fingerprint,
                                                            "data":hashed_phone_number,
                                                            "session_id":hashed_session_id})
        await client.expire(f"user:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        print(f"{phone_number} logged in succesfully")  # Return success message
        create_new_log("info", f"{phone_number} logged in successfully", "/api/backend/Auth")
        logger.info(f"{phone_number} logged in successfully") # log the cache hit
        return {"message":f"OTP verified successfully from {phone_number}", "status_code":status.HTTP_200_OK, "phone_number": hashed_phone_number}

    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error verifying OTP: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error verifying OTP: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))



# ********************************************************************* login with email/phone_number and password ************************************
# @limiter.limit("5/minute")  #******************************* Rate limit *********************************************************************
@auth_user.post("/user/login", status_code=status.HTTP_200_OK) # login using email and password
async def login(data: models.login, response: Response, request: Request):
    """
    Handles user login via email or phone number and password.
    This asynchronous function authenticates a user based on provided credentials (email or phone number and password). 
    On successful authentication, it generates and sets access and refresh tokens as cookies, manages device fingerprinting, 
    handles session management, and logs login attempts. It also interacts with a cache and Redis for token/session storage.
    Args:
        data (models.login): The login data containing email or phone number and password.
        response (Response): The HTTP response object for setting cookies.
        request (Request): The HTTP request object for extracting cookies, headers, and generating device fingerprint.
    Returns:
        dict: A dictionary containing a success message, status code, token type, user identifier (email or phone number), 
              access token, and refresh token.
    Raises:
        HTTPException: 
            - 400 if required fields (password, email/phone number) are missing.
            - 401 if credentials are invalid.
            - 500 for any unexpected errors during the login process.
    """

    try:
        form_data = dict(data)

        email_provided = form_data.get("email", None)
        password_provided = form_data.get("password", None)
        phone_number_provided = form_data.get("phone_number", None)
        incoming_refresh_token = request.cookies.get("refresh_token") or request.headers.get("refresh_token") or request.query_params.get("refresh_token") 

        # check if email or user_user_name or password is provided
        if not password_provided:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is required")
        
        if not email_provided and not phone_number_provided:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or phone number is required")
        
        else:
            # login using email and password
            if email_provided:
                # Generate a cache key based on login identifier
                hashed_email = generate_deterministic_hash(email_provided)
                cached_data = await cache_with_password(hashed_email, password_provided)
                if cached_data:
                    print("cache data returned", cached_data) # debug

                    device_fingerprint = generate_fingerprint_hash(request)
                    hashed_device_fingerprint = Hash.generate_hash(device_fingerprint) # encrypting device fingerprint
                    session_id = create_session_id()
                    hashed_session_id = Hash.generate_hash(session_id) # encrypting session id
                    # access token
                    access_token = auth_token.create_access_token(data={"sub": hashed_email})
                    response.delete_cookie("access_token")  # Remove old token
                    cookie_settings = get_secure_cookie_settings()
                    response.set_cookie(key="access_token", value=access_token, max_age=3600, **cookie_settings)

                    # refresh token
                    refresh_token = auth_token.create_refresh_token(data={
                                                                            "sub": session_id,
                                                                            "data": device_fingerprint})
                    hashed_refresh_token = Hash.generate_hash(refresh_token)
                    if incoming_refresh_token:
                        await client.delete(f"user:refresh_token:{incoming_refresh_token[:106]}") # delete old refresh token from redis
                    response.delete_cookie("refresh_token")  # Remove old token
                    response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
                    await client.hset(f"user:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": hashed_refresh_token,
                                                            "device_fingerprint":hashed_device_fingerprint,
                                                            "data":hashed_email,
                                                            "session_id":hashed_session_id})
                    await client.expire(f"user:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

                    # log 
                    create_new_log("info", f"{hashed_email} logged in successfully", "/api/backend/Auth" )
                    logger.info(f"{hashed_email} logged in successfully") 
                    
                    return {"message":f"{hashed_email} logged in succesfully", "status_code":status.HTTP_200_OK, "email":hashed_email}  # Return success message

                print("cache data returned none") # debug
                create_new_log("warning", f"login attempt with invalid credentials for email: {form_data['email']}", "/api/backend/Auth")
                logger.warning(f"login attempt with invalid credentials for email: {form_data['email']}") # log without password
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

            # login using phone_number and password
            elif phone_number_provided:
                # Generate a cache key based on login identifier
                hashed_phone_number = generate_deterministic_hash(phone_number_provided)
                cached_data = await cache_with_password(hashed_phone_number, password_provided)
                if cached_data:
                    print("cache data returned", cached_data) # debug

                    device_fingerprint = generate_fingerprint_hash(request)
                    hashed_device_fingerprint = Hash.generate_hash(device_fingerprint) # encrypting device fingerprint
                    session_id = create_session_id()
                    hashed_session_id = Hash.generate_hash(session_id) # encrypting session id
                    # access token
                    access_token = auth_token.create_access_token(data={"sub": hashed_phone_number})
                    response.delete_cookie("access_token")  # Remove old token
                    response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)

                    # refresh token
                    refresh_token = auth_token.create_refresh_token(data={
                                                                            "sub": session_id,
                                                                            "data": device_fingerprint})
                    hashed_refresh_token = Hash.generate_hash(refresh_token)
                    if incoming_refresh_token:
                        await client.delete(f"user:refresh_token:{incoming_refresh_token[:106]}") # delete old refresh token from redis
                    response.delete_cookie("refresh_token")  # Remove old token
                    response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
                    await client.hset(f"user:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": hashed_refresh_token,
                                                            "device_fingerprint":hashed_device_fingerprint,
                                                            "data":hashed_phone_number,
                                                            "session_id":hashed_session_id})
                    await client.expire(f"user:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

                    create_new_log("info", f"{hashed_phone_number} logged in successfully", "/api/backend/Auth")
                    logger.info(f"{hashed_phone_number} logged in successfully") # log the cache hit
                    
                    return {"message":f"{phone_number_provided[:4]+'x'*6+phone_number_provided[11:]} logged in succesfully", "status_code":status.HTTP_200_OK, "phone_number": hashed_phone_number}  # Return success message

                print("cache data returned none") # debug
                create_new_log("warning", f"login attempt with invalid credentials for phone: {form_data['phone_number']}", "/api/backend/Auth")
                logger.warning(f"login attempt with invalid credentials for phone: {form_data['phone_number']}") # log without password
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
            
    except Exception as e:
        print(f"login attempt failed: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"login attempt failed: {formatted_error}", "/api/backend/Auth")
        logger.error(f"login attempt failed: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        print(f"Formatted Error: {formatted_error}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
# ***************************************************************************************************************************************************************
   

@auth_user.get("/user/refresh_token", status_code=status.HTTP_200_OK)
async def refresh_token(request: Request, response: Response):
    """
    Handles the refresh token process for user authentication.
    This endpoint verifies the provided refresh token (from cookies, headers, or query parameters),
    checks its validity against stored values in Redis, and issues new access and refresh tokens if valid.
    It also validates the device fingerprint and session ID to ensure the request's authenticity.
    Steps:
        1. Extracts the incoming refresh token from the request.
        2. Decodes the token to retrieve the session ID and device fingerprint.
        3. Retrieves the corresponding stored refresh token data from Redis.
        4. Validates the refresh token, device fingerprint, and session ID.
        5. If valid, deletes the old refresh token from Redis, generates new tokens, and stores them.
        6. Sets the new tokens as cookies in the response.
        7. Logs the process and returns a success response with the new tokens.
    Args:
        request (Request): The incoming HTTP request containing the refresh token.
        response (Response): The HTTP response object to set new cookies.
    Returns:
        dict: A dictionary containing the status code, message, token type, user data, 
              new access token, and new refresh token.
    Raises:
        HTTPException: If the refresh token is missing, expired, invalid, or if any validation fails.
        HTTPException: If an unexpected error occurs during the process.
    """
    
    try:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"})
        
        #  handling incoming refresh token
        incoming_refresh_token = request.cookies.get("refresh_token") or request.headers.get("refresh_token") or request.query_params.get("refresh_token") 
        if not incoming_refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token required")
        incoming_session_id = auth_token.decode_token(incoming_refresh_token, credentials_exception) # verify access token and getting the session_id from it
        incoming_device_fingerprint = auth_token.decode_token_data(incoming_refresh_token, credentials_exception) # verify access token and getting the device_fingerprint from it
        # incoming_session_id = request.cookies.get("session_id") or request.headers.get("session_id") or request.query_params.get("session_id")

        
        #  handling stored refresh token
        stored_refresh_token_in_redis = await client.hgetall(f"user:refresh_token:{incoming_refresh_token[:106]}")  # get refresh token from redis

        extra_data = stored_refresh_token_in_redis.get("data") # extract data from redis data
        stored_refresh_token = stored_refresh_token_in_redis.get("refresh_token") # extract refresh_token from redis data
        stored_session_id = stored_refresh_token_in_redis.get("session_id") # extract session_id from redis data
        stored_device_fingerprint = stored_refresh_token_in_redis.get("device_fingerprint") # extract device_fingerprint from redis data

        if not stored_refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
        if not stored_device_fingerprint:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device fingerprint")
        if not stored_session_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session id")
        
        verify_refresh_token = await Hash.verify(stored_refresh_token, incoming_refresh_token)
        verify_device_fingerprint = await Hash.verify(stored_device_fingerprint, incoming_device_fingerprint)
        verify_session_id = await Hash.verify(stored_session_id, incoming_session_id)
        logger.info(f"Refresh token verification: {verify_refresh_token}, Device fingerprint verification: {verify_device_fingerprint}, Session ID verification: {verify_session_id}")

        if verify_refresh_token and verify_device_fingerprint and verify_session_id:  # if refresh token is valid, give access token
            print({"refresh_token":"valid", "device_fingerprint":"valid", "session_id":"valid"}) # debug
            await client.delete(f"user:refresh_token:{incoming_refresh_token[:106]}")

            device_fingerprint = generate_fingerprint_hash(request)
            hashed_device_fingerprint = Hash.generate_hash(device_fingerprint) # encrypting device fingerprint
            session_id = create_session_id()
            hashed_session_id = Hash.generate_hash(session_id) # encrypting session id
            # access token
            new_access_token = auth_token.create_access_token(data={"sub": extra_data})
            response.delete_cookie("access_token")  # Remove old token
            response.set_cookie(key="access_token", value=new_access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False) # access token expires in 1 hour

            # refresh token
            new_refresh_token = auth_token.create_refresh_token(data={
                                                                        "sub": session_id,
                                                                        "data":device_fingerprint})
            response.delete_cookie("refresh_token")  # Remove old token
            response.set_cookie(key="refresh_token", value=new_refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
            new_hashed_refresh_token = Hash.generate_hash(new_refresh_token)
            await client.hset(f"user:refresh_token:{new_refresh_token[:106]}",mapping={
                                                            "refresh_token": new_hashed_refresh_token,
                                                            "data":extra_data,
                                                            "device_fingerprint":hashed_device_fingerprint,
                                                            "session_id":hashed_session_id})
            await client.expire(f"user:refresh_token:{new_refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis
            create_new_log("info", f"Refresh token verified for {device_fingerprint} -> device_fingerprint", "/api/backend/Auth")
            logger.info(f"Refresh token verified for {device_fingerprint} -> device_fingerprint") # log the cache hit
            return({"status_code":status.HTTP_200_OK, "message":"Refresh token verified,user logged in", "data": extra_data}) # send extra_data as it is hashed
        else:
            return ({"status_code":status.HTTP_401_UNAUTHORIZED, "message":"Invalid refresh token"})
        
      
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error refreshing token: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error refreshing token: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@auth_user.post("/user/reset_password", status_code=status.HTTP_200_OK)
async def reset_password(data: models.email):
    """Asynchronously handles password reset requests by generating and emailing a one-time password (OTP) to the user.
    Args:
        data (models.email): An object containing the user's email address.
    Raises:
        HTTPException: 
            - 400 if the email is not provided.
            - 404 if the user with the given email is not found.
            - 500 if there is an error sending the email or any other internal error occurs.
    Returns:
        dict: A dictionary containing a success message, HTTP status code, and the hashed OTP.
    Side Effects:
        - Sends an OTP to the user's email address for password reset.
        - Logs the outcome of the operation (success or error)."""

    try:
        form_data = dict(data)
        email = form_data.get("email")
        if not email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required")
        hashed_email = generate_deterministic_hash(email)
        user = await mongo_client.auth.user.find_one({"hashed_email": hashed_email})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        otp = await generate_otp(hashed_email)
        html_body = f"""
                    <html>
                        <body style="font-family: Arial, sans-serif; background-color: #f0f2f5; padding: 30px;">

                            <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: auto; background-color: #ffffff; border: 1px solid #dcdfe6; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
                                <tr>
                                    <td style="padding: 30px; text-align: center;">
                                        <h1 style="color: #2c3e50; font-size: 24px; margin-bottom: 10px;">Reset Your Password</h1>
                                        <p style="color: #606f7b; font-size: 15px; margin-bottom: 25px;">
                                            Hello,
                                        </p>
                                        <p style="color: #606f7b; font-size: 15px; margin-bottom: 20px;">
                                            We received a request to reset the password for your <strong>SecureGate</strong> account. Please use the below otp for creaing a new password.
                                        </p>
                                        <span style="font-size: 24px; font-weight: bold; color: #2c3e50;">{otp}</span>
                                        <p style="color: #606f7b; font-size: 13px; margin-bottom: 30px;">
                                            If you did not request this, you can safely ignore this email.
                                        </p>
                                        <p style="color: #606f7b; font-size: 12px;">Need help? Contact our support team at <p>support@SecureGate.com"</p> style="color: #1d72b8; text-decoration: none;">support@SecureGate.com</a></p>
                                        <p style="color: #a0aec0; font-size: 12px;">&copy; 2025 SecureGate | All rights reserved.</p>
                                    </td>
                                </tr>
                            </table>
                        </body>
                    </html>
                    """
        
        # send email verification link
        email_sent = (send_mail_to_mailhog(email, "Password Reset Request", html_body, retries=3, delay=5))
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")
        create_new_log("info", f"Password reset otp sent successfully to {hashed_email}", "/api/backend/Auth")
        logger.info(f"Password reset link otp successfully to {hashed_email}") 
        return ({"message": "Password reset otp sent successfully", "status_code": status.HTTP_200_OK}) # Return success message
    
    except Exception as e:
        print(f"Error resetting password: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error sending reset password otp: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error sending reset password otp: {str(e)}")
        print(f"Error: {formatted_error}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
        

@auth_user.post("/user/reset_password/email_verify_otp", status_code=status.HTTP_200_OK) # verify otp during signup
async def verify_otp_reset_password(data: models.otp_email):
    """
    Endpoint to verify OTP (One-Time Password) during password reset.
    Accepts a POST request with email and OTP.
    Args:
        data (models.otp_email): The OTP data containing 'email' and 'otp'.
    Returns:
        dict: A message indicating OTP was verified successfully, or raises an HTTPException on error.
    Raises:
        HTTPException: If the OTP is invalid or any other error occurs during verification.
    """

    try:
        form_data = dict(data)
        email = form_data.get("email")
        otp_entered = form_data.get("otp")
        
        # Removed sensitive OTP logging
        if not otp_entered or len(otp_entered) != 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
        hashed_email = generate_deterministic_hash(email)
        otp_stored = await client.hgetall(f"otp:{hashed_email}")
        # Removed sensitive OTP logging
        if not otp_stored or (otp_stored.get('otp') != otp_entered):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        
        create_new_log("info", f"OTP verified successfully from {hashed_email}", "/api/backend/Auth")
        logger.info(f"OTP verified successfully from {hashed_email}")
        return {"message":f"OTP verified successfully from {hashed_email}", "status_code":status.HTTP_200_OK, "email": email}
                         
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error verifying OTP: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error verifying OTP: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    


@auth_user.post("/user/create_new_password", status_code=status.HTTP_200_OK) 
async def create_new_password(data: models.reset_password):
    """
    Asynchronously resets a user's password after validating the provided data.
    Args:
        data (models.reset_password): An object containing the user's email, new password, and password confirmation.
    Raises:
        HTTPException: 
            - 404 if the user is not found.
            - 400 if required fields are missing, passwords do not match, password is too short, or the new password matches the last used password.
            - 500 for any unexpected errors during the process.
    Returns:
        dict: A dictionary with a success message and HTTP status code upon successful password update.
    Side Effects:
        - Updates the user's password in the MongoDB database.
        - Updates the user's password in the Redis cache.
        - Logs the password reset event or any errors encountered.
    """

    try:
        form_data = dict(data)
        email = form_data.get("email")
        hashed_email = generate_deterministic_hash(email)
        user = await mongo_client.auth.user.find_one({"hashed_email": hashed_email})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        print(user) # debug
        password = form_data.get("password")
        confirm_password = form_data.get("confirm_password")
        
        last_used_password = await Hash.verify(user["password"], password)

        if not password or not confirm_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password and confirm password are required")
        if password != confirm_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")
        validate_password(password)
        if last_used_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password cannot be the same as the last one")
        
        hashed_password = Hash.generate_hash(password)
        hashed_email = generate_deterministic_hash(email)
        result = await mongo_client.auth.user.update_one({"hashed_email": hashed_email}, {"$set": {"password": hashed_password}})
        await client.hset(f"{REDIS_USER_AUTH}:{hashed_email}",mapping={
                                                            "data":hashed_email,
                                                            "password": hashed_password})
        await client.expire(f"{REDIS_USER_AUTH}:{hashed_email}", 3600) # expire in 1 hour -> storing user auth in redis
        # Check if user was updated
        if result.modified_count == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unable to update password, please try again later")
        create_new_log("info", f"Password reset successfully for {email}", "/api/backend/Auth")
        logger.info(f"Password reset successfully for {email}")
        return ({"message": "Password updated successfully", "status_code": status.HTTP_200_OK}) # Return success message
    
    except Exception as e:
        print(f"Error creating new password: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error creating new password: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error creating new password: {str(e)}") # log the cache hit
        print(f"Error: {formatted_error}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@auth_user.post("/user/logout", status_code=status.HTTP_200_OK)
async def logout(data: models.logout, response: Response, request: Request):
    """
    Logs out a user by deleting their refresh and access tokens from cookies and cache.
    Args:
        data (models.email): The email data of the user requesting logout.
        response (Response): The HTTP response object to modify cookies.
        request (Request): The HTTP request object to extract tokens.
    Returns:
        dict: A dictionary containing a success message and HTTP status code.
    Side Effects:
        - Deletes the user's refresh token from the cache if present.
        - Removes 'access_token' and 'refresh_token' cookies from the response.
        - Logs the logout event for auditing and debugging purposes.
    """
    try:
        incoming_refresh_token = request.cookies.get("refresh_token") or request.headers.get("refresh_token") or request.query_params.get("refresh_token")
        form_data = dict(data)
        data = form_data.get("data")
        if incoming_refresh_token:
            await client.delete(f"user:refresh_token:{incoming_refresh_token[:106]}")
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        create_new_log("info", f"{data} logged out successfully", "/api/backend/Auth")
        logger.info(f"{data} logged out successfully") # log the cache hit
        print(f"{data} logged out successfully") # debug
        return {"message":f"{data} logged out successfully", "status":status.HTTP_200_OK}  # Return success message
    except Exception as e:
        print(f"Error logging out: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error logging out: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error logging out: {str(e)}")



# ***********************************************NOT USED ROUTES***************************************************************************************************

# ***************************** this route helped in verifying email ****************************************************
# @auth_user.get("/user/verify_email/{token}", status_code=status.HTTP_200_OK, response_model=models.res)
# async def verify_email(token: str, response: Response):
#     try:
#         token_data = decode_verification_token(token)
#         email = token_data["email"]
#         temp_user = await mongo_client.auth.temp.find_one({"email": email})
#         if not temp_user:
#             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") 
#         temp_user.pop("_id")
#         await mongo_client.auth.user.insert_one(temp_user) # adding to the main db
#         await mongo_client.auth.temp.delete_many({"email": email}) # deleting from the temp db
        # create_new_log("info", f"Account for user created successfully: {email}", "/api/backend/Auth")
#         logger.info(f"Account for user created successfully: {email}") # log the cache hit
#         # Generate a cache during signup with email as key
#         cache_key = email
#         cached_data = await client.set(f"user:{cache_key}",cache_key,ex=3600) 
#         access_token = auth_token.create_access_token(data={"sub": cache_key})
#         response.delete_cookie("access_token")  # Remove old token
#         response.set_cookie(key="access_token", value=access_token, max_age=3600)
#         RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
#         return {"message":"Account for user created successfully"} # Return success message        
    
#     except Exception as e:
#         print(f"Error verifying email: {str(e)}")
#         formatted_error = traceback.format_exc()
        # create_new_log("error", f"Error verifying email: {formatted_error}", "/api/backend/Auth")
#         logger.error(f"Error verifying email: {str(e)}") # log the cache hit
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

