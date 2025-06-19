from fastapi import APIRouter, Request, status, HTTPException, Depends, Response
import traceback
from kafka import KafkaProducer
import json
from datetime import datetime
from ..models import models
from ..config.database import mongo_client
from ..helper.utils import create_session_id, create_new_log, generate_fingerprint_hash, get_country_name, generate_random_string, setup_logging
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError
from ..config.redis_config import client
from ..helper.auth_token import create_access_token
import os
from ..otp_service.send_mail import send_email
from ..helper.hashing import Hash
from ..helper import auth_token
from fastapi.templating import Jinja2Templates
from ..config.bloom_filter import CountingBloomFilter
from dotenv import load_dotenv

google_user_auth = APIRouter(tags=["Google Authentication"])
# google_user_auth.mount("/authentication/static", StaticFiles(directory="static"), name="static")
load_dotenv()

GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
SECRET_KEY = os.getenv("SECRET_KEY")

templates = Jinja2Templates(directory="authentication/templates")

# Kafka Producer
producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

google_user_email_bloom_filter = CountingBloomFilter(capacity=1000000, error_rate=0.01)
google_user_phone_bloom_filter = CountingBloomFilter(capacity=1000000, error_rate=0.01)

# initialize logger
logger = setup_logging()  

# OAuth Setup
oauth = OAuth()
oauth.register(
    name="google_user",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    userinfo_endpoint="https://www.googleapis.com/oauth2/v3/userinfo",
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",  # Manually set JWKS URI
    client_kwargs={"scope": "openid email profile https://www.googleapis.com/auth/user.phonenumbers.read"}
)

async def cache_without_password(data: str):
    """
    Asynchronously retrieves user authentication data from cache or database without requiring a password.
    Args:
        data (str): The identifier for the user (typically an email address).
    Returns:
        dict or str or None: Returns cached data (if present), user data from the database (if found), or None if the user does not exist.
    Side Effects:
        - Logs cache hits and invalid login attempts.
        - Caches user data for 5 days if found in the database.
    Raises:
        None
    """

    CachedData = await client.get(f'user:auth:2_factor_login:{data}')
    if CachedData:
        print("Data is cached") # debug
        print(CachedData) # debug
        create_new_log("info", f"cache hit for {data}", "/api/backend/Auth")
        logger.info(f"cache hit for {data}") # log the cache hit
        return CachedData
  
    user = await mongo_client.auth.user.find_one({"email": data}) # check if user exists in db
    if user:
        print("searching inside db") # debug
        await client.set(f"user:auth:2_factor_login:{data}",data, ex=432000) # expire in 5 days
        return user
    create_new_log("warning", f"login attempt with invalid credentials: {data}", "/api/backend/Auth")
    logger.warning(f"login attempt with invalid credentials: {data}") # log the cache hit
    return None

TOPIC_NAME = 'user_signups'
TOPIC2_NAME = "user_CIN"
# ---- user Signup ----


@google_user_auth.get("/user")
async def index(request: Request):
    return templates.TemplateResponse("user.html", {"request": request})


@google_user_auth.get("/user/google_signup")
async def user_google_signup(request: Request):
    redirect_uri = "http://127.0.0.1:8000/user/google_signup/callback"
    return await oauth.google_user.authorize_redirect(request, redirect_uri)

@google_user_auth.get("/user/google_signup/callback")
async def user_google_signup_callback(request: Request, response: Response):
    """
    Handles the Google OAuth2 signup callback for a user.
    This asynchronous function performs the following steps:
    1. Authorizes the Google access token from the OAuth2 flow.
    2. Retrieves basic user information and phone number from Google APIs.
    3. Checks for the existence of the user's email and phone number in Bloom filters, Redis cache, and MongoDB to prevent duplicate signups.
    4. If the phone number is missing, redirects the user to provide their phone number.
    5. Prepares user data, including generating a UID, setting verification status, and determining the user's country.
    6. Sends user data to Kafka topics for further processing.
    7. Caches user data in Redis and sets up two-factor login keys.
    8. Generates and stores refresh and access tokens, setting them as cookies in the response.
    9. Sends a welcome email to the user.
    10. Logs all significant events and errors for monitoring and debugging.
    Args:
        request (Request): The incoming HTTP request object.
        response (Response): The outgoing HTTP response object.
    Returns:
        dict: A dictionary containing a success message, status code, token type, UID, creation timestamp, access token, and refresh token.
        OR
        RedirectResponse: If the user's phone number is missing, redirects to the phone number input page.
    Raises:
        HTTPException: If authentication fails, or if the email or phone number already exists, or if sending the welcome email fails.
    """

    try:
        token = await oauth.google_user.authorize_access_token(request)

        # Fetch basic user info
        response = await oauth.google_user.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)
        user_info = response.json()

        # Fetch phone number separately from Google People API
        people_api_url = "https://people.googleapis.com/v1/people/me?personFields=phoneNumbers"
        phone_response = await oauth.google_user.get(people_api_url, token=token)
        phone_data = phone_response.json()

        # Extract phone number safely
        phone_numbers = phone_data.get("phoneNumbers", [])
        phone_number = phone_numbers[0]["value"] if phone_numbers else None

        if not phone_number :
            request.session["email"] = user_info.get("email")
            request.session["name"] = user_info.get("name")
            return RedirectResponse(url = "/user/phone_number")

        # User details
        user_data = {
            "email": user_info.get("email"),
            "first_name": user_info.get("name"),
            # "picture": user_info.get("picture"),
            # "locale": user_info.get("locale"),
            # "verified_email": user_info.get("email_verified"),
            "phone_number": phone_number,
            "country_code": user_info.get("country_code", None),
            "UID": generate_random_string(),
            "created_at" : datetime.now().isoformat(),
            "verification_status": "false"

        }

        # Email validation
        if not google_user_email_bloom_filter.contains(user_data["email"]):  # Check if email is definitely not present
            print("Email not in Bloom filter — safe to continue")
            # continue with signup
            return
        else:
            print("Bloom filter indicates possible existence — verifying with Redis and DB")

            # Double-check in Redis (temporary store, e.g., for recent signups or pending activation)
            email_in_redis = await client.hgetall(f"user:new_account:{user_data['email']}")
            if email_in_redis:
                print("Email found in Redis")
                create_new_log("warning", f"Signup attempt with existing email: {user_data['email']}", "/api/backend/Auth")
                logger.warning(f"Signup attempt with existing email: {user_data['email']}")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
            else:
                print("Email not found in Redis — checking MongoDB")
                # Check in MongoDB (source of truth)
                email = await mongo_client.auth.user.find_one({"email": user_data["email"]})
                if email:
                    print("Email found in MongoDB")
                    create_new_log("warning", f"Signup attempt with existing email: {user_data['email']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing email: {user_data['email']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

        print("Email is new — proceed with account creation")  # Email is confirmed to be new — proceed

        # Phone number validation
        if not google_user_phone_bloom_filter.contains(user_data["phone_number"]):  # Check if phone number is definitely not present
            print("Phone number not in Bloom filter — safe to continue")
            # continue with signup
            return
        else:
            print("Bloom filter indicates possible existence — verifying with Redis and DB")

            # Double-check in Redis
            phone_number_in_redis = await client.hgetall(f"user:new_account:{user_data['phone_number']}")
            if phone_number_in_redis:
                print("Phone number found in Redis")
                create_new_log("warning", f"Signup attempt with existing phone number: {user_data['phone_number']}", "/api/backend/Auth")
                logger.warning(f"Signup attempt with existing phone number: {user_data['phone_number']}")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already in use")
            else:
                print("Phone number not found in Redis — checking MongoDB")
                # Check in MongoDB
                phone_number = await mongo_client.auth.user.find_one({"phone_number": user_data["phone_number"]})
                if phone_number:
                    print("Phone number found in MongoDB")
                    create_new_log("warning", f"Signup attempt with existing phone number: {user_data['phone_number']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing phone number: {user_data['phone_number']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already in use")

        print("Phone number is new — proceed with account creation")  # Phone number is confirmed to be new — proceed

        # if phone number was fetched then insert the user into the database and create a JWT token
        user_data["full_name"] = user_data["first_name"]  # last_name will be handeled when all other details of user will be taken
        if user_data["country_code"] is not None:
            updated_phone_number = user_data["phone_number"] + user_data["country_code"]
            country_name = get_country_name(updated_phone_number)
            country_name = country_name.lower()
            user_data["country_name"] = country_name

        # ****************send data to kafka topic *****************
        producer.send(TOPIC_NAME, user_data) # send data to kafka topic
        producer.flush() # flush the producer to ensure data is sent
        producer.send(TOPIC2_NAME, value={"UID":user_data["UID"]}) # send data to kafka topic
        producer.flush() # flush the producer to ensure data is sent

        # await mongo_client.auth.user.insert_one(user_data)  # this is done when kafka topic is consumed

        # Generate a cache during signup with email as key
        cache_key = user_data["email"]
        google_user_email_bloom_filter.add(user_data["email"])
        google_user_phone_bloom_filter.add(user_data["phone_number"])
        await client.hset(f"user:new_account:{cache_key}",mapping=user_data)
        await client.expire(f"user:new_account:{cache_key}", 691200) # expire in 7 days
        await client.hset(f"user:new_account:{user_data['phone_number']}",mapping=user_data)
        await client.expire(f"user:new_account:{user_data['phone_number']}", 691200) # expire in 7 days

        #  for instant logging in after signup
        await client.set(f"user:auth:2_factor_login:{user_data['email']}", user_data["email"], ex=3600) # expire in 1 hour
        await client.set(f"user:auth:2_factor_login:{user_data['phone_number']}", user_data["phone_number"], ex=3600) # expire in 1 hour


        device_fingerprint = generate_fingerprint_hash(request)
        session_id = create_session_id()
        refresh_token = auth_token.create_refresh_token(data={
                                                                "sub": session_id,
                                                                "data": device_fingerprint})
        response.delete_cookie("refresh_token")  # Remove old token
        response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
        encrypted_refresh_token = Hash.bcrypt(refresh_token)
        encrypyted_session_id = Hash.bcrypt(session_id)
        encrypyted_device_fingerprint = Hash.bcrypt(device_fingerprint)
        print(encrypted_refresh_token) # debug

        await client.hset(f"user:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":user_data['email'],
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"user:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        # html_path = "/root/SecureGate_Auth/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()
        # send email verification link
        email_sent = send_email(user_data["email"], "Welcome to SecureGate. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")


        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        create_new_log("info", f"Account for user created successfully: {user_data['email']}", "/api/backend/Auth")
        logger.info(f"Account for user created successfully: {user_data['email']}")
        return {"message":f"Account for user created successfully: {user_data['email']}", "status_code": status.HTTP_201_CREATED, "token_type": "Bearer", "UID": user_data["UID"], "created_at": user_data["created_at"], "access_token": access_token, "refresh_token": refresh_token}

    except OAuthError as e:
        formatted_error = traceback.format_exc()
        create_new_log("error", f"OAuth Error: {str(e)}", "/api/backend/Auth")
        logger.exception(f"OAuth Error: {formatted_error}")
        raise HTTPException(status_code=400, detail="Authentication failed")

@google_user_auth.post("/user/phone_number/signup")
async def user_phone_number_signup(data:models.google_login, request: Request, response: Response):
    """
    Handles user signup using phone number after Google authentication.
    This asynchronous function performs the following steps:
    - Extracts phone number and country code from the provided data.
    - Retrieves email and name from the session.
    - Checks for existing users by email and phone number using Bloom filters, Redis, and MongoDB.
    - Prepares user data and sends it to Kafka topics for further processing.
    - Caches user data in Redis and sets up two-factor authentication keys.
    - Generates and sets refresh and access tokens as cookies in the response.
    - Sends a welcome email with a verification link to the user.
    - Logs all significant actions and errors.
    Args:
        data (models.google_login): The input data containing phone number and country code.
        request (Request): The incoming HTTP request object, used to access session data.
        response (Response): The HTTP response object, used to set cookies.
    Returns:
        dict: A dictionary containing a success message, status code, token type, UID, creation timestamp, access token, and refresh token.
    Raises:
        HTTPException: If required fields are missing, session is expired, email or phone number already exists, or if there is an error sending the email.
        Exception: For any other unexpected errors, returns a 400 status code with a generic error message.
    """

    try:
        form_data = dict(data)
        phone_number = form_data.get("phone_number")
        country_code = form_data.get("country_code")

        if not phone_number:
            raise HTTPException(status_code=400, detail="Phone number is required.")

        # retrieve  email and name from session
        email = request.session.get("email")
        name = request.session.get("name")
        if not email or not name:
            raise HTTPException(status_code=400, detail="Session expired. Please Signup again.")
        
        user_data = {
            "email": email,
            "first_name": name,
            "phone_number": phone_number,
            "country_code": country_code,
            "UID": generate_random_string(),
            "created_at" : datetime.now().isoformat(),
            "verification_status": "false"
        }

        # Email validation
        if not google_user_email_bloom_filter.contains(user_data["email"]):  # Check if email is definitely not present
            print("Email not in Bloom filter — safe to continue")
            # continue with signup
            return
        else:
            print("Bloom filter indicates possible existence — verifying with Redis and DB")

            # Double-check in Redis (temporary store, e.g., for recent signups or pending activation)
            email_in_redis = await client.hgetall(f"user:new_account:{user_data['email']}")
            if email_in_redis:
                print("Email found in Redis")
                create_new_log("warning", f"Signup attempt with existing email: {user_data['email']}", "/api/backend/Auth")
                logger.warning(f"Signup attempt with existing email: {user_data['email']}")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
            else:
                print("Email not found in Redis — checking MongoDB")
                # Check in MongoDB (source of truth)
                email = await mongo_client.auth.user.find_one({"email": user_data["email"]})
                if email:
                    print("Email found in MongoDB")
                    create_new_log("warning", f"Signup attempt with existing email: {user_data['email']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing email: {user_data['email']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

        print("Email is new — proceed with account creation")  # Email is confirmed to be new — proceed

        # Phone number validation
        if not google_user_phone_bloom_filter.contains(user_data["phone_number"]):  # Check if phone number is definitely not present
            print("Phone number not in Bloom filter — safe to continue")
            # continue with signup
            return
        else:
            print("Bloom filter indicates possible existence — verifying with Redis and DB")

            # Double-check in Redis
            phone_number_in_redis = await client.hgetall(f"user:new_account:{user_data['phone_number']}")
            if phone_number_in_redis:
                print("Phone number found in Redis")
                create_new_log("warning", f"Signup attempt with existing phone number: {user_data['phone_number']}", "/api/backend/Auth")
                logger.warning(f"Signup attempt with existing phone number: {user_data['phone_number']}")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already in use")
            else:
                print("Phone number not found in Redis — checking MongoDB")
                # Check in MongoDB
                phone_number = await mongo_client.auth.user.find_one({"phone_number": user_data["phone_number"]})
                if phone_number:
                    print("Phone number found in MongoDB")
                    create_new_log("warning", f"Signup attempt with existing phone number: {user_data['phone_number']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing phone number: {user_data['phone_number']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already in use")

        print("Phone number is new — proceed with account creation")  # Phone number is confirmed to be new — proceed


        # Insert user into the database
        user_data["full_name"] = user_data["first_name"] # last_name will be handeled when all other details of user will be taken
        updated_phone_number = phone_number + country_code
        country_name = get_country_name(updated_phone_number)
        country_name = country_name.lower()
        user_data["country_name"] = country_name

        # ****************send data to kafka topic *****************
        producer.send(TOPIC_NAME, user_data) # send data to kafka topic
        producer.flush() # flush the producer to ensure data is sent
        producer.send(TOPIC2_NAME, value={"UID":user_data["UID"]}) # send data to kafka topic
        producer.flush() # flush the producer to ensure data is sent

        # await mongo_client.auth.user.insert_one(user_data) # this is done when kafka topic is consumed

        cache_key = user_data["email"]
        google_user_email_bloom_filter.add(user_data["email"])
        google_user_phone_bloom_filter.add(user_data["phone_number"])
        await client.hset(f"user:new_account:{cache_key}",mapping=user_data)
        await client.expire(f"user:new_account:{cache_key}", 691200) # expire in 7 days
        await client.hset(f"user:new_account:{phone_number}",mapping=user_data)
        await client.expire(f"user:new_account:{phone_number}", 691200) # expire in 7 days

        #  for instant logging in after signup
        await client.set(f"user:auth:2_factor_login:{cache_key}", cache_key, ex=691200) # expire in 1 hour
        await client.set(f"user:auth:2_factor_login:{phone_number}", phone_number, ex=691200) # expire in 1 hour

        device_fingerprint = generate_fingerprint_hash(request)
        session_id = create_session_id()
        refresh_token = auth_token.create_refresh_token(data={
                                                                "sub": session_id,
                                                                "data": device_fingerprint})
        response.delete_cookie("refresh_token")  # Remove old token
        response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
        encrypted_refresh_token = Hash.bcrypt(refresh_token)
        encrypyted_session_id = Hash.bcrypt(session_id)
        encrypyted_device_fingerprint = Hash.bcrypt(device_fingerprint)
        print(encrypted_refresh_token) # debug

        await client.hset(f"user:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":user_data['email'],
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"user:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        # html_path = "/root/SecureGate_Auth/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()
        # send email verification link
        email_sent = send_email(user_data["email"], "Welcome to SecureGate. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        create_new_log("info", f"Account for user created successfully: {user_data['email']}", "/api/backend/Auth")
        logger.info(f"Account for user created successfully: {user_data['email']}")
        return {"message":f"Account for user created successfully: {user_data['email']}", "status_code": status.HTTP_201_CREATED, "token_type": "Bearer", "UID": user_data["UID"], "created_at": user_data["created_at"], "access_token": access_token, "refresh_token": refresh_token}
    
    except Exception as e:
        formatted_error = traceback.format_exc()
        print(f"Error: {str(e)}")
        create_new_log("error", f"Signup attempt failed: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Signup attempt failed: {str(e)}")
        raise HTTPException(status_code=400, detail="Internal server error")

# Phone Number Entry Page (GET)
@google_user_auth.get("/user/phone_number")
async def phone_number_page(request: Request):
    return templates.TemplateResponse("phone_number.html", {"request": request, "type": "user"})


# ---- user Login ----
@google_user_auth.get("/user/google_login")
async def user_google_login(request: Request):
    redirect_uri = "http://127.0.0.1:8000/user/google_login/callback"
    return await oauth.google_user.authorize_redirect(request, redirect_uri)

@google_user_auth.get("/user/phone_number_login")
async def phone_number_page_login(request: Request):
    return templates.TemplateResponse("phone_number.html", {"request": request, "type": "user", "flow": "login"})

@google_user_auth.post("/user/phone_number/login")
async def user_phone_number_login(data: models.google_login, request: Request, response: Response):
    """
    Handles user login or signup using phone number after Google authentication.
    This asynchronous function performs the following steps:
    1. Extracts phone number and country code from the provided data.
    2. Retrieves user's email and name from the session.
    3. Validates the presence of required fields and session data.
    4. Checks for existing users by email and phone number using Bloom filters, Redis cache, and MongoDB.
    5. If the user does not exist, creates a new user object and sends it to Kafka topics for further processing.
    6. Stores user data in Redis for caching and instant login.
    7. Generates and sets refresh and access tokens as HTTP cookies.
    8. Sends a welcome email with a verification link to the user.
    9. Logs all significant events and errors for monitoring and debugging.
    Args:
        data (models.google_login): The input data containing phone number and country code.
        request (Request): The HTTP request object, used to access session data.
        response (Response): The HTTP response object, used to set cookies.
    Returns:
        dict: A dictionary containing a success message, status code, token type, UID, creation time, access token, and refresh token.
    Raises:
        HTTPException: If required fields are missing, session is expired, user already exists, or an internal error occurs.
    """

    try:
        form_data = dict(data)
        phone_number = form_data.get("phone_number")
        country_code = form_data.get("country_code")

        if not phone_number:
            raise HTTPException(status_code=400, detail="Phone number is required.")
        email = request.session.get("email")
        name = request.session.get("name")
        if not email or not name:
            raise HTTPException(status_code=400, detail="Session expired. Please Login again.")

        # Create new user now
        new_user = {
            "email": email,
            "first_name": name,
            "full_name": name,
            "phone_number": phone_number,
            "country_code": country_code,
            "UID": generate_random_string(),
            "created_at": datetime.now().isoformat(),
            "verification_status": "false"
        }

        # Email validation
        if not google_user_email_bloom_filter.contains(new_user["email"]):  # Check if email is definitely not present
            print("Email not in Bloom filter — safe to continue")
            # continue with signup
            return
        else:
            print("Bloom filter indicates possible existence — verifying with Redis and DB")

            # Double-check in Redis (temporary store, e.g., for recent signups or pending activation)
            email_in_redis = await client.hgetall(f"user:new_account:{new_user['email']}")
            if email_in_redis:
                print("Email found in Redis")
                create_new_log("warning", f"Signup attempt with existing email: {new_user['email']}", "/api/backend/Auth")
                logger.warning(f"Signup attempt with existing email: {new_user['email']}")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
            else:
                print("Email not found in Redis — checking MongoDB")
                # Check in MongoDB (source of truth)
                email = await mongo_client.auth.user.find_one({"email": new_user["email"]})
                if email:
                    print("Email found in MongoDB")
                    create_new_log("warning", f"Signup attempt with existing email: {new_user['email']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing email: {new_user['email']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

        print("Email is new — proceed with account creation")  # Email is confirmed to be new — proceed

        # Phone number validation
        if not google_user_phone_bloom_filter.contains(new_user["phone_number"]):  # Check if phone number is definitely not present
            print("Phone number not in Bloom filter — safe to continue")
            # continue with signup
            return
        else:
            print("Bloom filter indicates possible existence — verifying with Redis and DB")

            # Double-check in Redis
            phone_number_in_redis = await client.hgetall(f"user:new_account:{new_user['phone_number']}")
            if phone_number_in_redis:
                print("Phone number found in Redis")
                create_new_log("warning", f"Signup attempt with existing phone number: {new_user['phone_number']}", "/api/backend/Auth")
                logger.warning(f"Signup attempt with existing phone number: {new_user['phone_number']}")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already in use")
            else:
                print("Phone number not found in Redis — checking MongoDB")
                # Check in MongoDB
                phone_number = await mongo_client.auth.user.find_one({"phone_number": new_user["phone_number"]})
                if phone_number:
                    print("Phone number found in MongoDB")
                    create_new_log("warning", f"Signup attempt with existing phone number: {new_user['phone_number']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing phone number: {new_user['phone_number']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already in use")

        print("Phone number is new — proceed with account creation")  # Phone number is confirmed to be new — proceed

        # ****************send data to kafka topic *****************
        producer.send(TOPIC_NAME, new_user) # send data to kafka topic
        producer.flush() # flush the producer to ensure data is sent
        producer.send(TOPIC2_NAME, value={"UID":new_user["UID"]}) # send data to kafka topic
        producer.flush() # flush the producer to ensure data is sent

        # await mongo_client.auth.user.insert_one(new_user)  # this is done when kafka topic is consumed

        cache_key = new_user["email"]
        google_user_email_bloom_filter.add(new_user["email"])
        google_user_phone_bloom_filter.add(new_user["phone_number"])
        await client.hset(f"user:new_account:{cache_key}",mapping=new_user)
        await client.expire(f"user:new_account:{cache_key}", 691200) # expire in 7 days
        await client.hset(f"user:new_account:{phone_number}",mapping=new_user)
        await client.expire(f"user:new_account:{phone_number}", 691200) # expire in 7 days

         #  for instant logging in after signup
        await client.set(f"user:auth:2_factor_login:{cache_key}", cache_key, ex=3600) # expire in 1 hour
        await client.set(f"user:auth:2_factor_login:{phone_number}", phone_number, ex=3600) # expire in 1 hour

        # ***** this was done previously to store data in redis cache *****
        # await client.hset(f"user:new_account:{cache_key}", mapping=new_user)
        # await client.expire(f"user:new_account:{cache_key}", 691200)  # expire in 7 days 
        
        device_fingerprint = generate_fingerprint_hash(request)
        session_id = create_session_id()
        refresh_token = auth_token.create_refresh_token(data={
                                                                "sub": session_id,
                                                                "data": device_fingerprint})
        response.delete_cookie("refresh_token")  # Remove old token
        response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
        encrypted_refresh_token = Hash.bcrypt(refresh_token)
        encrypyted_session_id = Hash.bcrypt(session_id)
        encrypyted_device_fingerprint = Hash.bcrypt(device_fingerprint)
        print(encrypted_refresh_token) # debug

        await client.hset(f"user:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":new_user['email'],
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"user:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        # html_path = "/root/SecureGate_Auth/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()
        # send email verification link
        email_sent = send_email(new_user["email"], "Welcome to SecureGate. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

        access_token = create_access_token(data={"sub": new_user["email"]})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        create_new_log("info", f"Account for user created successfully: {new_user['email']}", "/api/backend/Auth")
        logger.info(f"Account for user created successfully: {new_user['email']}")
        return {"message":f"Account for user created successfully: {new_user['email']}", "status_code": status.HTTP_201_CREATED, "token_type": "Bearer", "UID": new_user["UID"], "created_at": new_user["created_at"], "access_token": access_token, "refresh_token": refresh_token}

    except Exception as e:
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Login attempt failed: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Login attempt failed: {str(e)}")
        raise HTTPException(status_code=400, detail="Internal server error")



@google_user_auth.get("/user/google_login/callback")
async def user_google_login_callback(request: Request, response: Response):
    """
    Handles the Google OAuth2 login callback for user authentication and registration.
    This async function processes the OAuth2 callback from Google, performing the following steps:
    1. Authorizes the access token using the OAuth2 client.
    2. Retrieves user information from Google's userinfo endpoint.
    3. Checks if the user already exists in the system:
        - If the user exists, logs them in by generating access and refresh tokens, setting cookies, and updating session data.
        - If the user does not exist, attempts to retrieve the user's phone number from the Google People API.
            - If a phone number is found, checks for duplicate email/phone in Bloom filters, Redis, and MongoDB.
                - If no duplicates are found, auto-registers the user, sends a verification email, and logs them in.
            - If no phone number is found, redirects the user to a phone number collection page.
    4. Handles errors and logs relevant events.
    Args:
        request (Request): The incoming HTTP request object.
        response (Response): The outgoing HTTP response object.
    Returns:
        dict or RedirectResponse: A JSON response with login/registration details and tokens, or a redirect to the phone number collection page.
    Raises:
        HTTPException: If authentication fails, or if duplicate email/phone is detected, or if email sending fails.
    """
    
    try:
        token = await oauth.google_user.authorize_access_token(request)
        user_info = await oauth.google_user.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)
        user_data = user_info.json()

        existing_email = user_data.get("email")
        # Check if user exists in the database
        existing_account = cache_without_password(user_data.get("email"))
        if existing_account: # Case 1: User exists ➡️ Login

            # Generate access token
            cache_key = existing_email
            await client.set(f"user:new_account:{cache_key}", cache_key, ex=3600) 
            access_token = create_access_token(data={"sub": cache_key})
            
            response.delete_cookie("access_token")
            response.set_cookie(key="access_token", value=access_token, max_age=3600)

            device_fingerprint = generate_fingerprint_hash(request)
            session_id = create_session_id()
            refresh_token = auth_token.create_refresh_token(data={
                                                                    "sub": session_id,
                                                                    "data": device_fingerprint})
            response.delete_cookie("refresh_token")  # Remove old token
            response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
            encrypted_refresh_token = Hash.bcrypt(refresh_token)
            encrypyted_session_id = Hash.bcrypt(session_id)
            encrypyted_device_fingerprint = Hash.bcrypt(device_fingerprint)
            print(encrypted_refresh_token) # debug

            await client.hset(f"user:refresh_token:{refresh_token[:106]}",mapping={
                                                                "refresh_token": encrypted_refresh_token,
                                                                "device_fingerprint":encrypyted_device_fingerprint,
                                                                "data":user_data['email'],
                                                                "session_id":encrypyted_session_id})
            await client.expire(f"user:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis
            
            create_new_log("info", f"user login successful: {existing_email}", "/api/backend/Auth")
            logger.info(f"user login successful: {existing_email}")
            return {"message": f"user login successful: {existing_email}", "status_code": status.HTTP_200_OK, "token_type": "Bearer", "email": cache_key, "access_token": access_token, "refresh_token": refresh_token}
        
        # Case 2: User NOT found ➡️ Check for Google phone
        people_api_url = "https://people.googleapis.com/v1/people/me?personFields=phoneNumbers"
        phone_response = await oauth.google_user.get(people_api_url, token=token)
        phone_data = phone_response.json()
        phone_numbers = phone_data.get("phoneNumbers", [])
        phone_number = phone_numbers[0]["value"] if phone_numbers else None

        if phone_number:
            # Create new user here with Google info and phone
            user_doc = {
                "email": user_data.get("email"),
                "first_name": user_data.get("name"),
                "full_name": user_data.get("name"),
                "phone_number": phone_number,
                "country_code": user_data.get("country_code", None),
                "UID": generate_random_string(),
                "created_at" : datetime.now().isoformat(),
                "verification_status": "false"
            }

            # Email validation
            if not google_user_email_bloom_filter.contains(user_doc["email"]):  # Check if email is definitely not present
                print("Email not in Bloom filter — safe to continue")
                # continue with signup
                return
            else:
                print("Bloom filter indicates possible existence — verifying with Redis and DB")

                # Double-check in Redis (temporary store, e.g., for recent signups or pending activation)
                email_in_redis = await client.hgetall(f"user:new_account:{user_doc['email']}")
                if email_in_redis:
                    print("Email found in Redis")
                    create_new_log("warning", f"Signup attempt with existing email: {user_doc['email']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing email: {user_doc['email']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
                else:
                    print("Email not found in Redis — checking MongoDB")
                    # Check in MongoDB (source of truth)
                    email = await mongo_client.auth.user.find_one({"email": user_doc["email"]})
                    if email:
                        print("Email found in MongoDB")
                        create_new_log("warning", f"Signup attempt with existing email: {user_doc['email']}", "/api/backend/Auth")
                        logger.warning(f"Signup attempt with existing email: {user_doc['email']}")
                        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

            print("Email is new — proceed with account creation")  # Email is confirmed to be new — proceed

            # Phone number validation
            if not google_user_phone_bloom_filter.contains(user_doc["phone_number"]):  # Check if phone number is definitely not present
                print("Phone number not in Bloom filter — safe to continue")
                # continue with signup
                return
            else:
                print("Bloom filter indicates possible existence — verifying with Redis and DB")

                # Double-check in Redis
                phone_number_in_redis = await client.hgetall(f"user:new_account:{user_doc['phone_number']}")
                if phone_number_in_redis:
                    print("Phone number found in Redis")
                    create_new_log("warning", f"Signup attempt with existing phone number: {user_doc['phone_number']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing phone number: {user_doc['phone_number']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already in use")
                else:
                    print("Phone number not found in Redis — checking MongoDB")
                    # Check in MongoDB
                    phone_number = await mongo_client.auth.user.find_one({"phone_number": user_doc["phone_number"]})
                    if phone_number:
                        print("Phone number found in MongoDB")
                        create_new_log("warning", f"Signup attempt with existing phone number: {user_doc['phone_number']}", "/api/backend/Auth")
                        logger.warning(f"Signup attempt with existing phone number: {user_doc['phone_number']}")
                        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Phone number already in use")

            print("Phone number is new — proceed with account creation")  # Phone number is confirmed to be new — proceed

            #  add email and phone number to bloom filters
            google_user_email_bloom_filter.add(user_doc["email"])
            google_user_phone_bloom_filter.add(user_doc["phone_number"])

        # ****************send data to kafka topic *****************
            producer.send(TOPIC_NAME, user_doc) # send data to kafka topic
            producer.flush() # flush the producer to ensure data is sent
            producer.send(TOPIC2_NAME, value={"UID":user_doc["UID"]}) # send data to kafka topic
            producer.flush() # flush the producer to ensure data is sent

            # await mongo_client.auth.user.insert_one(user_doc)  # this is done when kafka topic is consumed


            cache_key = user_doc["email"]
            await client.hset(f"user:new_account:{cache_key}",mapping=user_doc)
            await client.expire(f"user:new_account:{cache_key}", 691200) # expire in  7 days
            await client.hset(f"user:new_account:{phone_number}",mapping=user_doc)
            await client.expire(f"user:new_account:{phone_number}", 691200) # expire in 7 days
            #  for instant logging in after signup
            await client.set(f"user:auth:2_factor_login:{cache_key}", cache_key, ex=3600) # expire in 1 hour
            await client.set(f"user:auth:2_factor_login:{phone_number}", phone_number, ex=3600) # expire in 1 hour

            # html_path = "/root/SecureGate_Auth/authentication/templates/index.html" # -> for production
            html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
            with open(html_path,'r') as file:
                html_body = file.read()
            # send email verification link
            email_sent = send_email(user_data["email"], "Welcome to SecureGate. Lets build your health Profile", html_body, retries=3, delay=5)
            if not email_sent:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

            create_new_log("info", f"Auto-registered user during login: {user_doc['email']}", "/api/backend/Auth")
            logger.info(f"Auto-registered user during login: {user_doc['email']}")
            # Proceed to login as usual below
            
            access_token = create_access_token(data={"sub": cache_key})
            response.delete_cookie("access_token")
            response.set_cookie(key="access_token", value=access_token, max_age=3600)

            # refresh token logic
            device_fingerprint = generate_fingerprint_hash(request)
            session_id = create_session_id()
            refresh_token = auth_token.create_refresh_token(data={
                                                                    "sub": session_id,
                                                                    "data": device_fingerprint})
            response.delete_cookie("refresh_token")  # Remove old token
            response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
            encrypted_refresh_token = Hash.bcrypt(refresh_token)
            encrypyted_session_id = Hash.bcrypt(session_id)
            encrypyted_device_fingerprint = Hash.bcrypt(device_fingerprint)
            print(encrypted_refresh_token) # debug

            await client.hset(f"user:refresh_token:{refresh_token[:106]}",mapping={
                                                                "refresh_token": encrypted_refresh_token,
                                                                "device_fingerprint":encrypyted_device_fingerprint,
                                                                "data":user_data['email'],
                                                                "session_id":encrypyted_session_id})
            await client.expire(f"user:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

            return {"message": f"user auto-registered and logged in: {user_doc['email']}", "status_code": status.HTTP_200_OK, "token_type": "Bearer", "UID": user_doc["UID"], "created_at": user_doc["created_at"], "access_token": access_token, "refresh_token": refresh_token}
        
        else:
            # Case 3: No phone found ➡️ redirect to phone collection page
            request.session["email"] = user_data.get("email")
            request.session["name"] = user_data.get("name")
            return RedirectResponse(url="/user/phone_number_login")
    
    except OAuthError as e:
        create_new_log("error", f"OAuth Error: {str(e)}", "/api/backend/Auth")
        logger.exception(f"OAuth Error: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(status_code=400, detail="Authentication failed")
