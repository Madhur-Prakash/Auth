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
from ..config.redis import client
from ..helper.auth_token import create_access_token
import os
from ..otp_service.send_mail import send_email
from ..helper.hashing import Hash
from ..helper import auth_token
from fastapi.templating import Jinja2Templates
from ..config.database import mongo_client
from dotenv import load_dotenv

google_patient_auth = APIRouter(tags=["Google Authentication"])
# google_patient_auth.mount("/authentication/static", StaticFiles(directory="static"), name="static")
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

# initialize logger
logger = setup_logging() 

# OAuth Setup
oauth = OAuth()
oauth.register(
    name="google_patient",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    userinfo_endpoint="https://www.googleapis.com/oauth2/v3/userinfo",
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",  # Manually set JWKS URI
    client_kwargs={"scope": "openid email profile https://www.googleapis.com/auth/user.phonenumbers.read"}
)

async def cache_without_password(data: str):
    CachedData = await client.get(f'patient:auth:2_factor_login:{data}')
    if CachedData:
        print("Data is cached") # debug
        print(CachedData) # debug
        create_new_log("info", f"cache hit for {data}", "/api/backend/Auth")
        logger.info(f"cache hit for {data}") # log the cache hit
        return CachedData
  
    user = await mongo_client.auth.patient.find_one({"email": data}) # check if user exists in db
    if user:
        print("searching inside db") # debug
        await client.set(f"patient:auth:2_factor_login:{data}",data, ex=432000) # expire in 5 days
        return user
    create_new_log("warning", f"login attempt with invalid credentials: {data}", "/api/backend/Auth")
    logger.warning(f"login attempt with invalid credentials: {data}") # log the cache hit
    return None

TOPIC_NAME = 'patient_google_signups'
# ---- Patient Signup ----


@google_patient_auth.get("/patient")
async def index(request: Request):
    return templates.TemplateResponse("patient.html", {"request": request})


@google_patient_auth.get("/patient/google_signup")
async def patient_google_signup(request: Request):
    redirect_uri = "http://127.0.0.1:8000/patient/google_signup/callback"
    return await oauth.google_patient.authorize_redirect(request, redirect_uri)

@google_patient_auth.get("/patient/google_signup/callback")
async def patient_google_signup_callback(request: Request, response: Response):
    try:
        token = await oauth.google_patient.authorize_access_token(request)

        # Fetch basic user info
        response = await oauth.google_patient.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)
        user_info = response.json()

        # Fetch phone number separately from Google People API
        people_api_url = "https://people.googleapis.com/v1/people/me?personFields=phoneNumbers"
        phone_response = await oauth.google_patient.get(people_api_url, token=token)
        phone_data = phone_response.json()

        # Extract phone number safely
        phone_numbers = phone_data.get("phoneNumbers", [])
        phone_number = phone_numbers[0]["value"] if phone_numbers else None

        if not phone_number :
            request.session["email"] = user_info.get("email")
            request.session["name"] = user_info.get("name")
            return RedirectResponse(url = "/patient/phone_number")

        # User details
        user_data = {
            "email": user_info.get("email"),
            "first_name": user_info.get("name"),
            # "picture": user_info.get("picture"),
            # "locale": user_info.get("locale"),
            # "verified_email": user_info.get("email_verified"),
            "phone_number": phone_number,
            "country_code": user_info.get("country_code", None),
            "CIN": generate_random_string(),
            "created_at" : datetime.now().isoformat(),
            "verification_status": "false"

        }

        existing_email = await mongo_client.auth.patient.find_one({"email": user_data["email"]})
        email_in_redis = await client.get(f"patient:new_account:{user_data['email']}")
        existing_phone = await mongo_client.auth.patient.find_one({"phone_number": user_data["phone_number"]})
        phone_in_redis = await client.get(f"patient:new_account:{user_data['phone_number']}")

        if existing_email or email_in_redis:
            create_new_log("error", "signup attempt with existing email", "/api/backend/Auth")
            raise HTTPException(status_code=400, detail="Email already exists.")
        if existing_phone or phone_in_redis:
            create_new_log("error", "signup attempt with existing phone number", "/api/backend/Auth")
            raise HTTPException(status_code=400, detail="Phone number already exists.")

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

        # await mongo_client.auth.patient.insert_one(user_data)  # this is done when kafka topic is consumed

        # Generate a cache during signup with email as key
        cache_key = user_data["email"]
        await client.hset(f"patient:new_account:{cache_key}",mapping=user_data)
        await client.expire(f"patient:new_account:{cache_key}", 3600) # expire in 1 hour

        #  for instant logging in after signup
        await client.set(f"patient:auth:2_factor_login:{user_data['email']}", user_data["email"], ex=3600) # expire in 1 hour
        await client.set(f"patient:auth:2_factor_login:{user_data['phone_number']}", user_data["phone_number"], ex=3600) # expire in 1 hour

        # **** this was done previously to store data in redis cache ****
        # await client.hset(f"patient:new_account:{cache_key}", mapping=user_data)
        # await client.expire(f"patient:new_account:{cache_key}", 691200)  # expire in 7 days  

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

        await client.hset(f"patient:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":user_data['email'],
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"patient:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        # html_path = "/root/CuraDocs_Auth/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()
        # send email verification link
        email_sent = send_email(user_data["email"], "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")


        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        create_new_log("info", f"Account for patient created successfully: {user_data['email']}", "/api/backend/Auth")
        logger.info(f"Account for patient created successfully: {user_data['email']}")
        return {"message":f"Account for patient created successfully: {user_data['email']}"}

    except OAuthError as e:
        formatted_error = traceback.format_exc()
        create_new_log("error", f"OAuth Error: {str(e)}", "/api/backend/Auth")
        logger.exception(f"OAuth Error: {formatted_error}")
        raise HTTPException(status_code=400, detail="Authentication failed")

@google_patient_auth.post("/patient/phone_number/signup")
async def patient_phone_number_signup(data:models.google_login, request: Request, response: Response):
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
            "CIN": generate_random_string(),
            "created_at" : datetime.now().isoformat(),
            "verification_status": "false"
        }

        existing_email = await mongo_client.auth.patient.find_one({"email": user_data["email"]})
        email_in_redis = await client.get(f"patient:new_account:{user_data['email']}")
        existing_phone = await mongo_client.auth.patient.find_one({"phone_number": user_data["phone_number"]})
        phone_in_redis = await client.get(f"patient:new_account:{user_data['phone_number']}")

        if existing_email or email_in_redis:
            create_new_log("error", "signup attempt with existing email", "/api/backend/Auth")
            raise HTTPException(status_code=400, detail="Email already exists.")
        if existing_phone or phone_in_redis:
            create_new_log("error", "signup attempt with existing phone number", "/api/backend/Auth")
            raise HTTPException(status_code=400, detail="Phone number already exists.")

        # Insert user into the database
        user_data["full_name"] = user_data["first_name"] # last_name will be handeled when all other details of user will be taken
        updated_phone_number = phone_number + country_code
        country_name = get_country_name(updated_phone_number)
        country_name = country_name.lower()
        user_data["country_name"] = country_name

        # ****************send data to kafka topic *****************
        producer.send(TOPIC_NAME, user_data) # send data to kafka topic
        producer.flush() # flush the producer to ensure data is sent

        # await mongo_client.auth.patient.insert_one(user_data) # this is done when kafka topic is consumed

        cache_key = user_data["email"]
        await client.hset(f"patient:new_account:{cache_key}",mapping=user_data)
        await client.expire(f"patient:new_account:{cache_key}", 3600) # expire in 1 hour

        #  for instant logging in after signup
        await client.set(f"patient:auth:2_factor_login:{user_data['email']}", user_data["email"], ex=3600) # expire in 1 hour
        await client.set(f"patient:auth:2_factor_login:{user_data['phone_number']}", user_data["phone_number"], ex=3600) # expire in 1 hour

        # **** this was done previously to store data in redis cache ****
        # await client.hset(f"patient:new_account:{cache_key}", mapping=user_data)
        # await client.expire(f"patient:new_account:{cache_key}", 691200)  # expire in 7 days 

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

        await client.hset(f"patient:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":user_data['email'],
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"patient:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        # html_path = "/root/CuraDocs_Auth/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()
        # send email verification link
        email_sent = send_email(user_data["email"], "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        create_new_log("info", f"Account for patient created successfully: {user_data['email']}", "/api/backend/Auth")
        logger.info(f"Account for patient created successfully: {user_data['email']}")
        return {"message":f"Account for patient created successfully: {user_data['email']}"}
    
    except Exception as e:
        formatted_error = traceback.format_exc()
        print(f"Error: {str(e)}")
        create_new_log("error", f"Signup attempt failed: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Signup attempt failed: {str(e)}")
        raise HTTPException(status_code=400, detail="Internal server error")

# Phone Number Entry Page (GET)
@google_patient_auth.get("/patient/phone_number")
async def phone_number_page(request: Request):
    return templates.TemplateResponse("phone_number.html", {"request": request, "type": "patient"})


# ---- Patient Login ----
@google_patient_auth.get("/patient/google_login")
async def patient_google_login(request: Request):
    redirect_uri = "http://127.0.0.1:8000/patient/google_login/callback"
    return await oauth.google_patient.authorize_redirect(request, redirect_uri)

@google_patient_auth.get("/patient/phone_number_login")
async def phone_number_page_login(request: Request):
    return templates.TemplateResponse("phone_number.html", {"request": request, "type": "patient", "flow": "login"})

@google_patient_auth.post("/patient/phone_number/login")
async def patient_phone_number_login(data: models.google_login, request: Request, response: Response):
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
            "CIN": generate_random_string(),
            "created_at": datetime.now().isoformat(),
            "verification_status": "false"
        }

        existing_phone = await mongo_client.auth.patient.find_one({"phone_number": new_user["phone_number"]})
        phone_in_redis = await client.get(f"patient:new_account:{new_user['phone_number']}")

        if phone_in_redis or existing_phone:
            create_new_log("error", "signup attempt with existing phone number", "/api/backend/Auth")
            raise HTTPException(status_code=400, detail="Phone number already exists.")

        updated_phone_number = phone_number + country_code
        country_name = get_country_name(updated_phone_number)
        country_name = country_name.lower()
        new_user["country_name"] = country_name

        # ****************send data to kafka topic *****************
        producer.send(TOPIC_NAME, new_user) # send data to kafka topic
        producer.flush() # flush the producer to ensure data is sent

        # await mongo_client.auth.patient.insert_one(new_user)  # this is done when kafka topic is consumed

        cache_key = new_user["email"]
        await client.hset(f"patient:new_account:{cache_key}",mapping={
            "email": cache_key})
        await client.expire(f"patient:new_account:{cache_key}", 3600) # expire in 1 hour

         #  for instant logging in after signup
        await client.set(f"patient:auth:2_factor_login:{new_user['email']}", new_user["email"], ex=3600) # expire in 1 hour
        await client.set(f"patient:auth:2_factor_login:{new_user['phone_number']}", new_user["phone_number"], ex=3600) # expire in 1 hour

        # ***** this was done previously to store data in redis cache *****
        # await client.hset(f"patient:new_account:{cache_key}", mapping=new_user)
        # await client.expire(f"patient:new_account:{cache_key}", 691200)  # expire in 7 days 
        
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

        await client.hset(f"patient:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":new_user['email'],
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"patient:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        # html_path = "/root/CuraDocs_Auth/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()
        # send email verification link
        email_sent = send_email(new_user["email"], "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

        access_token = create_access_token(data={"sub": new_user["email"]})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        create_new_log("info", f"Account for patient created successfully: {new_user['email']}", "/api/backend/Auth")
        logger.info(f"Account for patient created successfully: {new_user['email']}")
        return {"message":f"Account for patient created successfully: {new_user['email']}"}

    except Exception as e:
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Login attempt failed: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Login attempt failed: {str(e)}")
        raise HTTPException(status_code=400, detail="Internal server error")



@google_patient_auth.get("/patient/google_login/callback")
async def patient_google_login_callback(request: Request, response: Response):
    try:
        token = await oauth.google_patient.authorize_access_token(request)
        user_info = await oauth.google_patient.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)
        user_data = user_info.json()

        # Check if user exists in the database
        existing_email = cache_without_password(user_data.get("email"))
        if existing_email: # Case 1: User exists ➡️ Login

            # Generate access token
            cache_key = existing_email["email"]
            await client.set(f"patient:new_account:{cache_key}", cache_key, ex=3600) 
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

            await client.hset(f"patient:refresh_token:{refresh_token[:106]}",mapping={
                                                                "refresh_token": encrypted_refresh_token,
                                                                "device_fingerprint":encrypyted_device_fingerprint,
                                                                "data":user_data['email'],
                                                                "session_id":encrypyted_session_id})
            await client.expire(f"patient:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis
            
            create_new_log("info", f"Patient login successful: {existing_email['email']}", "/api/backend/Auth")
            logger.info(f"patient login successful: {existing_email['email']}")
            return {"message": f"patient login successful: {existing_email['email']}"}
        
        # Case 2: User NOT found ➡️ Check for Google phone
        people_api_url = "https://people.googleapis.com/v1/people/me?personFields=phoneNumbers"
        phone_response = await oauth.google_patient.get(people_api_url, token=token)
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
                "CIN": generate_random_string(),
                "created_at" : datetime.now().isoformat(),
                "verification_status": "false"
            }

            existing_phone = await mongo_client.auth.patient.find_one({"phone_number": user_doc["phone_number"]})
            phone_in_redis = await client.get(f"patient:new_account:{user_doc['phone_number']}")

            if existing_phone or phone_in_redis:
                create_new_log("error", "signup attempt with existing phone number", "/api/backend/Auth")
                raise HTTPException(status_code=400, detail="Phone number already exists.")

        # ****************send data to kafka topic *****************
            producer.send(TOPIC_NAME, user_doc) # send data to kafka topic
            producer.flush() # flush the producer to ensure data is sent

            # await mongo_client.auth.patient.insert_one(user_doc)  # this is done when kafka topic is consumed


            cache_key = user_doc["email"]
            await client.hset(f"patient:new_account:{cache_key}",mapping=user_doc)
            await client.expire(f"patient:new_account:{cache_key}", 3600) # expire in 1 hour

            #  for instant logging in after signup
            await client.set(f"patient:auth:2_factor_login:{user_doc['email']}", user_doc["email"], ex=3600) # expire in 1 hour
            await client.set(f"patient:auth:2_factor_login:{user_doc['phone_number']}", user_doc["phone_number"], ex=3600) # expire in 1 hour

            # **** this was done previously to store data in redis cache ****
            # await client.hset(f"patient:new_account:{cache_key}", mapping=user_doc)
            # await client.expire(f"patient:new_account:{cache_key}", 691200)  # expire in 7 days 

            # html_path = "/root/CuraDocs_Auth/authentication/templates/index.html" # -> for production
            html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
            with open(html_path,'r') as file:
                html_body = file.read()
            # send email verification link
            email_sent = send_email(user_data["email"], "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
            if not email_sent:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

            create_new_log("info", f"Auto-registered patient during login: {user_doc['email']}", "/api/backend/Auth")
            logger.info(f"Auto-registered patient during login: {user_doc['email']}")
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

            await client.hset(f"patient:refresh_token:{refresh_token[:106]}",mapping={
                                                                "refresh_token": encrypted_refresh_token,
                                                                "device_fingerprint":encrypyted_device_fingerprint,
                                                                "data":user_data['email'],
                                                                "session_id":encrypyted_session_id})
            await client.expire(f"patient:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

            return {"message": f"patient auto-registered and logged in: {user_doc['email']}"}
        
        else:
            # Case 3: No phone found ➡️ redirect to phone collection page
            request.session["email"] = user_data.get("email")
            request.session["name"] = user_data.get("name")
            return RedirectResponse(url="/patient/phone_number_login")
    
    except OAuthError as e:
        create_new_log("error", f"OAuth Error: {str(e)}", "/api/backend/Auth")
        logger.exception(f"OAuth Error: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(status_code=400, detail="Authentication failed")
