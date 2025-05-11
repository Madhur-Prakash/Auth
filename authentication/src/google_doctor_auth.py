from fastapi import APIRouter, Request, status, HTTPException, Depends, Response
import traceback
from datetime import datetime
from ..models import models
from ..config.database import mongo_client
from ..helper.utils import create_session_id, create_new_log, generate_fingerprint_hash, get_country_name, generate_random_string, setup_logging
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth, OAuthError
from ..config.redis_config import client
from ..helper.auth_token import create_access_token
import os
from ..otp_service.send_mail import send_email
from ..helper.hashing import Hash
from ..helper import auth_token
from fastapi.templating import Jinja2Templates
from ..config.database import mongo_client
from dotenv import load_dotenv

google_doctor_auth = APIRouter(tags=["Google Authentication"])
# google_doctor_auth.mount("/authentication/static", StaticFiles(directory="static"), name="static")
load_dotenv()

GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
SECRET_KEY = os.getenv("SECRET_KEY")

templates = Jinja2Templates(directory="authentication/templates")


async def cache_without_password(data: str):
    CachedData = await client.get(f'doctor:auth:2_factor_login:{data}')
    if CachedData:
        print("Data is cached") # debug
        print(CachedData) # debug
        create_new_log("info", f"cache hit for {data}", "/api/backend/Auth")
        logger.info(f"cache hit for {data}") # log the cache hit
        return CachedData
  
    user = await mongo_client.auth.doctor.find_one({"email": data}) # check if user exists in db
    if user:
        print("searching inside db") # debug
        await client.set(f"doctor:auth:2_factor_login:{data}",data, ex=432000) # expire in 5 days
        create_new_log("info", f"cache hit for {data}", "/api/backend/Auth")
        logger.info(f"cache hit for {data}") # log the cache hit
        return user
    create_new_log("warning", f"login attempt with invalid credentials: {data}", "/api/backend/Auth")
    logger.warning(f"login attempt with invalid credentials: {data}") # log the cache hit
    return None

# initialize logger
logger = setup_logging() 

# OAuth Setup
oauth = OAuth()
# oauth.register(
oauth.register(
    name="google_doctor",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    userinfo_endpoint="https://www.googleapis.com/oauth2/v3/userinfo",
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",  # Manually set JWKS URI
    client_kwargs={"scope": "openid email profile https://www.googleapis.com/auth/user.phonenumbers.read"}
)



@google_doctor_auth.get("/doctor")
async def index(request: Request):
    return templates.TemplateResponse("doctor.html", {"request": request})

# ---- Doctor Signup ----
@google_doctor_auth.get("/doctor/google_signup")
async def doctor_google_signup(request: Request):
    redirect_uri = "http://127.0.0.1:8000/doctor/google_signup/callback"
    return await oauth.google_doctor.authorize_redirect(request, redirect_uri)

@google_doctor_auth.get("/doctor/google_signup/callback")
async def doctor_google_signup_callback(request: Request, response: Response):
    try:
        token = await oauth.google_doctor.authorize_access_token(request)

        # Fetch basic user info
        response = await oauth.google_doctor.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)
        user_info = response.json()

        # Fetch phone number separately from Google People API
        people_api_url = "https://people.googleapis.com/v1/people/me?personFields=phoneNumbers"
        phone_response = await oauth.google_doctor.get(people_api_url, token=token)
        phone_data = phone_response.json()

        # Extract phone number safely
        phone_numbers = phone_data.get("phoneNumbers", [])
        phone_number = phone_numbers[0]["value"] if phone_numbers else None

        if not phone_number :
            request.session["email"] = user_info.get("email")
            request.session["name"] = user_info.get("name")
            return RedirectResponse(url = "/doctor/phone_number")

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

        existing_email = await mongo_client.auth.doctor.find_one({"email": user_data["email"]})
        email_in_redis = await client.hgetall(f"doctor:new_account:{user_data['email']}")
        existing_phone = await mongo_client.auth.doctor.find_one({"phone_number": user_data["phone_number"]})
        phone_in_redis = await client.hgetall(f"doctor:new_account:{user_data['phone_number']}")

        if existing_email or email_in_redis:
            create_new_log("error", f"signup attempt with existing email: {user_data['email']}", "/api/backend/Auth")
            raise HTTPException(status_code=400, detail="Email already exists.")
        if existing_phone or phone_in_redis:
            create_new_log("error", f"signup attempt with existing phone number: {user_data['phone_number']}", "/api/backend/Auth")
            raise HTTPException(status_code=400, detail="Phone number already exists.")

        # if phone number was fetched then insert the user into the database and create a JWT token
        user_data["full_name"] = user_data["first_name"]  # last_name will be handeled when all other details of user will be taken
        if user_data["country_code"] is not None:
            updated_phone_number = user_data["phone_number"] + user_data["country_code"]
            country_name = get_country_name(updated_phone_number)
            country_name = country_name.lower()
            user_data["country_name"] = country_name

        # await mongo_client.auth.doctor.insert_one(user_data) -> now data goes in cache

        # Generate a cache during signup with email as key
        cache_key = user_data["email"]
        await client.hset(f"doctor:new_account:{cache_key}", mapping=user_data)
        await client.expire(f"doctor:new_account:{cache_key}", 691200)  # expire in 7 days 
        await client.hset(f"doctor:new_account:{user_data['phone_number']}", mapping=user_data)
        await client.expire(f"doctor:new_account:{user_data['phone_number']}", 691200)  # expire in 7 days

        #  for instant logging in after signup
        await client.set(f"doctor:auth:2_factor_login:{user_data['email']}", user_data["email"], ex=3600) # expire in 1 hour
        await client.set(f"doctor:auth:2_factor_login:{user_data['phone_number']}", user_data["phone_number"], ex=3600) # expire in 1 hour

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

        await client.hset(f"doctor:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":user_data['email'],
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"doctor:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        # html_path = "/root/CuraDocs_Auth/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()
        # send email verification link
        email_sent = send_email(user_data["email"], "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")


        await client.set(f"doctor:{cache_key}",cache_key,ex=3600) 
        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        create_new_log("info", f"Account for doctor created successfully: {user_data['email']}", "/api/backend/Auth")
        logger.info(f"Account for doctor created successfully: {user_data['email']}")
        return {"message":f"Account for doctor created successfully: {user_data['email']}", "status_code": status.HTTP_201_CREATED, "token_type": "Bearer"}

    except OAuthError as e:
        formatted_error = (traceback.format_exc())
        create_new_log("error", f"OAuth Error: {str(e)}", "/api/backend/Auth")
        logger.exception(f"OAuth Error: {formatted_error}")
        raise HTTPException(status_code=400, detail="Authentication failed")

@google_doctor_auth.post("/doctor/phone_number/signup")
async def doctor_phone_number_signup(data:models.google_login, request: Request, response: Response):
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

        existing_email = await mongo_client.auth.doctor.find_one({"email": user_data["email"]})
        email_in_redis = await client.hgetall(f"doctor:new_account:{user_data['email']}")
        existing_phone = await mongo_client.auth.doctor.find_one({"phone_number": user_data["phone_number"]})
        phone_in_redis = await client.hgetall(f"doctor:new_account:{user_data['phone_number']}")
        if existing_email or email_in_redis:
            create_new_log("error", f"signup attempt with existing email: {user_data['email']}", "/api/backend/Auth")
            raise HTTPException(status_code=400, detail="Email already exists.")
        if existing_phone or phone_in_redis:
            create_new_log("error", f"signup attempt with existing phone number: {user_data['phone_number']}", "/api/backend/Auth")
            raise HTTPException(status_code=400, detail="Phone number already exists.")

        # Insert user into the database
        user_data["full_name"] = user_data["first_name"] # last_name will be handeled when all other details of user will be taken
        updated_phone_number = phone_number + country_code
        country_name = get_country_name(updated_phone_number)
        country_name = country_name.lower()
        user_data["country_name"] = country_name
        # await mongo_client.auth.doctor.insert_one(user_data) -> now data goes in cache

        # Generate a cache during signup with email as key
        cache_key = user_data["email"]
        await client.hset(f"doctor:new_account:{cache_key}", mapping=user_data)
        await client.expire(f"doctor:new_account:{cache_key}", 691200)  # expire in 7 days 
        await client.hset(f"doctor:new_account:{user_data['phone_number']}", mapping=user_data)
        await client.expire(f"doctor:new_account:{user_data['phone_number']}", 691200)  # expire in 7 days

        #  for instant logging in after signup
        await client.set(f"doctor:auth:2_factor_login:{user_data['email']}", user_data["email"], ex=3600) # expire in 1 hour
        await client.set(f"doctor:auth:2_factor_login:{user_data['phone_number']}", user_data["phone_number"], ex=3600) # expire in 1 hour


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

        await client.hset(f"doctor:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":user_data['email'],
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"doctor:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        await client.set(f"doctor:{cache_key}",cache_key,ex=3600) 
        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)

        # html_path = "/root/CuraDocs_Auth/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()
        # send email verification link
        email_sent = send_email(user_data["email"], "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

        create_new_log("info", f"Account for doctor created successfully: {user_data['email']}", "/api/backend/Auth")
        logger.info(f"Account for doctor created successfully: {user_data['email']}")
        return {"message":f"Account for doctor created successfully: {user_data['email']}", "status_code": status.HTTP_201_CREATED, "token_type": "Bearer"}
    
    except Exception as e:
        formatted_error = (traceback.format_exc())
        create_new_log("error", f"Signup attempt failed: {str(e)}", "/api/backend/Auth")
        logger.error(f"Signup attempt failed: {formatted_error}")
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=400, detail="Internal server error")

# Phone Number Entry Page (GET)
@google_doctor_auth.get("/doctor/phone_number")
async def phone_number_page(request: Request):
    return templates.TemplateResponse("phone_number.html", {"request": request, "type": "doctor"})


# ---- Doctor Login ----
@google_doctor_auth.get("/doctor/google_login")
async def doctor_google_login(request: Request):
    redirect_uri = "http://127.0.0.1:8000/doctor/google_login/callback"
    return await oauth.google_doctor.authorize_redirect(request, redirect_uri)

@google_doctor_auth.get("/doctor/phone_number_login")
async def phone_number_page_login(request: Request):
    return templates.TemplateResponse("phone_number.html", {"request": request, "type": "doctor", "flow": "login"})

@google_doctor_auth.post("/doctor/phone_number/login")
async def doctor_phone_number_login(data: models.google_login, request: Request, response: Response):
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
            "phone_number": phone_number,
            "country_code": country_code,
            "CIN": generate_random_string(),
            "created_at": datetime.now().isoformat(),
            "verification_status": "false"
        }

        existing_phone = await mongo_client.auth.doctor.find_one({"phone_number": phone_number})
        phone_number_in_redis = await client.hgetall(f"doctor:new_account:{phone_number}")

        if existing_phone or phone_number_in_redis:
            create_new_log("error", f"signup attempt with existing phone number: {phone_number}", "/api/backend/Auth")
            raise HTTPException(status_code=400, detail="Phone number already exists.")


        new_user["full_name"] = new_user["first_name"]  # last_name will be handeled when all other details of user will be taken
        updated_phone_number = phone_number + country_code
        country_name = get_country_name(updated_phone_number)
        country_name = country_name.lower()
        new_user["country_name"] = country_name
        # await mongo_client.auth.doctor.insert_one(new_user) -> now data goes in cache
       
       
        cache_key = new_user["email"]
        await client.hset(f"doctor:new_account:{cache_key}", mapping=new_user)
        await client.expire(f"doctor:new_account:{cache_key}", 691200)  # expire in 7 days 
        await client.hset(f"doctor:new_account:{phone_number}", mapping=new_user)
        await client.expire(f"doctor:new_account:{phone_number}", 691200)  # expire in 7 days

        #  for instant logging in after signup
        await client.set(f"doctor:auth:2_factor_login:{cache_key}", cache_key, ex=3600) # expire in 1 hour
        await client.set(f"doctor:auth:2_factor_login:{phone_number}", phone_number, ex=3600) # expire in 1 hour

        
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

        await client.hset(f"doctor:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":new_user['email'],
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"doctor:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        # Generate a cache during signup with email as key
        await client.set(f"doctor:{cache_key}",cache_key,ex=3600) 
        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)

        # html_path = "/root/CuraDocs_Auth/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()
        # send email verification link
        email_sent = send_email(new_user["email"], "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

        create_new_log("info", f"Account for doctor created successfully: {new_user['email']}", "/api/backend/Auth")
        logger.info(f"Account for doctor created successfully: {new_user['email']}")
        return {"message":f"Account for doctor created successfully: {new_user['email']}", "status_code": status.HTTP_201_CREATED, "token_type": "Bearer"}

    except Exception as e:
        formatted_error = (traceback.format_exc())
        create_new_log("error", f"signup attempt failed: {formatted_error}", "/api/backend/Auth")
        logger.error(f"signup attempt failed: {formatted_error}")
        raise HTTPException(status_code=400, detail="signup attempt failed")



@google_doctor_auth.get("/doctor/google_login/callback")
async def doctor_google_login_callback(request: Request, response: Response):
    try:
        token = await oauth.google_doctor.authorize_access_token(request)
        user_info = await oauth.google_doctor.get("https://openidconnect.googleapis.com/v1/userinfo", token=token)
        user_data = user_info.json()

        existing_email = user_data.get("email")

        # Check if user exists in the database
        existing_account = cache_without_password(existing_email)
        if existing_account: # Case 1: User exists ➡️ Login

            # Generate access token
            cache_key = existing_email
            await client.set(f"doctor:auth:2_factor_login:{cache_key}", cache_key, ex=3600) 
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

            await client.hset(f"doctor:refresh_token:{refresh_token[:106]}",mapping={
                                                                "refresh_token": encrypted_refresh_token,
                                                                "device_fingerprint":encrypyted_device_fingerprint,
                                                                "data":user_data['email'],
                                                                "session_id":encrypyted_session_id})
            await client.expire(f"doctor:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

            create_new_log("info", f"Doctor login successful: {cache_key}", "/api/backend/Auth")
            logger.info(f"Doctor login successful: {cache_key}")
            return {"message": f"Doctor login successful: {cache_key}", "status_code": status.HTTP_200_OK, "token_type": "Bearer"}
        
        # Case 2: User NOT found ➡️ Check for Google phone
        people_api_url = "https://people.googleapis.com/v1/people/me?personFields=phoneNumbers"
        phone_response = await oauth.google_doctor.get(people_api_url, token=token)
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

            existing_phone = await mongo_client.auth.doctor.find_one({"phone_number": user_doc["phone_number"]})
            phone_in_redis = await client.hgetall(f"doctor:new_account:{user_doc['phone_number']}")

            if phone_in_redis or existing_phone:
                create_new_log("error", f"signup attempt with existing phone number: {user_doc['phone_number']}", "/api/backend/Auth")
                raise HTTPException(status_code=400, detail="Phone number already exists.")

            if user_doc["country_code"] is not None:
                updated_phone_number = phone_number + user_data["country_code"]
                country_name = get_country_name(updated_phone_number)
                country_name = country_name.lower()
                user_doc["country_name"] = country_name
            
            # Generate a cache during signup with email as key
            cache_key = user_doc["email"]

            # await mongo_client.auth.doctor.insert_one(user_doc) -> now data goes in cache
            await client.hset(f"doctor:new_account:{cache_key}", mapping=user_doc)
            await client.expire(f"doctor:new_account:{cache_key}", 691200)  # expire in 7 days 
            await client.hset(f"doctor:new_account:{user_doc['phone_number']}", mapping=user_doc)
            await client.expire(f"doctor:new_account:{user_doc['phone_number']}", 691200)  # expire in 7 days

            #  for instant logging in after signup
            await client.set(f"doctor:auth:2_factor_login:{user_doc['email']}", user_doc["email"], ex=3600) # expire in 1 hour
            await client.set(f"doctor:auth:2_factor_login:{user_doc['phone_number']}", user_doc["phone_number"], ex=3600) # expire in 1 hour
            
            # html_path = "/root/CuraDocs_Auth/authentication/templates/index.html" # -> for production
            html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
            with open(html_path,'r') as file:
                html_body = file.read()
            # send email verification link
            email_sent = send_email(user_data["email"], "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
            if not email_sent:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

            create_new_log("info", f"Auto-registered doctor during login: {user_doc['email']}", "/api/backend/Auth")
            logger.info(f"Auto-registered doctor during login: {user_doc['email']}")
            # Proceed to login as usual below
            await client.set(f"auth:doctor:{cache_key}", cache_key, ex=3600) 
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

            await client.hset(f"doctor:refresh_token:{refresh_token[:106]}",mapping={
                                                                "refresh_token": encrypted_refresh_token,
                                                                "device_fingerprint":encrypyted_device_fingerprint,
                                                                "data":user_data['email'],
                                                                "session_id":encrypyted_session_id})
            await client.expire(f"doctor:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

            return {"message": f"Doctor auto-registered and logged in: {user_doc['email']}", "status_code": status.HTTP_200_OK, "token_type": "Bearer"}
        
        else:
            # Case 3: No phone found ➡️ redirect to phone collection page
            request.session["email"] = user_data.get("email")
            request.session["name"] = user_data.get("name")
            return RedirectResponse(url="/doctor/phone_number_login")
    
    except OAuthError as e:
        formatted_error = (traceback.format_exc())
        create_new_log("error", f"OAuth Error: {str(e)}", "/api/backend/Auth")
        logger.exception(f"OAuth Error: {formatted_error}")
        print(formatted_error)
        raise HTTPException(status_code=400, detail="Authentication failed")
