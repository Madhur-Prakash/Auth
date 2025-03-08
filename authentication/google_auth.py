from fastapi import APIRouter, Request, status, HTTPException, Depends, Response
import traceback
from datetime import datetime
from .database import mongo_client
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth, OAuthError
import aioredis
from .auth_token import create_access_token
import os
from fastapi.templating import Jinja2Templates
from .database import mongo_client
from dotenv import load_dotenv
from .utils import setup_logging, generate_random_string

google_auth = APIRouter(tags=["Google Authentication"])
# google_auth.mount("/authentication/static", StaticFiles(directory="static"), name="static")
load_dotenv()

GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
SECRET_KEY = os.getenv("SECRET_KEY")

templates = Jinja2Templates(directory="authentication/templates")

# redis connection
# client = aioredis.from_url('redis://default@54.198.65.205:6379', decode_responses=True) #in production

client =  aioredis.from_url('redis://localhost', decode_responses=True) # in local testing

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




@google_auth.get("/patient")
async def index(request: Request):
    return templates.TemplateResponse("patient.html", {"request": request})

@google_auth.get("/doctor")
async def index(request: Request):
    return templates.TemplateResponse("doctor.html", {"request": request})

# ---- Doctor Signup ----
@google_auth.get("/doctor/google_signup")
async def doctor_google_signup(request: Request):
    redirect_uri = "http://127.0.0.1:8000/doctor/google_signup/callback"
    return await oauth.google_doctor.authorize_redirect(request, redirect_uri)

@google_auth.get("/doctor/google_signup/callback")
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
            "full_name": user_info.get("name"),
            # "picture": user_info.get("picture"),
            # "locale": user_info.get("locale"),
            # "verified_email": user_info.get("email_verified"),
            "phone_number": phone_number,
            "CIN": generate_random_string(),
            "created_at" : datetime.now().isoformat()
        }

        existing_email = await mongo_client.auth.doctor.find_one({"email": user_data["email"]})
        existing_phone = await mongo_client.auth.doctor.find_one({"phone_number": user_data["phone_number"]})
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already exists.")
        if existing_phone:
            raise HTTPException(status_code=400, detail="Phone number already exists.")

        # if phone number was fetched then insert the user into the database and create a JWT token
        await mongo_client.auth.doctor.insert_one(user_data)
        logger.info(f"Account for doctor created successfully: {user_data['email']}")
        # Generate a cache during signup with email as key
        cache_key = user_data["email"]
        cached_data = await client.set(f"doctor:{cache_key}",cache_key,ex=3600) 
        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        return {"message":f"Account for doctor created successfully: {user_data['email']}"}

    except OAuthError as e:
        logger.error(f"OAuth Error: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(status_code=400, detail="Authentication failed")

@google_auth.post("/doctor/phone_number/signup")
async def doctor_phone_number_signup(request: Request, response: Response):
    try:
        data = await request.json()
        phone_number = data.get("phone_number")

        # retrieve  email and name from session
        email = request.session.get("email")
        name = request.session.get("name")
        if not email or not name:
            raise HTTPException(status_code=400, detail="Session expired. Please Signup again.")
        
        user_data = {
            "email": email,
            "full_name": name,
            "phone_number": phone_number,
            "CIN": generate_random_string(),
            "created_at" : datetime.now().isoformat()
        }

        existing_email = await mongo_client.auth.doctor.find_one({"email": user_data["email"]})
        existing_phone = await mongo_client.auth.doctor.find_one({"phone_number": user_data["phone_number"]})
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already exists.")
        if existing_phone:
            raise HTTPException(status_code=400, detail="Phone number already exists.")

        # Insert user into the database
        await mongo_client.auth.doctor.insert_one(user_data)
        logger.info(f"Account for doctor created successfully: {user_data['email']}")
        # Generate a cache during signup with email as key
        cache_key = user_data["email"]
        cached_data = await client.set(f"doctor:{cache_key}",cache_key,ex=3600) 
        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        return {"message":f"Account for doctor created successfully: {user_data['email']}"}
    
    except Exception as e:
        print(f"Error: {traceback.format_exc()}")
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=400, detail="Internal server error")

# Phone Number Entry Page (GET)
@google_auth.get("/doctor/phone_number")
async def phone_number_page(request: Request):
    return templates.TemplateResponse("phone_number.html", {"request": request, "type": "doctor"})




# ---- patient signup ----
@google_auth.get("/patient/google_signup")
async def patient_google_signup(request: Request):
    redirect_uri = "http://127.0.0.1:8000/patient/google_signup/callback"
    return await oauth.google_patient.authorize_redirect(request, redirect_uri)

@google_auth.get("/patient/google_signup/callback")
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
            "full_name": user_info.get("name"),
            # "picture": user_info.get("picture"),
            # "locale": user_info.get("locale"),
            # "verified_email": user_info.get("email_verified"),
            "phone_number": phone_number,
            "CIN": generate_random_string(),
            "created_at" : datetime.now().isoformat()
        }

        existing_email = await mongo_client.auth.patient.find_one({"email": user_data["email"]})
        existing_phone = await mongo_client.auth.patient.find_one({"phone_number": user_data["phone_number"]})
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already exists.")
        if existing_phone:
            raise HTTPException(status_code=400, detail="Phone number already exists.")

        # if phone number was fetched then insert the user into the database and create a JWT token
        await mongo_client.auth.patient.insert_one(user_data)
        logger.info(f"Account for patient created successfully: {user_data['email']}")
        # Generate a cache during signup with email as key
        cache_key = user_data["email"]
        cached_data = await client.set(f"patient:{cache_key}",cache_key,ex=3600) 
        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        return {"message":f"Account for patient created successfully: {user_data['email']}"}

    except OAuthError as e:
        logger.error(f"OAuth Error: {str(e)}")
        print(traceback.format_exc())
        raise HTTPException(status_code=400, detail="Authentication failed")

@google_auth.post("/patient/phone_number/signup")
async def patient_phone_number_signup(request: Request, response: Response):
    try:
        data = await request.json()
        phone_number = data.get("phone_number")

        # retrieve  email and name from session
        email = request.session.get("email")
        name = request.session.get("name")
        if not email or not name:
            raise HTTPException(status_code=400, detail="Session expired. Please Signup again.")
        
        user_data = {
            "email": email,
            "full_name": name,
            "phone_number": phone_number,
            "CIN": generate_random_string(),
            "created_at" : datetime.now().isoformat()
        }

        # Insert user into the database
        await mongo_client.auth.patient.insert_one(user_data)
        logger.info(f"Account for patient created successfully: {user_data['email']}")
        # Generate a cache during signup with email as key
        cache_key = user_data["email"]
        cached_data = await client.set(f"patient:{cache_key}",cache_key,ex=3600) 
        access_token = create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        return {"message":f"Account for patient created successfully: {user_data['email']}"}
    
    except Exception as e:
        print(f"Error: {traceback.format_exc()}")
        print(f"Error: {str(e)}")
        raise HTTPException(status_code=400, detail="Internal server error")

# Phone Number Entry Page (GET)
@google_auth.get("/patient/phone_number")
async def phone_number_page(request: Request):
    return templates.TemplateResponse("phone_number.html", {"request": request, "type": "patient"})




    

