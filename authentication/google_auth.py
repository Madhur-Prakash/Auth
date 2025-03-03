from fastapi import APIRouter, Request, status, HTTPException, Depends, BackgroundTasks
import traceback
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from authlib.integrations.starlette_client import OAuth, OAuthError
import aioredis
from .auth_token import create_access_token
import os
import jwt
from .database import mongo_client
from dotenv import load_dotenv
from .utils import setup_logging

google_auth = APIRouter(tags=["Google Authentication"])
# google_auth.mount("/authentication/static", StaticFiles(directory="static"), name="static")
load_dotenv()

GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")


# redis connection
# client = aioredis.from_url('redis://default@54.198.65.205:6379', decode_responses=True) #in production

client =  aioredis.from_url('redis://localhost', decode_responses=True) # in local testing

# initialize logger
logger = setup_logging() 

# OAuth Setup
oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    userinfo_endpoint="https://www.googleapis.com/oauth2/v3/userinfo",
    client_kwargs={"scope": "openid email profile"},
)

# ---- Doctor Signup ----
@google_auth.get("/doctor/google_signup")
async def doctor_google_signup(request: Request):
    redirect_uri = "http://127.0.0.1:8000/doctor/google_signup/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@google_auth.get("/doctor/google_signup/callback")
async def doctor_google_signup_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = await oauth.google.parse_id_token(request, token)

        # Check if user exists
        existing_user = await mongo_client.auth.patient.find_one({"email": user_info["email"]})
        if existing_user:
            raise HTTPException(status_code=400, detail="User already registered")

        # Save new doctor to DB
        new_user = {"email": user_info["email"], "name": user_info["name"], "role": "doctor"}
        await mongo_client.auth.patient.insert_one(new_user)

        # Generate JWT Token
        token = create_access_token({"sub": user_info["email"], "role": "doctor"})

        return RedirectResponse(url=f"/success?token={token}")
    except OAuthError as e:
        logger.error(f"OAuth Error: {str(e)}")
        # print(traceback.format_exc())
        raise HTTPException(status_code=400, detail="Authentication failed")

# ---- Patient Login ----
@google_auth.get("/patient/google_login")
async def patient_google_login(request: Request):
    redirect_uri = "http://127.0.0.1:8000/patient/google_login/callback"
    return await oauth.google.authorize_redirect(request, redirect_uri)

@google_auth.get("/patient/google_login/callback")
async def patient_google_login_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = await oauth.google.parse_id_token(request, token)

        # Check if user exists and is a patient
        user = await mongo_client.auth.patient.find_one({"email": user_info["email"]})
        if not user or user["role"] != "patient":
            raise HTTPException(status_code=403, detail="Unauthorized access")

        # Generate JWT Token
        token = create_access_token({"sub": user_info["email"], "role": "patient"})

        return RedirectResponse(url=f"/success?token={token}")
    except OAuthError as e:
        logger.error(f"OAuth Error: {str(e)}")
        # print(traceback.format_exc())
        raise HTTPException(status_code=400, detail="Authentication failed")
    

