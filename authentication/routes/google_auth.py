from fastapi import APIRouter, Request, status
from fastapi.responses import Response
from ..src import google_auth_manager
from ..models import models

auth_google_router = APIRouter(tags=["Google Authentication"], prefix="/google/user") # create a router for google auth

@auth_google_router.get("/", status_code=status.HTTP_200_OK)
async def home_page(request: Request):
    return google_auth_manager.index(request)

@auth_google_router.get("/google_signup")
async def google_signup(request: Request):
    return await google_auth_manager.user_google_signup(request)

@auth_google_router.get("/google_signup/callback")
async def google_signup_callback(request: Request, response: Response):
    return await google_auth_manager.user_google_signup_callback(request, response)

@auth_google_router.post("/phone_number/signup")
async def google_phone_number_signup(data: models.google_login, response: Response, request: Request):
    return await google_auth_manager.user_google_phone_number_signup(data, response, request)

# Phone Number Entry Page (GET)
@auth_google_router.get("/phone_number")
async def user_phone_number_page(request: Request):
    return await google_auth_manager.phone_number_page(request)

# ---- user Login ----
@auth_google_router.get("/google_login")
async def google_login(request: Request):
    return await google_auth_manager.user_google_login(request)

@auth_google_router.get("/phone_number_login")
async def user_phone_number_page_login(request: Request):
    return await google_auth_manager.phone_number_page_login(request)

@auth_google_router.post("/phone_number/login")
async def user_phone_login(data: models.google_login, request: Request, response: Response):
    return await google_auth_manager.user_phone_number_login(data, request, response)

@auth_google_router.get("/google_login/callback")
async def google_login_callback(request: Request, response: Response):
    return await google_auth_manager.user_google_login_callback(request, response)