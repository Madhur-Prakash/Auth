from fastapi import APIRouter, Request, status
from fastapi.responses import Response
from ..src import auth_manager
from ..models import models

auth_user_router = APIRouter(tags=["user Authentication"], prefix="/user") # create a router for user


@auth_user_router.post("/signup", status_code=status.HTTP_201_CREATED)
async def user_signup(data: models.user, response: Response, request: Request):
    return await auth_manager.signup(data, response, request)

@auth_user_router.post("/signup/send_otp", status_code=status.HTTP_200_OK) # verify otp
async def user_signup_send_otp(data: models.verify_otp_signup):
    return await auth_manager.send_otp_signup(data)

@auth_user_router.post("/signup/email_verify_otp", status_code=status.HTTP_200_OK) # verify otp during signup
async def user_signup_email_verify_otp(data: models.otp_email):
    return await auth_manager.verify_otp_signup_email(data)

@auth_user_router.post("/signup/phone_verify_otp", status_code=status.HTTP_200_OK) # verify otp during signup
async def user_signup_phone_verify_otp(data: models.otp_phone):
    return await auth_manager.verify_otp_signup_phone(data)

@auth_user_router.post("/login/send_otp", status_code=status.HTTP_200_OK) # login using email 
async def user_login_send_otp(data: models.login_otp):
    return await auth_manager.send_otp_login(data)

@auth_user_router.post("/login/email_verify_otp", status_code=status.HTTP_200_OK)
async def user_login_email_verify_otp(data: models.otp_email, response: Response, request: Request):
    return await auth_manager.verify_otp_login_email(data, response, request)

@auth_user_router.post("/login/phone_verify_otp", status_code=status.HTTP_200_OK)
async def user_login_phone_verify_otp(data: models.otp_phone, response: Response, request: Request):
    return await auth_manager.verify_otp_login_phone(data, response, request)


# @limiter.limit("5/minute")  #******************************* Rate limit *********************************************************************

# async def login(response: Response, request: Request, form_data: OAuth2UserRequestForm = Depends(), auth_token: OAuth2PasswordBearer = Depends(oauth2.oauth2_scheme)): -> for locking the route use this instead of below

@auth_user_router.post("/login", status_code=status.HTTP_200_OK) # login using email and password
async def user_login(data: models.login, response: Response, request: Request):
    return await auth_manager.login(data, response, request)

@auth_user_router.get("/refresh_token", status_code=status.HTTP_200_OK)
async def user_refresh_token(request: Request, response: Response):
    return await auth_manager.refresh_token(request, response)

@auth_user_router.post("/reset_password/send_otp", status_code=status.HTTP_200_OK)
async def user_reset_password(data: models.email):
    return await auth_manager.send_otp_reset_password(data)

@auth_user_router.post("/reset_password/email_verify_otp", status_code=status.HTTP_200_OK) # verify otp during password reset
async def user_verify_otp_reset_password(data: models.otp_email):
    return await auth_manager.verify_otp_reset_password(data)

@auth_user_router.post("/reset_password/create_new_password", status_code=status.HTTP_200_OK) 
async def user_create_new_password(data: models.reset_password):
    return await auth_manager.create_new_password(data)

@auth_user_router.post("/logout", status_code=status.HTTP_200_OK)
async def user_logout(data: models.logout, response: Response, request: Request):
    return await auth_manager.logout(data, response, request)