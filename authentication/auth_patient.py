from fastapi import APIRouter, Request, status, HTTPException, Depends, BackgroundTasks
import re
from .database import mongo_client
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
import aioredis
from .oauth2 import OAuth2PatientRequestForm
import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
from .hashing import Hash
from datetime import datetime
from .send_mail import send_email_async, send_email_background
from . import auth_token, models, oauth2
import os

auth_patient = APIRouter(tags=["Patient Authentication"]) # create a router for patient
templates = Jinja2Templates(directory="authemtication/templates")

# redis connection
client = aioredis.from_url('redis://default@54.198.65.205:6379', decode_responses=True)

def setup_logging():
    logger = logging.getLogger("auth_log") # create logger
    if not logger.hasHandlers(): # check if handlers already exist
        logger.setLevel(logging.INFO) # set log level

        # create log directory if it doesn't exist
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)

        # create a file handler
        file_handler = ConcurrentRotatingFileHandler(
            os.path.join(log_dir, "auth.log"), 
            maxBytes=10000, # 10KB 
            backupCount=500
        )
        file_handler.setLevel(logging.INFO) # The lock file .__auth.lock is created here by ConcurrentRotatingFileHandler

        #  create a console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # create a formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                                      datefmt="%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        #  add the handlers to the logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    return logger

logger = setup_logging() # initialize logger


# implemeting cahing using redis
async def cache(data: str, plain_password):
    user = await mongo_client.auth.patient.find_one({"$or": [{
        "email": data}, 
        {"patient_user_name": data}, 
        {"phone_number": data}]})
    CachedData = await client.get(f'patient:{data}')
    if CachedData and user:
            hashed_password = await Hash.verify(user["password"], plain_password)
            if hashed_password:
                print("Data is cached") # debug
                print(CachedData) # debug
                logger.info(f"Patient logged in successfully using: {data}")
                return CachedData
            logger.warning(f"login attempt with invalid password: {data}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    elif user:
        hashed_password = await Hash.verify(user["password"], plain_password)
        if hashed_password:
            print("searching inside db") # debug
            await client.set(f"patient:{data}",data, ex=30) # expire in 30 seconds
            logger.info(f"Patient logged in successfully using: {data}")
            return data
    return None

@auth_patient.get("/", response_class=HTMLResponse)
async def read(request: Request):
    user = await mongo_client.auth.patient.find()
    new_user = []
    for i in user:
        new_user.append({
            "id": i["_id"],
            "full_name": i["full_name"],
            "patient_user_name": i["patient_user_name"],
            "email": i["email"],
            "phone_number": i["phone_number"],
            "disabled": i["disabled"]
        })
    return templates.TemplateResponse("signup.html", {"request": request, "user": new_user}) 
    

@auth_patient.post("/patient/signup", status_code=status.HTTP_201_CREATED, response_model=models.res)
async def signup(request: Request, response: Response):
    try:
        form_data = await request.form()
        dict_data = dict(form_data)
        dict_data["created_at"] = datetime.now()

        required_fields = ["full_name", "email", "patient_user_name", "password", "confirm_password", "phone_number"]
        for field in required_fields:
            if field not in dict_data:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="All fields are required")
            
            #  define a regex pattern for allowed username characters
            regex_username_pattern = r"^[a-zA-Z0-9_.-]{3,}$"  # Allows letters, numbers, _ . - with at least 3 characters
            regex_restricted_words = {"admin", "superuser", "root", "moderator", "administrator", "null", "test", "system"}

        email = await mongo_client.auth.patient.find_one({"email": dict_data["email"]})
        user = await mongo_client.auth.patient.find_one({"patient_user_name": dict_data["patient_user_name"]})
        phone_number = await mongo_client.auth.patient.find_one({"phone_number": dict_data["phone_number"]})
        
        # data validation
        if email:
            logger.warning(f"Signup attempt with existing email: {dict_data['email']}")
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Email already exists")
        if user:
            logger.warning(f"Signup attempt with existing username: {dict_data['patient_user_name']}")
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Username already exists")
        if(form_data["phone_number"].__len__() < 10 or form_data["phone_number"].__len__() > 10):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Phone number must be 10 digits long")
        if phone_number:
            logger.warning(f"Signup attempt with existing phone number: {dict_data['phone_number']}")
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Phone number already in use")
        
        if not(form_data["phone_number"].isdigit()):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Phone number must be digits only")
        if dict_data["password"] != dict_data["confirm_password"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Password do not match")
        if(form_data["password"].__len__() < 6):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Password must be at least 6 characters long")
        if(form_data["email"].__contains__("@") == False):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Invalid email address")
        if(form_data["patient_user_name"].__len__() < 3):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Username must be greater than 3 characters")
        if not re.fullmatch(regex_username_pattern, form_data["patient_user_name"]):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid username. Allowed: letters, numbers, '_', '.', '-'. Min length: 3")
        if(form_data["full_name"].__len__() < 2):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Full name must be greater than 1 character")
        if any(word in form_data["patient_user_name"].lower() for word in regex_restricted_words):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username contains restricted words.")
        if(form_data["email"].__len__() < 4):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email must be greater than 3 characters") 


        # hashing the password
        hashed_password = Hash.bcrypt(dict_data["password"])
        dict_data["password"] = hashed_password

        # removing the confirm_password field from db
        dict_data.pop("confirm_password")

        await mongo_client.auth.patient.insert_one(dict_data)
        logger.info(f"Account for patient created successfully: {dict_data['email']}")
        
        # Generate a cache during signup with email as key
        cache_key = dict_data["email"]
        cached_data = await client.set(f"patient:{cache_key}",cache_key,ex=3600) 
        access_token = auth_token.create_access_token(data={"sub": cache_key})
        RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        return {"message":"Account for patient created successfully"} # Return success message
    
    except Exception as e:
        print(f"Error creating new user: {str(e)}")
        logger.error(f"Error creating new user: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    
# async def login(response: Response, request: Request, form_data: OAuth2PatientRequestForm = Depends(), auth_token: OAuth2PasswordBearer = Depends(oauth2.oauth2_scheme)): -> for locking the route use this instead of the below

@auth_patient.post("/patient/login", status_code=status.HTTP_200_OK) # login using email and password
async def login(response: Response, request: Request):
    try:
        form_data = await request.form()

        email_provided = form_data.get("email", None)
        user_name_provided = form_data.get("patient_user_name", None)
        password_provided = form_data.get("password", None)
        phone_number_provided = form_data.get("phone_number", None)

        # check if email or patient_user_name or password is provided
        if not password_provided:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is required")
        
        if not email_provided and not user_name_provided and not phone_number_provided:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User Name or Email or phone number is required")
        
        else:
            user = None # initialize user to None

            # login using email and password
            if email_provided:
                # Generate a cache key based on login identifier
                cache_key = email_provided
                cached_data = await cache(cache_key, form_data["password"])
                if cached_data:
                    print("cache data returned", cached_data) # debug
                    access_token = auth_token.create_access_token(data={"sub": cache_key})
                    RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_200_OK)
                    response.delete_cookie("access_token")  # Remove old token
                    response.set_cookie(key="access_token", value=access_token, max_age=3600)
                    return ("Patient logged in succesful")  # Return success message

                
                user = await mongo_client.auth.patient.find_one({"email": form_data["email"]})
                print("cache data returned none") # debug
                if not user:
                    logger.warning(f"login attempt with invalid email: {form_data['email']}")
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
                if not await Hash.verify(user["password"], form_data["password"]):
                    logger.warning(f"login attempt with invalid password: {form_data['email']}")
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
                         
            # login using patient_user_name and password
            elif user_name_provided:
                # Generate a cache key based on login identifier
                cache_key = user_name_provided
                cached_data = await cache(cache_key, form_data["password"])
                if cached_data:
                    print("cache data returned", cached_data) # debug
                    access_token = auth_token.create_access_token(data={"sub": cache_key})
                    RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_200_OK)
                    response.delete_cookie("access_token")  # Remove old token
                    response.set_cookie(key="access_token", value=access_token, max_age=3600)
                    return ("Patient logged in succesful")  # Return success message
                
                user = await mongo_client.auth.patient.find_one({"patient_user_name": form_data["patient_user_name"]})
                print("cache data returned none") # debug
                if not user:
                    logger.warning(f"login attempt with invalid user name: {form_data['patient_user_name']}")
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
                if not await Hash.verify(user["password"], form_data["password"]):
                    logger.warning(f"login attempt with invalid password: {form_data['patient_user_name']}")
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

            # login using phone_number and password
            elif phone_number_provided:
                # Generate a cache key based on login identifier
                cache_key = phone_number_provided
                cached_data = await cache(cache_key, form_data["password"])
                if cached_data:
                    print("cache data returned", cached_data) # debug
                    access_token = auth_token.create_access_token(data={"sub": cache_key})
                    RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_200_OK)
                    response.delete_cookie("access_token")  # Remove old token
                    response.set_cookie(key="access_token", value=access_token, max_age=3600)
                    return ("Patient logged in succesful")  # Return success message

                user = await mongo_client.auth.patient.find_one({"phone_number": form_data["phone_number"]})
                print("cache data returned none") # debug
                if not user:
                    logger.warning(f"login attempt with invalid phone number: {form_data['phone_number']}")
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
                if not await Hash.verify(user["password"], form_data["password"]):
                    logger.warning(f"login attempt with invalid password: {form_data['phone_number']}")
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
            
    except Exception as e:
        print(f"login attempt failed: {str(e)}")
        logger.error(f"login attempt failed: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

#  *********************************************************************for email************************************************************************
# @auth_patient.get('/send-email/asynchronous')
# async def send_email_asynchronous():
#     await send_email_async('Hello World', 'madhurprakash2005@gmail.com', {'title': 'Hello World', 'name': 'John Doe'})
#     return 'Success'

# @auth_patient.get('/send-email/backgroundtasks')
# def send_email_backgroundtasks(background_tasks: BackgroundTasks):
#     send_email_background(background_tasks, 'Hello World', 'madhurprakash2005@gmail.com', {'title': 'Hello World', 'name': 'John Doe'})
#     return 'Success'
# ********************************************************************************************************************************************************


@auth_patient.post("/patient/{patient_user_name}/logout", status_code=status.HTTP_200_OK)
async def logout(patient_user_name: str, response: Response):
    RedirectResponse("http://127.0.0.1:8000/login", status_code=status.HTTP_200_OK)
    response.delete_cookie("access_token")
    logger.info(f"{patient_user_name} logged out successfully")
    print(f"{patient_user_name} logged out successfully") # debug
    return (f"{patient_user_name} logged out successfully")  # Return success message