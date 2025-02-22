from fastapi import APIRouter, Request, status, HTTPException, Depends, BackgroundTasks
import re
from .otp_verify import send_otp
from .database import mongo_client
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
import aioredis
from .oauth2 import OAuth2PatientRequestForm, create_verification_token, decode_verification_token
from .utils import setup_logging  # Import setup_logging from utils
from .hashing import Hash
from datetime import datetime
from .send_mail import send_email
from . import auth_token, models, oauth2

auth_patient = APIRouter(tags=["Patient Authentication"]) # create a router for patient
templates = Jinja2Templates(directory="authentication/templates")

# redis connection
client = aioredis.from_url('redis://default@54.198.65.205:6379', decode_responses=True)

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
                logger.info(f"{user['patient_user_name']} logged in successfully using: {data}")
                return CachedData
            logger.warning(f"login attempt with invalid password: {data}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    elif user:
        hashed_password = await Hash.verify(user["password"], plain_password)
        if hashed_password:
            print("searching inside db") # debug
            await client.set(f"patient:{data}",data, ex=30) # expire in 30 seconds
            logger.info(f"{user['patient_user_name']} logged in successfully using: {data}")
            return user
    return None

@auth_patient.get("/", response_class=HTMLResponse)
async def read(request: Request):
    user = mongo_client.auth.patient.find()
    new_user = []
    # for i in user:
    #     new_user.append({
    #         "id": i["_id"],
    #         "full_name": i["full_name"],
    #         "patient_user_name": i["patient_user_name"],
    #         "email": i["email"],
    #         "phone_number": i["phone_number"],
    #         "disabled": i["disabled"]
    #     })
    return templates.TemplateResponse("login.html", {"request": request, "user": new_user}) 
    

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
        await mongo_client.auth.temp.insert_one(dict_data) # adding to the temp db
# ******************************************************email verification*******************************************************************
        # token = create_verification_token({"email":dict_data['email']})
        # link = f"http://127.0.0.1:8000/patient/verify_email/{token}"

        # html_body = f"""
        #                 <html>
        #                 <body style="margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, Helvetica, sans-serif;">
        #                 <div style="width: 100%; background: #efefef; border-radius: 10px; padding: 10px;">
        #                 <div style="margin: 0 auto; width: 90%; text-align: center;">
        #                     <h1 style="background-color: rgba(0, 53, 102, 1); padding: 5px 10px; border-radius: 5px; color: white;">CuraDocs</h1>
        #                     <div style="margin: 30px auto; background: white; width: 40%; border-radius: 10px; padding: 50px; text-align: center;">
        #                     <h3 style="margin-bottom: 100px; font-size: 24px;">Hello!</h3>
        #                     <p style="margin-bottom: 30px;">Thanks for choosing CuraDocs. Please click the link below to verify your email.</p>
        #                     <a style="display: block; margin: 0 auto; border: none; background-color: rgba(255, 214, 10, 1); color: white; width: 200px; line-height: 24px; padding: 10px; font-size: 24px; border-radius: 10px; cursor: pointer; text-decoration: none;"
        #                         href={link} 
        #                         target="_blank"
        #                     >
        #                         Let's Go
        #                     </a>
        #                     </div>
        #                 </div>
        #                 </div>
        #                 </body>
        #                 </html>
        #                 """
        # # send email verification link
        # email_sent = send_email(dict_data["email"], "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
        # if not email_sent:
        #     raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")
# ***********************************************************************************************************************************************


# ******************************************************otp verification*******************************************************************

        dict_data["phone_number"] = "+91" + dict_data["phone_number"] # adding country code
        otp = send_otp(dict_data["phone_number"])
        if not otp:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
        cache_key = dict_data["email"]
        cached_data = await client.set(f"patient:{cache_key}",cache_key,ex=3600) 
        
        return {"message":"OTP send successfully"} # Return success message

# ***********************************************************************************************************************************************

    except Exception as e:
        print(f"Error creating new user: {str(e)}")
        logger.error(f"Error creating new user: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    
@auth_patient.get("/patient/verify_email/{token}", status_code=status.HTTP_200_OK, response_model=models.res)
async def verify_email(token: str, response: Response):
    try:
        token_data = decode_verification_token(token)
        email = token_data["email"]
        temp_user = await mongo_client.auth.temp.find_one({"email": email})
        if not temp_user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") 
        temp_user.pop("_id")
        await mongo_client.auth.patient.insert_one(temp_user) # adding to the main db
        await mongo_client.auth.temp.delete_one({"email": email}) # deleting from the temp db
        logger.info(f"Account for patient created successfully: {email}")
        # Generate a cache during signup with email as key
        cache_key = email
        cached_data = await client.set(f"patient:{cache_key}",cache_key,ex=3600) 
        access_token = auth_token.create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
        return {"message":"Account for patient created successfully"} # Return success message        
    
    except Exception as e:
        print(f"Error verifying email: {str(e)}")
        logger.error(f"Error verifying email: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))



# async def login(response: Response, request: Request, form_data: OAuth2PatientRequestForm = Depends(), auth_token: OAuth2PasswordBearer = Depends(oauth2.oauth2_scheme)): -> for locking the route use this instead of below

@auth_patient.post("/patient/login", status_code=status.HTTP_200_OK, response_class=HTMLResponse) # login using email and password
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
                    cached_data['phone_number'] = "+91" + cached_data['phone_number'] # adding country code
                    otp = await send_otp(cached_data['phone_number'])
                    if not otp:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
                    return templates.TemplateResponse("otp.html", {"request": request, "message": "OTP sent successfully"}, status_code=status.HTTP_200_OK)

                
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
                    email = await mongo_client.auth.patient.find_one({"patient_user_name": user_name_provided})
                    # send_email(email['email'],  "Kindly verify your email", html_body, retries=3, delay=5)
                    response.delete_cookie("access_token")  # Remove old token
                    response.set_cookie(key="access_token", value=access_token, max_age=3600)
                    return (f"{user_name_provided} logged in succesfully")  # Return success message
                
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
                    #  sending otp
                    phone_number_provided = "+91" + phone_number_provided # adding country code
                    otp = await send_otp(phone_number_provided)
                    if not otp:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
                    return templates.TemplateResponse("otp.html", {"request": request, "message": "OTP sent successfully"}, status_code=status.HTTP_200_OK)

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


@auth_patient.post("/patient/verify_otp", status_code=status.HTTP_200_OK, response_class=HTMLResponse) 
async def verify_otp(request: Request, response: Response):
    try:
        form_data = await request.form()
        
        otp_entered = form_data.get("otp")
        print(otp_entered) # debug
        if not otp_entered or len(otp_entered) != 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP format")
        otp_stored = await mongo_client.auth.temp.find_one({"otp": otp_entered})
        print(otp_stored) # debug
        if not otp_stored:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        phone_number = str(otp_stored["phone_number"])[3:]  # Remove country code (91)
        temp_patient = await mongo_client.auth.temp.find_one({"phone_number": phone_number})
        if temp_patient:
            temp_patient.pop("_id")
            print(temp_patient) # debug
            await mongo_client.auth.patient.insert_one(temp_patient) # adding to the main db
            await mongo_client.auth.temp.delete_one({"phone_number": phone_number}) # deleting from the temp db
        print(phone_number) # debug
        access_token = auth_token.create_access_token(data={"sub": phone_number})
        print("Access token:", access_token)  # debug
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)
        print(f"{phone_number} logged in succesfully")  # Return success message
        await mongo_client.auth.temp.delete_many({"otp": otp_entered})
        return ("OTP verified successfully")
                         
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        logger.error(f"Error verifying OTP: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@auth_patient.post("/patient/{patient_user_name}/logout", status_code=status.HTTP_200_OK)
async def logout(patient_user_name: str, response: Response):
    RedirectResponse("http://127.0.0.1:8000/login", status_code=status.HTTP_200_OK)
    response.delete_cookie("access_token")
    logger.info(f"{patient_user_name} logged out successfully")
    print(f"{patient_user_name} logged out successfully") # debug
    return (f"{patient_user_name} logged out successfully")  # Return success message