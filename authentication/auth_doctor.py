from fastapi import APIRouter, Request, status, HTTPException, Depends, BackgroundTasks
import traceback
from .otp_verify import send_otp, generate_otp
from .database import mongo_client
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
import aioredis
from .oauth2 import OAuth2PatientRequestForm, create_verification_token, decode_verification_token
from .utils import setup_logging, generate_random_string  # Import setup_logging from utils
from .hashing import Hash
from datetime import datetime
from .send_mail import send_email
from . import auth_token, models, oauth2

auth_doctor = APIRouter(tags=["doctor Authentication"]) # create a router for doctor
templates = Jinja2Templates(directory="authentication/templates")

# redis connection
# client = aioredis.from_url('redis://default@54.198.65.205:6379', decode_responses=True) in production

client =  aioredis.from_url('redis://localhost', decode_responses=True) # in local testing

logger = setup_logging() # initialize logger


# implemeting cahing using redis
async def cache(data: str, plain_password):
    user = await mongo_client.auth.doctor.find_one({"$or": [{
        "email": data}, 
        {"phone_number": data}]})
    CachedData = await client.get(f'doctor:{data}')
    if CachedData and user:
            hashed_password = await Hash.verify(user["password"], plain_password)
            if hashed_password:
                print("Data is cached") # debug
                print(CachedData) # debug
                return user
            logger.warning(f"login attempt with invalid credentials: {data} and {plain_password}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    elif user:
        hashed_password = await Hash.verify(user["password"], plain_password)
        if hashed_password:
            print("searching inside db") # debug
            await client.set(f"doctor:{data}",data, ex=30) # expire in 30 seconds
            return user
    return None

async def cache_without_password(data: str):
    user = await mongo_client.auth.doctor.find_one({"$or": [{
        "email": data}, 
        {"phone_number": data}]})
    CachedData = await client.get(f'doctor:{data}')
    if CachedData:
        if user:
            print("Data is cached") # debug
            print(CachedData) # debug
            return user
        logger.warning(f"login attempt with invalid credentials: {data}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    elif user:
            print("searching inside db") # debug
            await client.set(f"doctor:{data}",data, ex=30) # expire in 30 seconds
            return user
    return None

@auth_doctor.get("/", response_class=HTMLResponse)
async def read(request: Request):
    user = mongo_client.auth.doctor.find()
    new_user = []
    # for i in user:
    #     new_user.append({
    #         "id": i["_id"],
    #         "full_name": i["full_name"],
    #         "doctor_user_name": i["doctor_user_name"],
    #         "email": i["email"],
    #         "phone_number": i["phone_number"],
    #         "disabled": i["disabled"]
    #     })
    return templates.TemplateResponse("login.html", {"request": request, "user": new_user}) 
    

@auth_doctor.post("/doctor/signup", status_code=status.HTTP_201_CREATED)
async def signup(request: Request, response: Response):
    try:
        form_data = await request.json()
        dict_data = dict(form_data)
        dict_data["created_at"] = datetime.now().isoformat()
        dict_data["CIN"] = generate_random_string()

        required_fields = ["full_name", "email", "password", "phone_number"]
        for field in required_fields:
            if field not in dict_data:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="All fields are required")

        email = await mongo_client.auth.doctor.find_one({"email": dict_data["email"]})
        phone_number = await mongo_client.auth.doctor.find_one({"phone_number": dict_data["phone_number"]})
        
        # data validation
        if email:
            logger.warning(f"Signup attempt with existing email: {dict_data['email']}")
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Email already exists")
        if(form_data["phone_number"].__len__() < 10 or form_data["phone_number"].__len__() > 10):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Phone number must be 10 digits long")
        if phone_number:
            logger.warning(f"Signup attempt with existing phone number: {dict_data['phone_number']}")
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Phone number already in use")
        
        if not(form_data["phone_number"].isdigit()):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Phone number must be digits only")
        if(form_data["password"].__len__() < 6):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Password must be at least 6 characters long")
        if(form_data["email"].__contains__("@") == False):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Invalid email address")
        if(form_data["full_name"].__len__() < 2):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Full name must be greater than 1 character")
        if(form_data["email"].__len__() < 4):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email must be greater than 3 characters") 


        # hashing the password
        hashed_password = Hash.bcrypt(dict_data["password"])
        dict_data["password"] = hashed_password


        await mongo_client.auth.doctor.insert_one(dict_data)  # Insert into MongoDB
        logger.info(f"Account for doctor created successfully: {dict_data['email']}")
        # Generate a cache during signup with email as key
        cache_key = dict_data["email"]
        cached_data = await client.set(f"doctor:{cache_key}",cache_key,ex=3600) 
        access_token = auth_token.create_access_token(data={"sub": cache_key})
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600)


        # await client.hset(dict_data["email"], mapping={
        #     "email": dict_data["email"],
        #     "full_name": dict_data["full_name"],
        #     "password": dict_data["password"],
        #     "phone_number": dict_data["phone_number"],
        #     "CIN": dict_data["CIN"],
        #     "created_at": dict_data["created_at"]})
        
        # await client.hset(dict_data["phone_number"], mapping={
        #     "email": dict_data["email"],
        #     "full_name": dict_data["full_name"],
        #     "password": dict_data["password"],
        #     "phone_number": dict_data["phone_number"],
        #     "CIN": dict_data["CIN"],
        #     "created_at": dict_data["created_at"]})
        # await client.expire(dict_data["email"], 300)  # Expire in 5 minutes
        # await client.expire(dict_data["phone_number"], 300)  # Expire in 5 minutes
        
        # token = create_verification_token({"email":dict_data['email']})
        # link = f"http://127.0.0.1:8000/doctor/verify_email/{token}"
        # otp =  await generate_otp(dict_data["email"])
        
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
        #                         target="_blank"
        #                     >
        #                         {otp}
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

        # dict_data["phone_number"] = "+91" + dict_data["phone_number"] # adding country code
        # otp = await send_otp(dict_data["phone_number"])
        # if not otp:
        #     raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
        
        # return {"message":f"OTP sent successfully on {form_data['phone_number'][:6]+'x'*6+dict_data['phone_number'][13:]} and {dict_data['email']}"} # Return success message
        return (f"Account for doctor created successfully: {dict_data['email']}")


    except Exception as e:
        print(f"Error creating new user: {str(e)}")
        logger.error(f"Error creating new user: {str(e)}")
        # print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
# ***********************************************************************************************************************************************


@auth_doctor.post("/doctor/verify_otp_signup", status_code=status.HTTP_200_OK) # verify otp
async def verify_otp_signup(request: Request):
    try:
        form_data = await request.json()
        email = form_data.get("email")
        phone_number = form_data.get("phone_number")
        if email:
            otp =  await generate_otp(email)
            otp = str(otp)
            encrypted_otp = Hash.bcrypt(otp)
        
            html_body = f"""
                            <html>
                            <body style="margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, Helvetica, sans-serif;">
                            <div style="width: 100%; background: #efefef; border-radius: 10px; padding: 10px;">
                            <div style="margin: 0 auto; width: 90%; text-align: center;">
                                <h1 style="background-color: rgba(0, 53, 102, 1); padding: 5px 10px; border-radius: 5px; color: white;">CuraDocs</h1>
                                <div style="margin: 30px auto; background: white; width: 40%; border-radius: 10px; padding: 50px; text-align: center;">
                                <h3 style="margin-bottom: 100px; font-size: 24px;">Hello!</h3>
                                <p style="margin-bottom: 30px;">Thanks for choosing CuraDocs. Please click the link below to verify your email.</p>
                                <a style="display: block; margin: 0 auto; border: none; background-color: rgba(255, 214, 10, 1); color: white; width: 200px; line-height: 24px; padding: 10px; font-size: 24px; border-radius: 10px; cursor: pointer; text-decoration: none;"
                                    target="_blank"
                                >
                                    {otp}
                                </a>
                                </div>
                            </div>
                            </div>
                            </body>
                            </html>
                            """
            # send email verification link
            email_sent = send_email(email, "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
            if not email_sent:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

            # otp_entered = form_data.get("otp")
            # if not otp_entered or len(otp_entered) != 6:
            #     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
            # otp_stored = await client.hgetall(email)
            # print(otp_stored) # debug
            # if not otp_stored or (otp_stored.get('otp') != otp_entered):
            #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
            # access_token = auth_token.create_access_token(data={"sub": email})
            # print("Access token:", access_token)  # debug
            # mongodb_document = {
            #     "full_name": otp_stored.get("full_name"),
            #     "email": otp_stored.get("email"),
            #     "password": otp_stored.get("password"),
            #     "phone_number": otp_stored.get("phone_number"),
            #     "created_at": otp_stored.get("created_at"),
            #     "CIN": otp_stored.get("CIN")
            # }
            # user = await mongo_client.auth.doctor.find_one({"email": otp_stored.get("email")})
            # if user:
            #     raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")
            # # Insert into MongoDB
            # await mongo_client.auth.doctor.insert_one(mongodb_document)


            # response.delete_cookie("access_token")  # Remove old token
            # response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)
            # print(f"{email} signed up succesfully as doctor")  # Return success message
            print("otp sent successfuly")
            logger.info("otp verified successfuly")
            return ({"message":"otp sent successfuly", "status": status.HTTP_200_OK, "otp": encrypted_otp})
        elif phone_number:
            phone_number = "91" + phone_number # adding country code
            otp = await send_otp(phone_number)
            otp = str(otp)
            encrypted_otp = Hash.bcrypt(otp)
            if not otp:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
            print("otp sent successfuly")
            logger.info("otp verified successfuly")
            return ({"message":"otp sent successfuly", "status": status.HTTP_200_OK, "otp": encrypted_otp})
        
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        logger.error(f"Error verifying OTP: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    


# async def login(response: Response, request: Request, form_data: OAuth2doctorRequestForm = Depends(), auth_token: OAuth2PasswordBearer = Depends(oauth2.oauth2_scheme)): -> for locking the route use this instead of below

# ***************** login through email/phone_number and otp ****************************************************
@auth_doctor.post("/doctor/login_otp", status_code=status.HTTP_200_OK) # login using email 
async def login(request: Request):
    try:
        form_data = await request.json()

        email_provided = form_data.get("email", None)
        phone_number_provided = form_data.get("phone_number", None)

        # check if email or phone number is provided
        if not email_provided and not phone_number_provided:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or phone number is required")
        
        else:
            # login using email and password
            if email_provided:
                # Generate a cache key based on login identifier
                cache_key = email_provided
                cached_data = await cache_without_password(cache_key)
                if cached_data:
                    # token = create_verification_token({"email":dict_data['email']})
                    # link = f"http://127.0.0.1:8000/doctor/verify_email/{token}"
                    otp = await generate_otp(email_provided)

                    html_body = f"""
                                    <html>
                                    <body style="margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, Helvetica, sans-serif;">
                                    <div style="width: 100%; background: #efefef; border-radius: 10px; padding: 10px;">
                                    <div style="margin: 0 auto; width: 90%; text-align: center;">
                                        <h1 style="background-color: rgba(0, 53, 102, 1); padding: 5px 10px; border-radius: 5px; color: white;">CuraDocs</h1>
                                        <div style="margin: 30px auto; background: white; width: 40%; border-radius: 10px; padding: 50px; text-align: center;">
                                        <h3 style="margin-bottom: 100px; font-size: 24px;">Hello!</h3>
                                        <p style="margin-bottom: 30px;">Thanks for choosing CuraDocs.</p>
                                        <a style="display: block; margin: 0 auto; border: none; background-color: rgba(255, 214, 10, 1); color: white; width: 200px; line-height: 24px; padding: 10px; font-size: 24px; border-radius: 10px; cursor: pointer; text-decoration: none;"
                                            target="_blank"
                                        >
                                             {otp}
                                        </a>
                                        </div>
                                    </div>
                                    </div>
                                    </body>
                                    </html>
                                    """
                    # send otp via email
                    email_sent = send_email(form_data["email"], "Login to CuraDocs using the provided otp", html_body, retries=3, delay=5)
                    if not email_sent:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")
                    return templates.TemplateResponse("otp.html", {"request": request, "message": f"OTP sent successfully on {email_provided}"}, status_code=status.HTTP_200_OK)

                    
                print("cache data returned none") # debug
                logger.warning(f"login attempt with invalid credentials: {form_data['email']}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

            # login using phone_number and password
            elif phone_number_provided:
                # Generate a cache key based on login identifier
                cache_key = phone_number_provided
                cached_data = await cache_without_password(cache_key)
                if cached_data:
                    print("cache data returned", cached_data) # debug
                    #  sending otp
                    phone_number_provided = "+91" + phone_number_provided # adding country code
                    otp = await send_otp(phone_number_provided)
                    if not otp:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
                    return templates.TemplateResponse("otp.html", {"request": request, "message": f"OTP sent successfully on {phone_number_provided[3:7]+'x'*6+phone_number_provided[13:]}"}, status_code=status.HTTP_200_OK) # masking the phone number for security

                print("cache data returned none") # debug
                logger.warning(f"login attempt with invalid credentials: {form_data['email']}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
                
    except Exception as e:
        print(f"login attempt failed: {str(e)}")
        logger.error(f"login attempt failed: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
# ***************************************************************************************************************************************************************



@auth_doctor.post("/doctor/{email}/verify_otp_login_email", status_code=status.HTTP_200_OK) 
async def verify_otp(request: Request, response: Response, email: str):
    try:
        form_data = await request.json()
        
        otp_entered = form_data.get("otp")
        print(otp_entered) # debug
        if not otp_entered or len(otp_entered) != 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
        otp_stored = await client.hgetall(email)
        print(otp_stored) # debug
        if not otp_stored or (otp_stored.get('otp') != otp_entered):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        access_token = auth_token.create_access_token(data={"sub": email})
        print("Access token:", access_token)  # debug
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)
        print(f"{email} logged in succesfully")  # Return success message
        logger.info(f"{email} logged in successfully")
        return (f"OTP verified successfully from {email}")
                         
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        logger.error(f"Error verifying OTP: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@auth_doctor.post("/doctor/{phone_number}/verify_otp_login_phone", status_code=status.HTTP_200_OK)
async def verify(response: Response, request: Request, phone_number: str):
    try:
        form_data = await request.json()

        otp_entered = form_data.get("otp")
        print(otp_entered)
        if not otp_entered or len(otp_entered) != 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
        otp_stored = await client.hgetall(phone_number)
        print(otp_stored)
        if not otp_stored or (otp_stored.get('otp') != otp_entered):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        access_token = auth_token.create_access_token(data={"sub": phone_number})
        print("Access token:", access_token)  # debug
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)
        print(f"{phone_number} logged in succesfully")  # Return success message
        logger.info(f"{phone_number} logged in successfully")
        return (f"OTP verified successfully from {phone_number}")

    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        logger.error(f"Error verifying OTP: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))



# ********************************************************************* login with email/phone_number and password ************************************
@auth_doctor.post("/doctor/login", status_code=status.HTTP_200_OK) # login using email and password
async def login(response: Response, request: Request):
    try:
        form_data = await request.json()

        email_provided = form_data.get("email", None)
        password_provided = form_data.get("password", None)
        phone_number_provided = form_data.get("phone_number", None)

        # check if email or doctor_user_name or password is provided
        if not password_provided:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is required")
        
        if not email_provided and not phone_number_provided:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User Name or Email or phone number is required")
        
        else:
            # login using email and password
            if email_provided:
                # Generate a cache key based on login identifier
                cache_key = email_provided
                cached_data = await cache(cache_key, form_data["password"])
                if cached_data:
                    print("cache data returned", cached_data) # debug
                    access_token = auth_token.create_access_token(data={"sub": cache_key})
                    response.delete_cookie("access_token")  # Remove old token
                    response.set_cookie(key="access_token", value=access_token, max_age=3600)
                    logger.info(f"{email_provided} logged in successfully")
                    RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_200_OK)
                    return (f"{email_provided} logged in succesfully")  # Return success message

                print("cache data returned none") # debug
                logger.warning(f"login attempt with invalid Invalid credentials: {form_data['email']} ; {form_data['password']}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

            # login using phone_number and password
            elif phone_number_provided:
                # Generate a cache key based on login identifier
                cache_key = phone_number_provided
                cached_data = await cache(cache_key, form_data["password"])
                if cached_data:
                    print("cache data returned", cached_data) # debug
                    access_token = auth_token.create_access_token(data={"sub": cache_key})
                    response.delete_cookie("access_token")  # Remove old token
                    response.set_cookie(key="access_token", value=access_token, max_age=3600)
                    logger.info(f"{phone_number_provided} logged in successfully")
                    RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_200_OK)
                    return (f"{phone_number_provided} logged in succesfully")  # Return success message

                print("cache data returned none") # debug
                logger.warning(f"login attempt with invalid Invalid credentials: {form_data['phone_number']} ; {form_data['password']}")
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
            
    except Exception as e:
        print(f"login attempt failed: {str(e)}")
        logger.error(f"login attempt failed: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
# ***************************************************************************************************************************************************************
   
@auth_doctor.post("/doctor/reset_password", status_code=status.HTTP_200_OK)
async def reset_password(request: Request):
    try:
        form_data = await request.json()
        email = form_data.get("email")
        if not email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required")
        user = await mongo_client.auth.doctor.find_one({"email": email})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        token = create_verification_token({"email":email})
        reset_link = f"http://127.0.0.1:8000/doctor/create_new_password/{token}"
        html_body = f"""
                    <html>
                    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;">
    <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f4; padding: 20px;">
        <tr>
            <td align="center">
                <table width="600" cellspacing="0" cellpadding="0" border="0" style="background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1); text-align: center;">
                    <tr>
                        <td>
                            <img src="https://your-logo-url.com/logo.png" alt="CuraDocs Logo" style="width: 150px; margin-bottom: 20px;">
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <h2 style="color: #333; margin: 0;">Password Reset Request</h2>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p style="color: #666; font-size: 16px;">We received a request to reset your password for your CuraDocs account.</p>
                            <p style="color: #666; font-size: 16px;">Click the button below to reset your password:</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <a href="{reset_link}" style="display: inline-block; padding: 12px 24px; background-color: #007BFF; color: #ffffff; text-decoration: none; font-size: 16px; border-radius: 5px; margin-top: 20px;">Reset Password</a>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p style="color: #666; font-size: 16px;">If you did not request this, please ignore this email.</p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p style="font-size: 14px; color: #999; margin-top: 20px;">© 2025 CuraDocs. All rights reserved.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
                    """
        
        # send email verification link
        email_sent = send_email(email, "Password Reset Request", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")
        return ({"message": "Password reset link sent successfully"}) # Return success message
    
    except Exception as e:
        print(f"Error resetting password: {str(e)}")
        logger.error(f"Error resetting password: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
        

@auth_doctor.get("/doctor/reset_password", status_code=status.HTTP_200_OK)
async def reset_password_form(request: Request):
    return templates.TemplateResponse("reset_password.html", {"request": request}, status_code=status.HTTP_200_OK)


@auth_doctor.post("/doctor/create_new_password/{token}", status_code=status.HTTP_200_OK) 
async def create_new_password(request: Request, token: str):
    try:
        token_data = decode_verification_token(token)
        email = token_data["email"]
        form_data = await request.json()
        password = form_data.get("password")
        confirm_password = form_data.get("confirm_password")
        if not password or not confirm_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password and confirm password are required")
        if password != confirm_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")
        if len(password) < 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 6 characters long")
        hashed_password = Hash.bcrypt(password)
        # If bcrypt returns bytes, decode to string for MongoDB storage
        hashed_password = hashed_password.decode('utf-8')
        user = await mongo_client.auth.doctor.find_one({"email": email})
        print(user) # debug
        result = await mongo_client.auth.doctor.update_one({"email": email}, {"$set": {"password": hashed_password}})
        # Check if user was updated
        if result.modified_count == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return ({"message": "Password updated successfully"}) # Return success message
    
    except Exception as e:
        print(f"Error creating new password: {str(e)}")
        logger.error(f"Error creating new password: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@auth_doctor.post("/doctor/{email}/logout", status_code=status.HTTP_200_OK)
async def logout(email: str, response: Response):
    RedirectResponse("http://127.0.0.1:8000/login", status_code=status.HTTP_200_OK)
    response.delete_cookie("access_token")
    logger.info(f"{email} logged out successfully")
    print(f"{email} logged out successfully") # debug
    return (f"{email} logged out successfully")  # Return success message



# ***********************************************NOT USED ROUTES***************************************************************************************************

# *****************************this route verified otp for signup using phone number, the route are now merged with route for verifying otp using email******************************
# @auth_doctor.post("/doctor/verify_otp_signup_phone", status_code=status.HTTP_200_OK) # verify otp
# async def verify_otp_signup_phone(request: Request):
#     try:
#         form_data = await request.json()
#         phone_number = form_data.get("phone_number")
#         phone_number = "+91" + phone_number # adding country code
#         otp = await send_otp(phone_number)
#         if not otp:
#             raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
#         otp_entered = form_data.get("otp")
#         if not otp_entered or len(otp_entered) != 6:
#             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
#         otp_stored = await client.hgetall(phone_number)
#         # phone_number['phone_number'] = str(phone_number['phone_number'])
#         print("otp_stored:",otp_stored) # debug
#         if not otp_stored or (otp_stored.get('otp') != otp_entered):
#             raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        
        # phone_number = phone_number[3:] # removing country code
        # data = await client.hgetall(phone_number)
        # access_token = auth_token.create_access_token(data={"sub": phone_number})
        # print("phone_number:",data) # debug
        # user = await mongo_client.auth.doctor.find_one({"phone_number":data.get("phone_number")})
        # print("user:",user) # debug
        # if user:
        #     raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")
        # mongodb_document = {
        #     "full_name": data.get("full_name"),
        #     "email": data.get("email"),
        #     "password": data.get("password"),
        #     "phone_number": data.get("phone_number"),
        #     "created_at": data.get("created_at"),
        #     "CIN": data.get("CIN")
        # }
        # await mongo_client.auth.doctor.insert_one(mongodb_document)  # Insert into MongoDB
        # print("Access token:", access_token)  # debug
        # response.delete_cookie("access_token")  # Remove old token
        # response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)
        # print(f"{phone_number} signed up succesfully as doctor")  # Return success message
    #     print(f"otp verified successfuly through {phone_number}")
    #     logger.info(f"otp verified successfuly through {phone_number}")
    #     return(f"otp verified successfuly through {phone_number}")
       
        
    # except Exception as e:
    #     print(f"Error verifying OTP: {str(e)}")
    #     logger.error(f"Error verifying OTP: {str(e)}")
    #     print(f"Error: {traceback.format_exc()}")
    #     raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))




# ***************************** this route helped in verifying email ****************************************************
# @auth_doctor.get("/doctor/verify_email/{token}", status_code=status.HTTP_200_OK, response_model=models.res)
# async def verify_email(token: str, response: Response):
#     try:
#         token_data = decode_verification_token(token)
#         email = token_data["email"]
#         temp_user = await mongo_client.auth.temp.find_one({"email": email})
#         if not temp_user:
#             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") 
#         temp_user.pop("_id")
#         await mongo_client.auth.doctor.insert_one(temp_user) # adding to the main db
#         await mongo_client.auth.temp.delete_many({"email": email}) # deleting from the temp db
#         # logger.info(f"Account for doctor created successfully: {email}")
#         # Generate a cache during signup with email as key
#         cache_key = email
#         cached_data = await client.set(f"doctor:{cache_key}",cache_key,ex=3600) 
#         access_token = auth_token.create_access_token(data={"sub": cache_key})
#         response.delete_cookie("access_token")  # Remove old token
#         response.set_cookie(key="access_token", value=access_token, max_age=3600)
#         RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
#         return {"message":"Account for doctor created successfully"} # Return success message        
    
#     except Exception as e:
#         print(f"Error verifying email: {str(e)}")
#         logger.error(f"Error verifying email: {str(e)}")
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))