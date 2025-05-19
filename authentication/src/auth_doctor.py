from fastapi import APIRouter, Request, status, HTTPException, Depends, BackgroundTasks
import traceback
from ..models import models
from ..otp_service.otp_verify import send_otp, generate_otp, send_otp_sns_during_login, send_otp_sns_during_signup
from ..config.database import mongo_client
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from kafka import KafkaProducer
import json
from ..config.redis_config import client
import os
from ..config.rate_limiting import limiter
from ..helper.oauth2 import OAuth2PatientRequestForm, create_verification_token, decode_verification_token, serializer
from ..helper import auth_token
from ..helper.utils import create_session_id, create_new_log, generate_fingerprint_hash, get_country_name, generate_random_string, setup_logging
from ..helper.hashing import Hash
from datetime import datetime
from ..otp_service.send_mail import send_email_ses, send_email
from ..helper import oauth2
from config.bloom_filter import CountingBloomFilter

auth_doctor = APIRouter(tags=["doctor Authentication"]) # create a router for doctor
templates = Jinja2Templates(directory="authentication/templates")

logger = setup_logging() # initialize logger
# Kafka Producer
producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# implemeting cahing using redis
async def cache(data: str, plain_password):
    CachedData = await client.hgetall(f'doctor:auth:{data}')
    new_account = await client.hgetall(f'doctor:new_account:{data}')
    if CachedData:
        hashed_password = await Hash.verify(CachedData["password"], plain_password)
        if hashed_password:
            print("Data is cached") # debug
            print(CachedData) # debug
            create_new_log("info", f"cache hit and credential verified for {data}", "/api/backend/Auth")
            logger.info(f"cache hit and credential verified for {data}") # log the cache hit
            return data
        
    elif new_account:
        hashed_password = await Hash.verify(new_account["password"], plain_password)
        if hashed_password:
            print("Data is cached in new_account") # debug
            print(new_account) # debug
            create_new_log("info", f"cache hit and credential verified for {data}", "/api/backend/Auth")
            logger.info(f"cache hit and credential verified for {data}") # log the cache hit
            return data
            
    # user was not cached, searching in db
    user = await mongo_client.auth.doctor.find_one({"$or": [{
        "email": data}, 
        {"phone_number": data}]})
    if user:
        hashed_password = await Hash.verify(user["password"], plain_password)
        if hashed_password:
            print("searching inside db") # debug
            await client.hset(f"doctor:auth:{data}",mapping={
                "data":data,
                "password":user['password']
            }) 
            await client.expire(f"doctor:auth:{data}", 432000) # expire in 5 days
            create_new_log("info", f"searched inside db and credential verified for:{data}", "/api/backend/Auth")
            logger.info(f"searched inside db and credential verified for:{data}") # log the cache hit
            return user
    return None

async def cache_without_password(data: str):
    CachedData = await client.get(f'doctor:auth:2_factor_login:{data}')
    if CachedData:
        print("Data is cached") # debug
        print(CachedData) # debug
        create_new_log("info", f"cache hit for {data}", "/api/backend/Auth")
        logger.info(f"cache hit for {data}") # log the cache hit
        return CachedData
  
    user = await mongo_client.auth.doctor.find_one({"$or": [{
        "email": data}, 
        {"phone_number": data}]})
    if user:
        print("searching inside db") # debug
        await client.set(f"doctor:auth:2_factor_login:{data}",data, ex=432000) # expire in 5 days
        return user
    create_new_log("warning", f"login attempt with invalid credentials: {data}", "/api/backend/Auth")
    logger.warning(f"login attempt with invalid credentials: {data}") # log the cache hit
    return None

# @auth_doctor.get("/", response_class=HTMLResponse)
# async def read(request: Request):
#     user = mongo_client.auth.doctor.find()
#     new_user = []
#     # for i in user:
#     #     new_user.append({
#     #         "id": i["_id"],
#     #         "full_name": i["full_name"],
#     #         "doctor_user_name": i["doctor_user_name"],
#     #         "email": i["email"],
#     #         "phone_number": i["phone_number"],
#     #         "disabled": i["disabled"]
#     #     })
#     return templates.TemplateResponse("login.html", {"request": request, "user": new_user}) 
    

# Initialize bloom filters
doctor_email_bloom_filter = CountingBloomFilter(capacity=100000, error_rate=0.01)
doctor_phone_bloom_filter = CountingBloomFilter(capacity=100000, error_rate=0.01)

TOPIC_NAME = "doctor_CIN"
@auth_doctor.post("/doctor/signup", status_code=status.HTTP_201_CREATED)
async def signup(data: models.doctor, response: Response, request: Request):
    try:
        form_data = dict(data)
        dict_data = dict(form_data)
        dict_data["full_name"] = dict_data["first_name"] + ' ' + dict_data["last_name"]
        dict_data["created_at"] = datetime.now().isoformat()
        dict_data["CIN"] = generate_random_string()
        dict_data["verification_status"] = "false"

        updated_phone_number = dict_data['country_code'] + dict_data['phone_number'] # adding country code to get country name
        country_name = get_country_name(updated_phone_number)
        country_name = country_name.lower()
        dict_data["country_name"] = country_name

        required_fields = ["first_name", "last_name", "email", "password", "phone_number", "country_code"]
        for field in required_fields:
            if field not in dict_data:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="All fields are required")

        # data validation
        if doctor_email_bloom_filter.contains(dict_data["email"]):
            print("email in bloom filter")
            create_new_log("warning", f"Signup attempt with existing email: {dict_data['email']}", "/api/backend/Auth")
            logger.warning(f"Signup attempt with existing email: {dict_data['email']}")
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Email already exists")
        
        else:
            email_in_redis = await client.hgetall(f"doctor:new_account:{dict_data['email']}")
            if email_in_redis:
                print("email in redis")
                create_new_log("warning", f"Signup attempt with existing email: {dict_data['email']}", "/api/backend/Auth")
                logger.warning(f"Signup attempt with existing email: {dict_data['email']}") 
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Email already exists")
            else:
                email = await mongo_client.auth.doctor.find_one({"email": dict_data["email"]})
                if email:
                    print("email in db")
                    create_new_log("warning", f"Signup attempt with existing email: {dict_data['email']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing email: {dict_data['email']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Email already exists")

        if doctor_phone_bloom_filter.contains(dict_data["phone_number"]):
            print("phone number in bloom filter")
            create_new_log("warning", f"Signup attempt with existing phone number: {dict_data['phone_number']}", "/api/backend/Auth")
            logger.warning(f"Signup attempt with existing phone number: {dict_data['phone_number']}")
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Phone number already in use")
        else:
            phone_number_in_redis = await client.hgetall(f"doctor:new_account:{dict_data['phone_number']}")
            if phone_number_in_redis:
                print("phone number in redis")
                create_new_log("warning",f"Signup attempt with existing phone number: {dict_data['phone_number']}", "/api/backend/Auth")
                logger.warning(f"Signup attempt with existing phone number: {dict_data['phone_number']}")
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Phone number already in use")
            else:
                phone_number = await mongo_client.auth.doctor.find_one({"phone_number": dict_data["phone_number"]})
                if phone_number:
                    print("phone number in db")
                    create_new_log("warning",f"Signup attempt with existing phone number: {dict_data['phone_number']}", "/api/backend/Auth")
                    logger.warning(f"Signup attempt with existing phone number: {dict_data['phone_number']}")
                    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail = "Phone number already in use")

        if(form_data["phone_number"].__len__() < 10 or form_data["phone_number"].__len__() > 10):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Phone number must be 10 digits long")
        
        if not(form_data["phone_number"].isdigit()):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Phone number must be digits only")
        if(form_data["password"].__len__() < 6):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Password must be at least 6 characters long")
        if(form_data["email"].__contains__("@") == False):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Invalid email address")
        if(form_data["first_name"].__len__() < 2):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "First name must be greater than 1 character")
        if(form_data["last_name"].__len__() < 2):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "Last name must be greater than 1 character")
        if(form_data["email"].__len__() < 4):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email must be greater than 3 characters") 


        # hashing the password
        hashed_password = Hash.bcrypt(dict_data["password"])
        dict_data["password"] = hashed_password
        doctor_email_bloom_filter.add(dict_data["email"])
        doctor_phone_bloom_filter.add(dict_data["phone_number"])
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
                                                            "data":dict_data['email'],
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"doctor:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        # send all data in cache 
        cache_key = dict_data["email"]
        await client.hset(f"doctor:new_account:{cache_key}", mapping=dict_data)
        await client.expire(f"doctor:new_account:{cache_key}", 691200)  # expire in 7 days
        # producer.send(TOPIC_NAME, value={"CIN":dict_data["CIN"]}) # send CIN to kafka topic
        # producer.flush() # flush the producer
        await client.hset(f"doctor:new_account:{dict_data['phone_number']}", mapping=dict_data)
        await client.expire(f"doctor:new_account:{dict_data['phone_number']}", 691200)  # expire in 7 days

        #  for instant logging in after signup
        await client.set(f"doctor:auth:2_factor_login:{dict_data['email']}", dict_data["email"], ex=3600) # expire in 1 hour
        await client.set(f"doctor:auth:2_factor_login:{dict_data['phone_number']}", dict_data["phone_number"], ex=3600) # expire in 1 hour

        # await mongo_client.auth.doctor.insert_one(dict_data)  # Insert into MongoDB  --> #  this will be done when user verifies himself
        create_new_log("info", f"Account for doctor created successfully: {dict_data['email']}", "/api/backend/Auth")
        logger.info(f"Account for doctor created successfully: {dict_data['email']}") # log the cache hit
        
        access_token = auth_token.create_access_token(data={"sub": dict_data['email']})
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
        
        # html_path = "/root/CuraDocs_Auth/authentication/templates/index.html" # -> for production
        html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates', 'index.html') # in local testing
        with open(html_path,'r') as file:
            html_body = file.read()
        # send email verification link
        email_sent = send_email(dict_data["email"], "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5)
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

        # dict_data["phone_number"] = "+91" + dict_data["phone_number"] # adding country code
        # otp = await send_otp_sns(dict_data["phone_number"])
        # if not otp:
        #     raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
        
        # return {"message":f"OTP sent successfully on {form_data['phone_number'][:6]+'x'*6+dict_data['phone_number'][13:]} and {dict_data['email']}"} # Return success message
        return {"message":f"Account for doctor created successfully: {dict_data['email']}", "status_code":status.HTTP_201_CREATED, "token_type":"Bearer", "CIN":dict_data["CIN"], "created_at":dict_data["created_at"]}


    except Exception as e:
        print(f"Error creating new user: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error creating new user: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error creating new user: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
# ***********************************************************************************************************************************************


# @auth_doctor.post("/verify_otp_signup", status_code=status.HTTP_200_OK) # verify otp
# async def verify_otp_signup(data: models.verify_otp_signup):
#     try:
#         form_data = dict(data)
#         email = form_data.get("email")
#         phone_number = form_data.get("phone_number")
#         country_code = form_data.get("country_code")
#         if email:
#             otp =  await generate_otp(email)
#             otp = str(otp)
#             encrypted_otp = Hash.bcrypt(otp)
        
#             html_body = f"""
#                             <html>
#                             <body style="font-family: Arial, sans-serif; background-color: #f5f7fa; padding: 20px;">

#     <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: auto; background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px;">
#         <tr>
#             <td style="padding: 20px; text-align: center;">
#                 <h2 style="color: #2c3e50; margin-bottom: 10px;">Verify Your Email</h2>
#                 <p style="color: #7f8c8d; font-size: 14px;">Hi there,</p>
#                 <p style="color: #7f8c8d; font-size: 14px; margin-bottom: 20px;">
#                     Thank you for signing up with <strong>CuraDocs</strong>! To complete your registration, please verify your email address by using the OTP below.
#                 </p>
#                 <div style="background-color: #ecf0f1; padding: 15px; border-radius: 4px; display: inline-block;">
#                     <span style="font-size: 24px; font-weight: bold; color: #2c3e50;">{otp}</span>
#                 </div>
#                 <p style="color: #7f8c8d; font-size: 12px; margin-top: 20px;">This OTP is valid for 10 minutes. Please do not share this code with anyone.</p>
#                 <p style="color: #bdc3c7; font-size: 12px; margin-top: 40px;">&copy; 2025 CuraDocs. All rights reserved.</p>
#             </td>
#         </tr>
#     </table>

# </body>
#                             </html>
#                             """
#             # send email verification link
#             email_sent = (send_email(email, "Welcome to CuraDocs. Lets build your health Profile", html_body, retries=3, delay=5))
#             if not email_sent:
#                 raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")

#             # otp_entered = form_data.get("otp")
#             # if not otp_entered or len(otp_entered) != 6:
#             #     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
#             # otp_stored = await client.hgetall(email)
#             # print(otp_stored) # debug
#             # if not otp_stored or (otp_stored.get('otp') != otp_entered):
#             #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
#             # access_token = auth_token.create_access_token(data={"sub": email})
#             # print("Access token:", access_token)  # debug
#             # mongodb_document = {
#             #     "full_name": otp_stored.get("full_name"),
#             #     "email": otp_stored.get("email"),
#             #     "password": otp_stored.get("password"),
#             #     "phone_number": otp_stored.get("phone_number"),
#             #     "created_at": otp_stored.get("created_at"),
#             #     "CIN": otp_stored.get("CIN")
#             # }
#             # user = await mongo_client.auth.doctor.find_one({"email": otp_stored.get("email")})
#             # if user:
#             #     raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")
#             # # Insert into MongoDB
#             # await mongo_client.auth.doctor.insert_one(mongodb_document)


#             # response.delete_cookie("access_token")  # Remove old token
#             # response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)
#             # print(f"{email} signed up succesfully as doctor")  # Return success message
#             print("otp sent successfuly")
#             create_new_log("info", f"otp sent successfuly on {email}", "/api/backend/Auth")
#             logger.info(f"otp sent successfuly on {email}") # log the cache hit
#             return ({"message":f"otp sent successfuly on {email}", "status": status.HTTP_200_OK, "otp": encrypted_otp})
#         elif phone_number:
#             phone_number = country_code + phone_number # adding country code

#             res = await send_otp(phone_number)
#             if not res:
#                 raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
#             otp = str(res)

#             encrypted_otp = Hash.bcrypt(otp)
#             print("otp sent successfuly")
#             create_new_log("info", f"otp sent successfuly on {phone_number}", "/api/backend/Auth")
#             logger.info(f"otp sent successfuly on {phone_number}") # log the cache hit
#             return ({"message":f"otp sent successfuly on {phone_number}", "status": status.HTTP_200_OK, "otp": encrypted_otp})
        
#     except Exception as e:
#         print(f"Error verifying OTP: {str(e)}")
#         formatted_error = traceback.format_exc()
#         create_new_log("error", f"Error verifying OTP: {formatted_error}", "/api/backend/Auth")
#         logger.error(f"Error verifying OTP: {str(e)}") # log the cache hit
#         print(f"Error: {traceback.format_exc()}")
#         formatted_error = traceback.format_exc()
#         print(f"Formatted Error: {formatted_error}")
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    


# async def login(response: Response, request: Request, form_data: OAuth2doctorRequestForm = Depends(), auth_token: OAuth2PasswordBearer = Depends(oauth2.oauth2_scheme)): -> for locking the route use this instead of below

# ***************** login through email/phone_number and otp ****************************************************
@auth_doctor.post("/doctor/login_otp", status_code=status.HTTP_200_OK) # login using email 
async def login(data: models.login_otp):
    try:
        form_data = dict(data)

        email_provided = form_data.get("email", None)
        phone_number_provided = form_data.get("phone_number", None)
        country_code = form_data.get("country_code", None)

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
<body style="font-family: Arial, sans-serif; background-color: #f5f7fa; padding: 20px;">

    <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: auto; background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px;">
        <tr>
            <td style="padding: 20px; text-align: center;">
                <h2 style="color: #2c3e50; margin-bottom: 10px;">Login to CuraDocs</h2>
                <p style="color: #7f8c8d; font-size: 14px;">Hello,</p>
                <p style="color: #7f8c8d; font-size: 14px; margin-bottom: 20px;">
                    You requested an OTP to log in to your <strong>CuraDocs</strong> account. Please use the code below to proceed.
                </p>
                <div style="background-color: #ecf0f1; padding: 15px; border-radius: 4px; display: inline-block;">
                    <span style="font-size: 24px; font-weight: bold; color: #2c3e50;">{otp}</span>
                </div>
                <p style="color: #7f8c8d; font-size: 12px; margin-top: 20px;">This OTP will expire in 10 minutes. For your safety, do not share this code with anyone.</p>
                <p style="color: #bdc3c7; font-size: 12px; margin-top: 40px;">&copy; 2025 CuraDocs. All rights reserved.</p>
            </td>
        </tr>
    </table>

</body>
                                    </html>
                                    """
                    # send otp via email
                    email_sent = (send_email(form_data["email"], "Login to CuraDocs using the provided otp", html_body, retries=3, delay=5))
                    if not email_sent:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")
                    create_new_log("info", f"otp sent successfuly on {email_provided}", "/api/backend/Auth")
                    logger.info(f"otp sent successfuly on {email_provided}") # log the cache hit
                    return {"message": f"OTP sent successfully on {email_provided}", "status_code":status.HTTP_200_OK}

                    
                print("cache data returned none") # debug
                create_new_log("warning", f"login attempt with invalid credentials: {form_data['email']}", "/api/backend/Auth")
                logger.warning(f"login attempt with invalid credentials: {form_data['email']}") # log the cache hit
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

            # login using phone_number and password
            elif phone_number_provided:
                # Generate a cache key based on login identifier
                cache_key = phone_number_provided
                cached_data = await cache_without_password(cache_key)
                if cached_data:
                    print("cache data returned", cached_data) # debug
                    #  sending otp
                    phone_number_provided = country_code + phone_number_provided # adding country code
                    res = await send_otp(phone_number_provided)
                    if not res:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending OTP")
                    create_new_log("info", f"otp sent successfuly on {phone_number_provided}", "/api/backend/Auth")
                    logger.info(f"otp sent successfuly on {phone_number_provided}") # log the cache hit
                    return {"message": f"OTP sent successfully on {phone_number_provided[:5]+'x'*6+phone_number_provided[13:]}", "status_code":status.HTTP_200_OK} # masking the phone number for security

                print("cache data returned none") # debug
                create_new_log("warning", f"login attempt with invalid credentials: {form_data['phone_number']}", "/api/backend/Auth")
                logger.warning(f"login attempt with invalid credentials: {form_data['phone_number']}") # log the cache hit
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
                
    except Exception as e:
        print(f"login attempt failed: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"login attempt failed: {formatted_error}", "/api/backend/Auth")
        logger.error(f"login attempt failed: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
# ***************************************************************************************************************************************************************



@auth_doctor.post("/doctor/verify_otp_login_email", status_code=status.HTTP_200_OK) 
async def verify_otp(data: models.otp_email, response: Response, request: Request):
    try:
        form_data = dict(data)
        email = form_data.get("email")
        otp_entered = form_data.get("otp")
        incoming_refresh_token = request.cookies.get("refresh_token") or request.headers.get("refresh_token") or request.query_params.get("refresh_token") 
        print(otp_entered) # debug
        if not otp_entered or len(otp_entered) != 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
        otp_stored = await client.hgetall(f"otp:{email}")
        print(otp_stored) # debug
        if not otp_stored or (otp_stored.get('otp') != otp_entered):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        
        device_fingerprint = generate_fingerprint_hash(request)
        encrypyted_device_fingerprint = Hash.bcrypt(device_fingerprint) # encrypting device fingerprint
        session_id = create_session_id()
        encrypyted_session_id = Hash.bcrypt(session_id) # encrypting session id
        # access_token
        access_token = auth_token.create_access_token(data={"sub": email})
        print("Access token:", access_token)  # debug
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)

        # refresh token
        refresh_token = auth_token.create_refresh_token(data={
                                                                "sub": session_id,
                                                                "data": device_fingerprint})
        response.delete_cookie("refresh_token")  # Remove old token
        response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
        encrypted_refresh_token = Hash.bcrypt(refresh_token)
        if incoming_refresh_token:
            await client.delete(f"doctor:refresh_token:{incoming_refresh_token[:106]}")
        await client.hset(f"doctor:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":email,
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"doctor:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        print(f"{email} logged in succesfully")  # Return success message
        create_new_log("info", f"{email} logged in successfully", "/api/backend/Auth")
        logger.info(f"{email} logged in successfully") # log the cache hit
        return {"message":f"OTP verified successfully from {email}", "status_code":status.HTTP_200_OK, "token_type":"Bearer", "email":email}
                         
    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error verifying OTP: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error verifying OTP: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@auth_doctor.post("/doctor/verify_otp_login_phone", status_code=status.HTTP_200_OK)
async def verify(data: models.otp_phone, response: Response, request: Request):
    try:
        form_data = dict(data)
        phone_number = form_data.get("phone_number")
        country_code = form_data.get("country_code")
        incoming_refresh_token = request.cookies.get("refresh_token") or request.headers.get("refresh_token") or request.query_params.get("refresh_token") 

        phone_number = country_code + phone_number # adding country code
        otp_entered = form_data.get("otp")
        print(otp_entered)
        if not otp_entered or len(otp_entered) != 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP required")
        otp_stored = await client.hgetall(f"otp:{phone_number}")
        print(otp_stored)
        if not otp_stored or (otp_stored.get('otp') != otp_entered):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
        
        device_fingerprint = generate_fingerprint_hash(request)
        encrypyted_device_fingerprint = Hash.bcrypt(device_fingerprint) # encrypting device fingerprint
        session_id = create_session_id()
        encrypyted_session_id = Hash.bcrypt(session_id) # encrypting session id

        # access_token
        access_token = auth_token.create_access_token(data={"sub": phone_number})
        print("Access token:", access_token)  # debug
        response.delete_cookie("access_token")  # Remove old token
        response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)

        # refresh token
        refresh_token = auth_token.create_refresh_token(data={
                                                                "sub": session_id,
                                                                "data": device_fingerprint})
        response.delete_cookie("refresh_token")  # Remove old token
        response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
        encrypted_refresh_token = Hash.bcrypt(refresh_token)
        if incoming_refresh_token:
            await client.delete(f"doctor:refresh_token:{incoming_refresh_token[:106]}") # delete old refresh token from redis -> email
        await client.hset(f"doctor:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":phone_number,
                                                            "session_id":encrypyted_session_id})
        await client.expire(f"doctor:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

        print(f"{phone_number} logged in succesfully")  # Return success message
        create_new_log("info", f"{phone_number} logged in successfully", "/api/backend/Auth")
        logger.info(f"{phone_number} logged in successfully") # log the cache hit
        return {"message":f"OTP verified successfully from {phone_number}", "status_code":status.HTTP_200_OK, "token_type":"Bearer", "phone_number":phone_number}

    except Exception as e:
        print(f"Error verifying OTP: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error verifying OTP: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error verifying OTP: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))



# ********************************************************************* login with email/phone_number and password ************************************
@auth_doctor.post("/doctor/login", status_code=status.HTTP_200_OK) # login using email and password

# @limiter.limit("5/minute")  #******************************* Rate limit *********************************************************************
async def login(data: models.login, response: Response, request: Request):
    try:
        form_data = dict(data)

        email_provided = form_data.get("email", None)
        password_provided = form_data.get("password", None)
        phone_number_provided = form_data.get("phone_number", None)
        incoming_refresh_token = request.cookies.get("refresh_token") or request.headers.get("refresh_token") or request.query_params.get("refresh_token") 

        # check if email or doctor_user_name or password is provided
        if not password_provided:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is required")
        
        if not email_provided and not phone_number_provided:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or phone number is required")
        
        else:
            # login using email and password
            if email_provided:
                # Generate a cache key based on login identifier
                cache_key = email_provided
                cached_data = await cache(cache_key, password_provided)
                if cached_data:
                    print("cache data returned", cached_data) # debug

                    device_fingerprint = generate_fingerprint_hash(request)
                    encrypyted_device_fingerprint = Hash.bcrypt(device_fingerprint) # encrypting device fingerprint
                    session_id = create_session_id()
                    encrypyted_session_id = Hash.bcrypt(session_id) # encrypting session id
                    # access token
                    access_token = auth_token.create_access_token(data={"sub": email_provided})
                    response.delete_cookie("access_token")  # Remove old token
                    response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)

                    # refresh token
                    refresh_token = auth_token.create_refresh_token(data={
                                                                            "sub": session_id,
                                                                            "data": device_fingerprint})
                    encrypted_refresh_token = Hash.bcrypt(refresh_token)
                    if incoming_refresh_token:
                        await client.delete(f"doctor:refresh_token:{incoming_refresh_token[:106]}") # delete old refresh token from redis
                    response.delete_cookie("refresh_token")  # Remove old token
                    response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
                    await client.hset(f"doctor:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":email_provided,
                                                            "session_id":encrypyted_session_id})
                    await client.expire(f"doctor:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

                    # log 
                    create_new_log("info", f"{email_provided} logged in successfully", "/api/backend/Auth" )
                    logger.info(f"{email_provided} logged in successfully") 
                    
                    # RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_200_OK)
                    return {"message":f"{email_provided} logged in succesfully", "status_code":status.HTTP_200_OK, "token_type": "Bearer", "email": email_provided}  # Return success message

                print("cache data returned none") # debug
                create_new_log("warning", f"login attempt with invalid Invalid credentials: {form_data['email']} ; {form_data['password']}", "/api/backend/Auth")
                logger.warning(f"login attempt with invalid Invalid credentials: {form_data['email']} ; {form_data['password']}") # log the cache hit
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

            # login using phone_number and password
            elif phone_number_provided:
                # Generate a cache key based on login identifier
                cache_key = phone_number_provided
                cached_data = await cache(cache_key, password_provided)
                if cached_data:
                    print("cache data returned", cached_data) # debug

                    device_fingerprint = generate_fingerprint_hash(request)
                    encrypyted_device_fingerprint = Hash.bcrypt(device_fingerprint) # encrypting device fingerprint
                    session_id = create_session_id()
                    encrypyted_session_id = Hash.bcrypt(session_id) # encrypting session id
                    # access token
                    access_token = auth_token.create_access_token(data={"sub": phone_number_provided})
                    response.delete_cookie("access_token")  # Remove old token
                    response.set_cookie(key="access_token", value=access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False)

                    # refresh token
                    refresh_token = auth_token.create_refresh_token(data={
                                                                            "sub": session_id,
                                                                            "data": device_fingerprint})
                    encrypted_refresh_token = Hash.bcrypt(refresh_token)
                    if incoming_refresh_token:
                        await client.delete(f"doctor:refresh_token:{incoming_refresh_token[:106]}") # delete old refresh token from redis
                    response.delete_cookie("refresh_token")  # Remove old token
                    response.set_cookie(key="refresh_token", value=refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
                    await client.hset(f"doctor:refresh_token:{refresh_token[:106]}",mapping={
                                                            "refresh_token": encrypted_refresh_token,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "data":phone_number_provided,
                                                            "session_id":encrypyted_session_id})
                    await client.expire(f"doctor:refresh_token:{refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis

                    create_new_log("info", f"{phone_number_provided} logged in successfully", "/api/backend/Auth")
                    logger.info(f"{phone_number_provided} logged in successfully") # log the cache hit
                    # RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_200_OK)
                    return {"message":f"{phone_number_provided[:4]+'x'*6+phone_number_provided[11:]} logged in succesfully", "status_code":status.HTTP_200_OK, "token_type": "Bearer", "phone_number": phone_number_provided}  # Return success message

                print("cache data returned none") # debug
                create_new_log("warning", f"login attempt with invalid credentials: {form_data['phone_number']} ; {form_data['password']}", "/api/backend/Auth")
                logger.warning(f"login attempt with invalid credentials: {form_data['phone_number']} ; {form_data['password']}") # log the cache hit
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
            
    except Exception as e:
        print(f"login attempt failed: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"login attempt failed: {formatted_error}", "/api/backend/Auth")
        logger.error(f"login attempt failed: {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        print(f"Formatted Error: {formatted_error}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
# ***************************************************************************************************************************************************************
   
# ************ this still needs to be done ********************************************************************************************************************

@auth_doctor.post("/doctor/refresh_token", status_code=status.HTTP_200_OK)
async def refresh_token(request: Request, response: Response):
    try:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"})
        
        #  handling incoming refresh token
        incoming_refresh_token = request.cookies.get("refresh_token") or request.headers.get("refresh_token") or request.query_params.get("refresh_token") 
        if not incoming_refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token required")
        incoming_session_id = auth_token.decode_token(incoming_refresh_token, credentials_exception) # verify access token and getting the session_id from it
        incoming_device_fingireprint = auth_token.decode_token_data(incoming_refresh_token, credentials_exception) # verify access token and getting the device_fingerprint from it
        # incoming_session_id = request.cookies.get("session_id") or request.headers.get("session_id") or request.query_params.get("session_id")

        print("incoming refresh token:",incoming_refresh_token) # debug
        print("incoming session id:",incoming_session_id) # debug
        
        #  handling stored refresh token
        stored_refresh_token_in_redis = await client.hgetall(f"doctor:refresh_token:{incoming_refresh_token[:106]}")  # get refresh token from redis
        print("stored refresh token from redis:",stored_refresh_token_in_redis) # debug

        extra_data = stored_refresh_token_in_redis.get("data") # extract data from redis data
        stored_refresh_token = stored_refresh_token_in_redis.get("refresh_token") # extract refresh_token from redis data
        stored_session_id = stored_refresh_token_in_redis.get("session_id") # extract session_id from redis data
        stored_device_fingerprint = stored_refresh_token_in_redis.get("device_fingerprint") # extract device_fingerprint from redis data

        print("stored refresh token:",stored_refresh_token) # debug
        print("stored session id:",stored_session_id) # debug
        print("stored device fingerprint:",stored_device_fingerprint) # debug

        if not stored_refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
        if not stored_device_fingerprint:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device fingerprint")
        if not stored_session_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session id")
        
        verify_refresh_token = await Hash.verify(stored_refresh_token, incoming_refresh_token)
        verify_device_fingerprint = await Hash.verify(stored_device_fingerprint, incoming_device_fingireprint)
        verify_session_id = await Hash.verify(stored_session_id, incoming_session_id)

        if verify_refresh_token and verify_device_fingerprint and verify_session_id:  # if refresh token is valid, give access token
            print({"refresh_token":"valid", "device_fingerprint":"valid", "session_id":"valid"}) # debug
            await client.delete(f"doctor:refresh_token:{incoming_refresh_token[:106]}")

            device_fingerprint = generate_fingerprint_hash(request)
            encrypyted_device_fingerprint = Hash.bcrypt(device_fingerprint) # encrypting device fingerprint
            session_id = create_session_id()
            encrypyted_session_id = Hash.bcrypt(session_id) # encrypting session id
            # access token
            new_access_token = auth_token.create_access_token(data={"sub": extra_data})
            response.delete_cookie("access_token")  # Remove old token
            response.set_cookie(key="access_token", value=new_access_token, max_age=3600, path="/", samesite="lax", httponly=True, secure=False) # access token expires in 1 hour

            # refresh token
            new_refresh_token = auth_token.create_refresh_token(data={
                                                                        "sub": session_id,
                                                                        "data":device_fingerprint})
            response.delete_cookie("refresh_token")  # Remove old token
            response.set_cookie(key="refresh_token", value=new_refresh_token, max_age=691200, path="/", samesite="lax", httponly=True, secure=False) # refresh token expires in 7 days
            new_enctrpted_refresh_token = Hash.bcrypt(new_refresh_token)
            await client.hset(f"doctor:refresh_token:{new_refresh_token[:106]}",mapping={
                                                            "refresh_token": new_enctrpted_refresh_token,
                                                            "data":extra_data,
                                                            "device_fingerprint":encrypyted_device_fingerprint,
                                                            "session_id":encrypyted_session_id})
            await client.expire(f"doctor:refresh_token:{new_refresh_token[:106]}", 691200) # expire in 7 days -> storing refresh token in redis
            create_new_log("info", f"Refresh token verified for {device_fingerprint} -> device_fingerprint", "/api/backend/Auth")
            logger.info(f"Refresh token verified for {device_fingerprint} -> device_fingerprint") # log the cache hit
            return({"status_code":status.HTTP_200_OK, "message":"Refresh token verified,doctor logged in", "token_type":"Bearer"})
        
      
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error refreshing token: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error refreshing token: {str(e)}") # log the cache hit
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    
@auth_doctor.post("/doctor/reset_password", status_code=status.HTTP_200_OK)
async def reset_password(data: models.email):
    try:
        form_data = dict(data)
        email = form_data.get("email")
        if not email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is required")
        user = await mongo_client.auth.doctor.find_one({"email": email})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")        # token = create_verification_token({"email":email})
        # reset_link = f"http://127.0.0.1:8000/patient/create_new_password/{token}"
        otp = await generate_otp(email)
        hashed_otp = Hash.bcrypt(otp)
        html_body = f"""
                    <html>
<body style="font-family: Arial, sans-serif; background-color: #f0f2f5; padding: 30px;">

    <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: auto; background-color: #ffffff; border: 1px solid #dcdfe6; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.05);">
        <tr>
            <td style="padding: 30px; text-align: center;">
                <h1 style="color: #2c3e50; font-size: 24px; margin-bottom: 10px;">Reset Your Password</h1>
                <p style="color: #606f7b; font-size: 15px; margin-bottom: 25px;">
                    Hello,
                </p>
                <p style="color: #606f7b; font-size: 15px; margin-bottom: 20px;">
                    We received a request to reset the password for your <strong>CuraDocs</strong> account. Please use the below otp for creaing a new password.
                </p>
                <span style="font-size: 24px; font-weight: bold; color: #2c3e50;">{otp}</span>
                <p style="color: #606f7b; font-size: 13px; margin-bottom: 30px;">
                    If you did not request this, you can safely ignore this email.
                </p>
                <p style="color: #606f7b; font-size: 12px;">Need help? Contact our support team at <p>support@curadocs.com"</p> style="color: #1d72b8; text-decoration: none;">support@curadocs.com</a></p>
                <p style="color: #a0aec0; font-size: 12px;">&copy; 2025 CuraDocs | All rights reserved.</p>
            </td>
        </tr>
    </table>
</body>

</html>
                    """
        
        # send email verification link
        email_sent = (send_email(email, "Password Reset Request", html_body, retries=3, delay=5))
        if not email_sent:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error sending email")
        create_new_log("info", f"Password reset otp sent successfully to {email}", "/api/backend/Auth")
        logger.info(f"Password reset otp sent successfully to {email}") 
        return ({"message": "Password reset otp sent successfully", "status_code": status.HTTP_200_OK, "otp": hashed_otp}) # Return success message # Return success message
    
    except Exception as e:
        print(f"Error resetting password: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error sending reset password otp: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error sending reset password otp: {str(e)}") # log the cache hit
        print(f"Error: {formatted_error}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
        

# @auth_doctor.get("/doctor/reset_password", status_code=status.HTTP_200_OK)
# async def reset_password_form(request: Request):
#     return templates.TemplateResponse("reset_password.html", {"request": request}, status_code=status.HTTP_200_OK)


@auth_doctor.post("/doctor/create_new_password", status_code=status.HTTP_200_OK) 
async def create_new_password(data: models.reset_password):
    try:
        # token_data = decode_verification_token(token)
        # email = token_data["email"]
        form_data = dict(data)
        email = form_data.get("email")
        
        user = await mongo_client.auth.doctor.find_one({"email": email})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        print(user) # debug
        password = form_data.get("password")
        confirm_password = form_data.get("confirm_password")
        
        last_used_password = await Hash.verify(user["password"], password)

        if not password or not confirm_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password and confirm password are required")
        if password != confirm_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")
        if len(password) < 6:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 6 characters long")
        if last_used_password:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password cannot be the same as the last one")
        
        hashed_password = Hash.bcrypt(password)
        # If bcrypt returns bytes, decode to string for MongoDB storage
        hashed_password = hashed_password.encode('utf-8')
        result = await mongo_client.auth.doctor.update_one({"email": email}, {"$set": {"password": hashed_password}})
        await client.hset(f"doctor:auth:{email}",mapping={
                                                            "data":email,
                                                            "password": hashed_password})
        # Check if user was updated
        if result.modified_count == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        create_new_log("info", f"Password reset successfully for {email}", "/api/backend/Auth")
        logger.info(f"Password reset successfully for {email}")
        return ({"message": "Password updated successfully", "status_code": status.HTTP_200_OK}) # Return success message
    
    except Exception as e:
        print(f"Error creating new password: {str(e)}")
        formatted_error = traceback.format_exc()
        create_new_log("error", f"Error creating new password: {formatted_error}", "/api/backend/Auth")
        logger.error(f"Error creating new password: {str(e)}") # log the cache hit
        print(f"Error: {formatted_error}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@auth_doctor.post("/doctor/logout", status_code=status.HTTP_200_OK)
async def logout(data: models.email, response: Response, request: Request):
    incoming_refresh_token = request.cookies.get("refresh_token") or request.headers.get("refresh_token") or request.query_params.get("refresh_token")
    form_data = dict(data)
    email = form_data.get("email")
    if incoming_refresh_token:
        await client.delete(f"doctor:refresh_token:{incoming_refresh_token[:106]}")
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    create_new_log("info", f"{email} logged out successfully", "/api/backend/Auth")
    logger.info(f"{email} logged out successfully") # log the cache hit
    print(f"{email} logged out successfully") # debug
    return {"message":f"{email} logged out successfully", "status":status.HTTP_200_OK}  # Return success message



# ***********************************************NOT USED ROUTES***************************************************************************************************

# *****************************this route verified otp for signup using phone number, the route are now merged with route for verifying otp using email******************************
# @auth_doctor.post("/doctor/verify_otp_signup_phone", status_code=status.HTTP_200_OK) # verify otp
# async def verify_otp_signup_phone(request: Request):
#     try:
#         form_data = await request.json()
#         phone_number = form_data.get("phone_number")
#         phone_number = "+91" + phone_number # adding country code
#         otp = await send_otp_sns(phone_number)
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
        # create_new_log("info", f"otp verified successfuly through {phone_number}", "/api/backend/Auth")
    #     logger.info(f"otp verified successfuly through {phone_number}") # log the cache hit
    #     return(f"otp verified successfuly through {phone_number}")
       
        
    # except Exception as e:
    #     print(f"Error verifying OTP: {str(e)}")
    #     formatted_error = traceback.format_exc()
        # create_new_log("error", f"Error verifying OTP: {formatted_error}", ""/api/backend/Auth"")
    #     logger.error(f"Error verifying OTP: {str(e)}") # log the cache hit
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
        # create_new_log("info", f"Account for doctor created successfully: {email}", "/api/backend/Auth")
#         logger.info(f"Account for doctor created successfully: {email}") # log the cache hit
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
#         formatted_error = traceback.format_exc()
        # create_new_log("error", f"Error verifying email: {formatted_error}", "/api/backend/Auth")
#         logger.error(f"Error verifying email: {str(e)}") # log the cache hit
#         raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
