from fastapi import APIRouter, Request, status, HTTPException, Depends
from .database import conn
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import aioredis
from .hashing import Hash
from datetime import datetime
from . import models,token

auth = APIRouter()
templates = Jinja2Templates(directory="auth/templates")

# redis connection
client =  aioredis.from_url('redis://localhost', decode_responses=True)

# implemeting cahing using redis
async def cache(data: str):
    email = conn.auth.User.find_one({"email": data})
    user_name = conn.auth.User.find_one({"user_name": data})
    phone_number = conn.auth.User.find_one({"phone_number": data})
    CachedData = await client.get('data')
    if CachedData:
        if email or user_name or phone_number:  
            print("Data is cached") # debug
            return CachedData
    if email or user_name or phone_number:
        res = await client.set("data",data)
        await client.expire('data',30) # expire in 30 seconds
        return res

@auth.get("/", response_class=HTMLResponse)
async def read(request: Request):
    user = conn.authenticator.user.find()
    new_user = []
    for i in user:
        new_user.append({
            "id": i["_id"],
            "full_name": i["full_name"],
            "user_name": i["user_name"],
            "email": i["email"],
            "password": i["password"],
            "password2": i["password2"],
            "phone_number": i["phone_number"],
            "disabled": i["disabled"]
        })
    return templates.TemplateResponse("signup.html", {"request": request, "user": new_user}) 
    

@auth.post("/signup", status_code=status.HTTP_201_CREATED, response_model=models.User)
async def signup(request: Request):
    try:
        form_data = await request.form()
        dict_data = dict(form_data)
        dict_data["created_at"] = datetime.now()

        required_fields = ["full_name", "email", "user_name", "password", "password2", "phone_number"]
        for field in required_fields:
            if field not in dict_data:
                raise HTTPException(status_code=400, detail="All fields are required")

        email = conn.auth.User.find_one({"email": dict_data["email"]})
        user = conn.auth.User.find_one({"user_name": dict_data["user_name"]})
        phone_number = conn.auth.User.find_one({"phone_number": dict_data["phone_number"]})
        
        # data validation
        if email:
            raise HTTPException(status_code=400, detail = "Email already exists")
        if user:
            raise HTTPException(status_code=400, detail = "Username already exists")
        if(form_data["phone_number"].__len__() < 10 or form_data["phone_number"].__len__() > 10):
            raise HTTPException(status_code=400, detail = "Phone number must be 10 digits long")
        if phone_number:
            raise HTTPException(status_code=400, detail = "Phone number already in use")
        if dict_data["password"] != dict_data["password2"]:
            raise HTTPException(status_code=400, detail = "Password do not match")
        if(form_data["password"].__len__() < 6):
            raise HTTPException(status_code=400, detail = "Password must be at least 6 characters long")
        if(form_data["email"].__contains__("@") == False):
            raise HTTPException(status_code=400, detail = "Invalid email address")
        if(form_data["full_name"].__len__() < 2):
            raise HTTPException(status_code=400, detail = "Full name must be greater than 1 character")
        if(form_data["email"].__len__() < 4):
            raise HTTPException("Email must be greater than 3 characters") 


        # hashing the password
        hashed_password = Hash.bcrypt(dict_data["password"])
        dict_data["password"] = hashed_password

        # removing the password2 field from db
        dict_data.pop("password2")

        conn.auth.User.insert_one(dict_data)
        
        # Generate a cache during signup with email as key
        cache_key = dict_data["email"]
        count_doc = conn.auth.User.count_documents({})
        cached_data = await client.set(f"data:{count_doc}",cache_key)
        await client.expire(f"data:{count_doc}",3600) # expire in 30 seconds
        access_token = token.create_access_token(data={"sub": cache_key})
        response = RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
        response.set_cookie(key="access_token", value=access_token, max_age=3600)
        return response
    
    except Exception as e:
        print(f"Error creating new user: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

    

@auth.post("/login", status_code=status.HTTP_202_ACCEPTED) # login using email and password
async def login(request: Request):
    try:
        form_data = await request.form()

        email_provided = form_data.get("email", None)
        user_name_provided = form_data.get("user_name", None)
        password_provided = form_data.get("password", None)
        phone_number_provided = form_data.get("phone_number", None)

        # check if email or user_name or password is provided
        if not password_provided:
            raise HTTPException(status_code=400, detail="Password is required")
        
        if not email_provided and not user_name_provided and not phone_number_provided:
                raise HTTPException(status_code=400, detail="User Name or Email or phone number is required")
        
        else:
            user = None # initialize user to None

            # login using email and password
            if email_provided:
                # Generate a cache key based on login identifier
                cache_key = email_provided
                cached_data = await cache(cache_key)
                if cached_data:
                    access_token = token.create_access_token(data={"sub": cache_key})
                    response = RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
                    response.set_cookie(key="access_token", value=access_token, max_age=3600)
                    return {"access_token": access_token, "token_type": "bearer"}
                
                user = conn.auth.User.find_one({"email": form_data["email"]})
                if not user:
                    raise HTTPException(status_code=400, detail="Invalid Email")
                if not Hash.verify(user["password"], form_data["password"]):
                    raise HTTPException(status_code=400, detail="Invalid password")
                
                access_token = token.create_access_token(data={"sub": user["email"]})
                response = RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
                response.set_cookie(key="access_token", value=access_token, max_age=3600)
            
            # login using user_name and password
            elif user_name_provided:
                # Generate a cache key based on login identifier
                cache_key = user_name_provided
                cached_data = await cache(cache_key)
                if cached_data:
                    access_token = token.create_access_token(data={"sub": cache_key})
                    response = RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
                    response.set_cookie(key="access_token", value=access_token, max_age=3600)
                    return {"access_token": access_token, "token_type": "bearer"}
                
                user = conn.auth.User.find_one({"user_name": form_data["user_name"]})
                if not user:
                    raise HTTPException(status_code=400, detail="Invalid User Name")
                if not Hash.verify(user["password"], form_data["password"]):
                    raise HTTPException(status_code=400, detail="Invalid password")

                access_token = token.create_access_token(data={"sub": user["user_name"]})
                response = RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
                response.set_cookie(key="access_token", value=access_token, max_age=3600)

            # login using phone_number and password
            elif phone_number_provided:
                # Generate a cache key based on login identifier
                cache_key = phone_number_provided
                cached_data = await cache(cache_key)
                if cached_data:
                    access_token = token.create_access_token(data={"sub": cache_key})
                    response = RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
                    response.set_cookie(key="access_token", value=access_token, max_age=3600)
                    return {"access_token": access_token, "token_type": "bearer"}

                user = conn.auth.User.find_one({"phone_number": form_data["phone_number"]})
                if not user:
                    raise HTTPException(status_code=400, detail="Invalid Phone Number")
                if not Hash.verify(user["password"], form_data["password"]):
                    raise HTTPException(status_code=400, detail="Invalid password")
                
                access_token = token.create_access_token(data={"sub": user["phone_number"]})
                response = RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
                response.set_cookie(key="access_token", value=access_token, max_age=3600)

            return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        return {"error": str(e)}

    