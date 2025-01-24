from fastapi import APIRouter, Request, status, HTTPException, Depends
from .database import conn
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from motor.motor_asyncio import AsyncIOMotorDatabase
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from .hashing import Hash
from datetime import datetime
from . import models,token

auth = APIRouter()
templates = Jinja2Templates(directory="authentication/templates")


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
            "disabled": i["disabled"]
        })
    return templates.TemplateResponse("signup.html", {"request": request, "user": new_user}) 
    

@auth.post("/signup", status_code=status.HTTP_201_CREATED, response_model=models.User)
async def signup(request: Request):
    try:
        form_data = await request.form()
        dict_data = dict(form_data)
        dict_data["created_at"] = datetime.now()

        required_fields = ["full_name", "email", "user_name", "password", "password2"]
        for field in required_fields:
            if field not in dict_data:
                raise HTTPException(status_code=400, detail="All fields are required")

        email = conn.auth.User.find_one({"email": dict_data["email"]})
        user = conn.auth.User.find_one({"user_name": dict_data["user_name"]})
        
        # data validation
        if email:
            raise HTTPException(status_code=400, detail = "Email already exists")
        if user:
            raise HTTPException(status_code=400, detail = "Username already exists")
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
        
        return RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
    
    except Exception as e:
        print(f"Error creating new user: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

    

# @auth.post("/login", status_code=status.HTTP_202_ACCEPTED) # login using email and password
# async def login(request: Request):
    # try:
    #     form_data = await request.form()

    #     email_provided = form_data.get("email", None)
    #     user_name_provided = form_data.get("user_name", None)
    #     password_provided = form_data.get("password", None)

    #     # check if email or user_name or password is provided
    #     if not password_provided:
    #         raise HTTPException(status_code=400, detail="Password is required")
        
    #     if not email_provided:
    #         if not user_name_provided:
    #             raise HTTPException(status_code=400, detail="User Name or Email is required")
    #         else:
    #             return 0
    #             # raise HTTPException(status_code=400, detail="Email is required")
        
    #     else:
    #         user = None # initialize user to None

    #         # login using email and password
    #         if email_provided:
    #             user = conn.auth.User.find_one({"email": form_data["email"]})
    #             if not user:
    #                 raise HTTPException(status_code=400, detail="Email not found")
    #             if not Hash.verify(user["password"], form_data["password"]):
    #                 raise HTTPException(status_code=400, detail="Invalid password")
                
    #             token_data = {
    #                 "email": user["email"]
    #             }
    #             # print(token_data) # for debugging

    #             access_token = token.create_access_token(data={"sub": user["email"]})
    #             return {"access_token": access_token, "token_type": "bearer"}
            
    #         # login using user_name and password
    #         elif user_name_provided:
    #             user = conn.auth.User.find_one({"user_name": form_data["user_name"]})
    #             if not user:
    #                 raise HTTPException(status_code=400, detail="User not found")
    #             if not Hash.verify(user["password"], form_data["password"]):
    #                 raise HTTPException(status_code=400, detail="Invalid password")
                
    #             token_data = {
    #                 "user_name": user["user_name"]
    #             }
    #             # print(token_data) # for debugging

    #             access_token = token.create_access_token(data={"sub": user["user_name"]})
    #             return {"access_token": access_token, "token_type": "bearer"}
    # except Exception as e:
    #     return {"error": str(e)}


@auth.post("/login", status_code=status.HTTP_202_ACCEPTED)
async def login(request: Request):
    try:
        form_data = await request.form()

        email = form_data.get("email")
        user_name = form_data.get("user_name")
        password = form_data.get("password")

        if not password:
            raise HTTPException(status_code=400, detail="Password is required")
        if not email and not user_name:
            raise HTTPException(status_code=400, detail="Provide either email or username")

        # Determine if login is via email or username
        user = None
        if email:
            user = conn.auth.User.find_one({"email": email})
            if not user:
                raise HTTPException(status_code=404, detail="Email not found")
        elif user_name:
            user = conn.auth.User.find_one({"user_name": user_name})
            if not user:
                raise HTTPException(status_code=404, detail="Username not found")

        # Validate password
        if not Hash.verify(user["password"], password):
            raise HTTPException(status_code=400, detail="Invalid password")

        # Generate token
        identifier = user.get("email") or user.get("user_name")
        access_token = token.create_access_token(data={"sub": identifier})

        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        return {"error": str(e)}

    