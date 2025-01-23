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

        required_fields = ["full_name", "email", "password", "password2"]
        for field in required_fields:
            if field not in dict_data:
                raise HTTPException(status_code=400, detail="All fields are required")

        # # data validation
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
        # passw = dict_data["password"]
        hashed_password = Hash.bcrypt(dict_data["password"])
        # passw = hashed_password
        dict_data["password"] = hashed_password

        # removing the password2 field from db
        dict_data.pop("password2")

        conn.auth.User.insert_one(dict_data)
        
        return RedirectResponse("http://127.0.0.1:8000", status_code=status.HTTP_201_CREATED)
    
    except Exception as e:
        print(f"Error creating new user: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

    

@auth.post("/login", status_code=status.HTTP_202_ACCEPTED)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = conn.auth.User.find_one({"email": form_data.username})
        if not user:
            return {"error": "User not found"}
        if not Hash.verify(user["password"], form_data.password):
            return {"error": "Invalid password"}
        token_data = {
            "email": user["email"]
        }
        token = token.create_token(data=token_data)
        return {"token": token}
    except Exception as e:
        return {"error": str(e)}
    

   