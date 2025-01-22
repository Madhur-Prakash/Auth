from fastapi import APIRouter, Request, status, HTTPException, Depends
from .database import conn
from motor.motor_asyncio import AsyncIOMotorDatabase
from . import database
from . import schemas
auth = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

get_db = database.get_db


@auth.get("/")
async def read():
    user = conn.authenticator.user.find()
    new_user = []
    for i in user:
        new_user.append({
            "id": i["_id"],
            "full_name": i["full_name"],
            "email": i["email"],
            "password": i["password"],
            "password2": i["password2"],
            "profile_picture": i["profile_picture"],
            "timestramp": i["timestramp"]
        })
    return new_user

@auth.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(request: schemas.user, db:AsyncIOMotorDatabase  = Depends(get_db)):
    data = request.json()
    if data["password"] != data["password2"]:
        raise HTTPException(status_code=400, detail="Password do not match")
    del data["password2"]
    conn.authenticator.user.insert_one(data)
    return {"message": "User created successfully"}