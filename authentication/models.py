from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field

class Patient(BaseModel):
    first_name: str = Field(None, title="First Name of the User")
    last_name: str = Field(None, title="Last Name of the User")
    email: EmailStr = Field(..., title="Email Address")
    password: str = Field(..., title="Password")
    phone_number: str = Field(..., min_length=10, title="Phone Number")
    country: str = Field(None, title="Country")
    country_code: str = Field(None, title="Country Code")
 

class Doctor(BaseModel):
    first_name: str = Field(None, title="First Name of the User")
    last_name: str = Field(None, title="Last Name of the User")
    email: EmailStr = Field(..., title="Email Address")
    password: str = Field(..., title="Password")
    phone_number: str = Field(..., min_length=10, title="Phone Number")
    country: str = Field(None, title="Country")
    country_code: str = Field(None, title="Country Code")


class TokenData(BaseModel):
    patient_user_name: Optional[str] = None
    email: Optional[str] = None

class Login(BaseModel):
    patient_user_name: str
    password:str

class res(BaseModel):
    message: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserInDB(Patient):
    hashed_password: str

class UserInDB(Doctor):
    hashed_password: str
