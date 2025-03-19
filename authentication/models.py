from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field

class patient(BaseModel):
    first_name: str = Field(..., title="First Name of the User")
    last_name: str = Field(..., title="Last Name of the User")
    email: EmailStr = Field(..., title="Email Address")
    phone_number: str = Field(..., min_length=10, title="Phone Number")
    country_code: str = Field(..., title="Country Code")
    password: str = Field(..., title="Password")
 

class doctor(BaseModel):
    first_name: str = Field(..., title="First Name of the User")
    last_name: str = Field(..., title="Last Name of the User")
    email: EmailStr = Field(..., title="Email Address")
    phone_number: str = Field(..., min_length=10, title="Phone Number")
    country_code: str = Field(..., title="Country Code")
    password: str = Field(..., title="Password")

class verify_otp(BaseModel):
    email: Optional[EmailStr] = Field(None, title="Email Address")
    phone_number: Optional[str] = Field(None, min_length=10, title="Phone Number")
    country_code: Optional[str] = Field(None, title="Country Code")


class otp_email(BaseModel):
    otp : str = Field(..., title="OTP")
    email: EmailStr = Field(..., title="Email Address")

class otp_phone(BaseModel):
    otp : str = Field(..., title="OTP")
    phone_number: str = Field(..., min_length=10, title="Phone Number")

class login(BaseModel):
    email: Optional[EmailStr] = Field(None, title="Email Address")
    phone_number: Optional[str] = Field(None, min_length=10, title="Phone Number")
    password: str = Field(..., title="Password")

class email(BaseModel):
    email: EmailStr = Field(None, title="Email Address")

class reset_password(BaseModel):
    password: str = Field(..., title="Password")
    confirm_password: str = Field(..., title="Confirm Password")

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

class UserInDB(patient):
    hashed_password: str

class UserInDB(doctor):
    hashed_password: str
