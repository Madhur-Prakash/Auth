from datetime import datetime
from typing import Optional, List
from fastapi.exceptions import HTTPException
from fastapi import status
from pydantic import BaseModel, EmailStr, Field, model_validator

class user(BaseModel):
    first_name: str = Field(..., title="First Name of the User")
    last_name: str = Field(..., title="Last Name of the User")
    email: EmailStr = Field(..., title="Email Address")
    phone_number: str = Field(..., min_length=10, title="Phone Number")
    country_code: str = Field(..., title="Country Code")
    password: str = Field(..., title="Password")
 

class verify_otp_signup(BaseModel):
    email: Optional[EmailStr] = Field(None, title="Email Address")
    phone_number: Optional[str] = Field(None, min_length=10, title="Phone Number")
    country_code: Optional[str] = Field(None, title="Country Code")

    @model_validator(mode='after')
    def country_code_required_if_phone_number(self):
        if self.phone_number and not self.country_code:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "validation_error",
                    "message": "Country code is required when phone_number is provided",
                    "field": "country_code"
                }
            )
        return self

class otp_email(BaseModel):
    otp : str = Field(..., title="OTP")
    email: EmailStr = Field(..., title="Email Address")

class otp_phone(BaseModel):
    otp : str = Field(..., title="OTP")
    phone_number: str = Field(..., min_length=10, title="Phone Number")
    country_code: str = Field(..., title="Country Code")
    
class login(BaseModel):
    email: Optional[EmailStr] = Field(None, title="Email Address")
    phone_number: Optional[str] = Field(None, min_length=10, title="Phone Number")
    password: str = Field(..., title="Password")

class google_login(BaseModel):
    phone_number: str = Field(..., min_length=10, title="Phone Number")
    country_code: str = Field(..., title="Country Code")

class refresh_token(BaseModel):
    refresh_token: str = Field(None, title="Refresh Token")
    session_id: str = Field(None, title="Session ID")
    device_fingerprint: str = Field(None, title="Device Fingerprint")

class logout(BaseModel):
    data: str = Field(..., title="Data to be logged out")

class email(BaseModel):
    email: EmailStr = Field(..., title="Email Address")

class login_otp(BaseModel):
    email: Optional[EmailStr] = Field(None, title="Email Address")
    phone_number: Optional[str] = Field(None, min_length=10, title="Phone Number")
    country_code: Optional[str] = Field(None, title="Country Code")

    @model_validator(mode='after')
    def country_code_required_if_phone_number(self):
        if self.phone_number and not self.country_code:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "validation_error",
                    "message": "Country code is required when phone_number is provided",
                    "field": "country_code"
                }
            )
        return self

class reset_password(BaseModel):
    email: EmailStr = Field(..., title="Email Address")
    password: str = Field(..., title="Password")
    confirm_password: str = Field(..., title="Confirm Password")

class TokenData(BaseModel):
    email: Optional[str] = None

class Login(BaseModel):
    user_user_name: str
    password:str

class res(BaseModel):
    message: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserInDB(user):
    hashed_password: str

