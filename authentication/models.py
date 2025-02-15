from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class Patient(BaseModel):
    full_name: str = Field(None, title="Full Name of the User")
    email: EmailStr = Field(..., title="Email Address")
    patient_user_name: str = Field(..., title="Username")
    password: str = Field(..., title="Password")
    password2: str = Field(..., title="Confirm Password")
    phone_number: int = Field(..., min_length=10, title="Phone Number")
    disabled: bool = Field(default=False, title="User Account Status")

class Doctor(BaseModel):
    full_name: str = Field(None, title="Full Name of the User")
    email: EmailStr = Field(..., title="Email Address")
    doctor_user_name: str = Field(..., title="Username")
    password: str = Field(..., title="Password")
    password2: str = Field(..., title="Confirm Password")
    phone_number: int = Field(..., min_length=10, title="Phone Number")
    disabled: bool = Field(default=False, title="User Account Status")

class Message(BaseModel):
    sender: str = Field(None, title="Sender ID or Name")
    receiver: str = Field(None, title="Receiver ID or Name")
    message: str = Field(None, title="Message Content")
    timestamp: str = Field(default_factory=lambda: datetime.now().strftime('%Y-%m-%d %H:%M:%S'), title="Timestamp")


class TokenData(BaseModel):
    username: Optional[str] = None

class Login(BaseModel):
    username: str
    password:str


class Token(BaseModel):
    access_token: str
    token_type: str

class UserInDB(Patient):
    hashed_password: str

class UserInDB(Doctor):
    hashed_password: str