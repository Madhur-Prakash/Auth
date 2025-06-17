from fastapi import Depends, HTTPException, status, Form
from . import auth_token
import traceback
from itsdangerous import URLSafeTimedSerializer
from fastapi.security import OAuth2PasswordBearer 
from typing import Optional
from ..helper.utils import setup_logging, create_new_log  # Import setup_logging from utils

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/jhon/logout")
logger = setup_logging() # initialize logger

# this is the route/url from fastapi will be able to fetch the token

def get_current_user(data: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    return auth_token.verify_token(data, credentials_exception)


class OAuth2UserRequestForm:
    def __init__(
        self,
        email: str = Form(...),  # Use email instead of username
        password: str = Form(...),
        scope: str = Form(""),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
    ):
        self.email = email
        self.password = password
        self.scope = scope
        self.client_id = client_id
        self.client_secret = client_secret


serializer = URLSafeTimedSerializer(
    secret_key = auth_token.SECRET_KEY,
    salt = 'email-confirm')
    
def create_verification_token(data: dict):
    token = serializer.dumps(data) 
    return token

def decode_verification_token(token: str):
    try:
        token_data = serializer.loads(token, max_age=600)
        return token_data
    except Exception as e:
        create_new_log("error", "Error validating user", "/api/backend/Auth")
        logger.exception("Error validating user")
        print(f"Error validating user {str(e)}")
        print(f"Error: {traceback.format_exc()}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
