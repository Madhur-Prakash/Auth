from fastapi import Depends, HTTPException, status, Form
from . import auth_token
from fastapi.security import OAuth2PasswordBearer 
from typing import Optional

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/patient/mpm/logout")

# this is the route/url from fastapi will be able to fetch the token

def get_current_user(data: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    return auth_token.verify_token(data, credentials_exception)


class OAuth2PatientRequestForm:
    def __init__(
        self,
        patient_user_name: str = Form(...),  # Use patient_user_name instead of username
        password: str = Form(...),
        scope: str = Form(""),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
    ):
        self.patient_user_name = patient_user_name
        self.password = password
        self.scope = scope
        self.client_id = client_id
        self.client_secret = client_secret
