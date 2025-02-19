from fastapi import Depends, HTTPException, status
from . import auth_token
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/patient/mpm/logout")

# this is the route/url from fastapi will be able to fetch the token

def get_current_user(data: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    return auth_token.verify_token(data, credentials_exception)