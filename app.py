from fastapi import FastAPI
from authentication.auth_patient import auth_patient
from authentication.auth_doctor import auth_doctor
from fastapi.middleware.cors import CORSMiddleware
from authentication.google_auth import google_auth
import os
from starlette.middleware.sessions import SessionMiddleware
app = FastAPI()
app.include_router(auth_patient)
app.include_router(auth_doctor)
app.include_router(google_auth)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY"))