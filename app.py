from fastapi import FastAPI
from authentication.auth_patient import auth_patient
from authentication.auth_doctor import auth_doctor
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.include_router(auth_patient)
app.include_router(auth_doctor)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
