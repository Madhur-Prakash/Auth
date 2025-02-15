from fastapi import FastAPI
from authentication.auth_patient import auth_patient
from authentication.auth_doctor import auth_doctor

app = FastAPI()
app.include_router(auth_patient)
app.include_router(auth_doctor)
