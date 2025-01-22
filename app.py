from fastapi import FastAPI
from authentication.auth import auth

app = FastAPI()
app.include_router(auth)
