from fastapi import FastAPI
from fastapi.testclient import TestClient
from ..app import app


@app.get("/")
async def read_main():
    return {"msg": "Hello World"}


client = TestClient(app)

def test_patient_login():
    response = client.post("/patient/login", json={
        "email": "madhurprakash2005@gmail.com",
        "password": "123456"
    })
    assert response.status_code == 200
    assert response.json() == {
        "message": "Login successful",
        "access_token": response.json()["access_token"]}