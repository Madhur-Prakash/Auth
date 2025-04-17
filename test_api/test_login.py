import sys
import os
# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import app  # Use absolute import instead of relative import
from authentication.helper.utils import get_country_name,generate_random_string

client = TestClient(app)

# def test_patient_login():
#     response = client.post("/patient/login", json={
#         "email": "madhurprakash772005@gmail.com",
#         "password": "123456"
#     })
#     assert response.status_code == 200
#     assert response.json() == {
#         "message": "Login successful",
#         "access_token": response.json()["access_token"]}
    

def test_patient_signup():
    response = client.post("/patient/signup", json={
        "email": "madhurprakash2005@gmail.com",
        "password": "123456",
        "first_name": "Madhur",
        "last_name": "Prakash",
        "phone_number": "1234567890",
        "country_code": "+91"})
    assert response.status_code == 200
    
        
