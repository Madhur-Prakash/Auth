from pymongo import MongoClient
from faker import Faker
import bcrypt
import random
from datetime import datetime

# Initialize Faker
fake = Faker()

# Connect to MongoDB
client = MongoClient("mongodb://ec2-98-80-166-39.compute-1.amazonaws.com:27017/")  # Change this if your MongoDB is hosted elsewhere

# Function to generate a fake patient
def generate_fake_patient():
    first_name = fake.first_name()
    last_name = fake.last_name()
    email = fake.email()
    phone_number = fake.numerify("##########")  # Generates a 10-digit phone number
    country_code = random.choice(["+1", "+91", "+44", "+61", "+33", "+49", "+81", "+86"])  # Common country codes
    password = "123456"  # Default password for testing
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    full_name = f"{first_name} {last_name}"
    created_at = fake.date_time_between(start_date='-2y', end_date='now').isoformat()
    cin = fake.bothify(text='???#####').upper()  # Generate random CIN-like identifier
    verification_status = random.choice([True, False])
    country_name = fake.country()
    
    return {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "phone_number": phone_number,
        "country_code": country_code,
        "password": hashed_password,
        "full_name": full_name,
        "created_at": created_at,
        "CIN": cin,
        "verification_status": verification_status,
        "country_name": country_name
    }

# Number of patients to insert
num_patients = 10  # Change this as needed

# Generate and insert patients
fake_patients = [generate_fake_patient() for _ in range(num_patients)]
client.auth.doctor.insert_many(fake_patients)

print(f"Inserted {num_patients} fake patients into MongoDB.")

# Close the connection
client.close()