from pymongo import MongoClient
from faker import Faker
from passlib.hash import bcrypt
import random

# Initialize Faker
fake = Faker()

# Connect to MongoDB
client = MongoClient("mongodb://ec2-3-84-251-0.compute-1.amazonaws.com:27017/auth")  # Change this if your MongoDB is hosted elsewhere

# Function to generate a fake user
def generate_fake_user():
    full_name = fake.name()
    email = fake.email()
    patient_user_name = fake.user_name()  # Use a valid Faker method for generating usernames
    phone_number = fake.numerify("98########")  # Generates a 10-digit phone number
    password = "123456"  # Default password for testing
    hashed_password = bcrypt.hash(password)
    
    return {
        "full_name": full_name,
        "email": email,
        "patient_user_name": patient_user_name,
        "phone_number": phone_number,
        "password": hashed_password,
        "disabled": random.choice([True, False]),
    }

# Number of users to insert
num_users = 10000  # Change this as needed

# Generate and insert users
fake_users = [generate_fake_user() for _ in range(num_users)]
client.auth.patient.insert_many(fake_users)

print(f"Inserted {num_users} fake users into MongoDB.")
