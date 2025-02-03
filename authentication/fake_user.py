from pymongo import MongoClient
from faker import Faker
from passlib.hash import bcrypt
import random

# Initialize Faker
fake = Faker()

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")  # Change this if your MongoDB is hosted elsewhere

# Function to generate a fake user
def generate_fake_user():
    full_name = fake.name()
    email = fake.email()
    user_name = fake.user_name()
    phone_number = fake.numerify("98########")  # Generates a 10-digit phone number
    password = "Test@123"  # Default password for testing
    hashed_password = bcrypt.hash(password)
    
    return {
        "full_name": full_name,
        "email": email,
        "user_name": user_name,
        "phone_number": phone_number,
        "password": hashed_password,
        "disabled": random.choice([True, False]),
    }

# Number of users to insert
num_users = 182  # Change this as needed

# Generate and insert users
fake_users = [generate_fake_user() for _ in range(num_users)]
client.auth.User.insert_many(fake_users)

print(f"Inserted {num_users} fake users into MongoDB.")
