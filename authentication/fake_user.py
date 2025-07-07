from pymongo import MongoClient
from faker import Faker
import bcrypt
import random
from datetime import datetime

# Initialize Faker
fake = Faker()

# Connect to MongoDB
client = MongoClient("mongodb://ec2-98-80-166-39.compute-1.amazonaws.com:27017/")  # Change this if your MongoDB is hosted elsewhere

# Function to generate a fake user
def generate_fake_user():
    first_name = fake.first_name()
    last_name = fake.last_name()
    email = fake.email()
    phone_number = fake.numerify("##########")  # Generates a 10-digit phone number
    country_code = random.choice(["+1", "+91", "+44", "+61", "+33", "+49", "+81", "+86"])  # Common country codes
    password = "123456"  # Default password for testing
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    full_name = f"{first_name} {last_name}"
    created_at = fake.date_time_between(start_date='-2y', end_date='now').isoformat()
    uid = fake.bothify(text='???#####').upper()  # Generate random UID-like identifier
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
        "UID": uid,
        "verification_status": verification_status,
        "country_name": country_name
    }

# Number of users to insert
num_users = 10  # Change this as needed

# Generate and insert users
fake_users = [generate_fake_user() for _ in range(num_users)]
client.auth.user.insert_many(fake_users)

print(f"Inserted {num_users} fake users into MongoDB.")

# Close the connection
client.close()