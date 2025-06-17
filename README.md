# Authentication

**A Full-Fledged Authentication System with Production-Level Concepts**

## Overview
This repository implements a robust authentication system using FastAPI, incorporating production-level concepts such as caching with Redis, message queuing with Kafka, and database storage with MongoDB. It utilizes bloom filters for fast lookup, a technique employed by tech giants like Google, Amazon, and Facebook. The system implements JWT authentication and access tokens, ensuring secure and efficient user authentication.

---

## Features
- **Multiple Authentication Methods**: Supports email-password, username-password, and phone number-password combinations.
- **Secure Password Handling**: Implements password hashing using industry-standard algorithms.
- **Fast and Scalable**: Built with FastAPI for high performance and scalability.
- **MongoDB Integration**: Stores user credentials and data in a reliable NoSQL database.
- **Redis Caching**: Enhances performance with caching using Redis.
- **Kafka Message Queue**: Utilizes Kafka for efficient message queuing.
- **Bloom Filters**: Employs bloom filters for fast lookup, as used by tech giants like Google, Amazon, and Facebook.
- **JWT Authentication**: Implements JWT authentication for secure and efficient user authentication.
- **Access Tokens**: Utilizes access tokens for secure authentication.
- **OTP Service**: Offers OTP service via mail and SMS, with support for AWS SNS and AWS SMS.
- **Refresh Token**: Implements refresh token logic for password-less login.
- **Google OAuth2**: Supports Google OAuth2 for user signup and login through their Google account.

---

## Technology Stack
- **Backend Framework**: FastAPI
- **Database**: MongoDB
- **Caching**: Redis
- **Message Queue**: Kafka
- **Password Hashing**: Industry-standard algorithms
- **Programming Language**: Python
- **OTP Service**: Supports mail and SMS, with AWS SNS and AWS SMS integration
- **Google OAuth2**: Supports user signup and login through Google account

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Madhur-Prakash/Auth.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Auth
   ```
3. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Set up MongoDB:
```bash
   # Install MongoDB and start the service.
   # Configure the MongoDB URI in the `.env` file.
   ```

6. Set up Redis:
```bash
   # Make sure Redis is running on localhost:6379
   ```

7. Set up Kafka:
```bash
   # Use docker compose to setup Kafka
```

8. Set up .env:
```plaintext
SECRET_KEY = "YOUR_SECRET_KEY"
ALGORITHM = "YOUR_ALGORITHM"
ACCESS_TOKEN_EXPIRE_MINUTES = "30" 
REFRESH_TOKEN_EXPIRE_DAYS = "7"
GOOGLE_CLIENT_SECRET = "YOUR_GOOGLE_CLIENT_SECRET"
GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID"
SESSION_SECRET_KEY = "YOUR_SESSION_SECRET_KEY"
AWS_ACCESS_KEY_ID = "YOUR_AWS_ACCESS_KEY_ID"
AWS_SECRET_ACCESS_KEY = "YOUR_AWS_SECRET_ACCESS_KEY"
AWS_REGION = "YOUR_AWS_REGION"
NO_REPLY_EMAIL = "YOUR_NO_REPLY_EMAIL"
ACCOUNT_SID = "YOUR_TWILIO_ACCOUNT_SID"
AUTH_TOKEN = "YOUR_TWILIO_AUTH_TOKEN"
```
---

## Usage

1. Start the FastAPI server:
   ```bash
   uvicorn app:app --reload
   ```
2. Access the API documentation at:
   ```
   http://127.0.0.1:8000/docs
   # for detailed docs visit 👉 http://127.0.0.1:8000/scalar
   ```
3. Use the API to register, log in, and manage users with email-password, username-password, or phone number-password combinations.
---

## Project Structure

```plaintext
Auth/
├── .dockerignore
├── .env
├── .gitignore  # gitignore file for GitHub
├── Dockerfile
├── README.md  # Project documentation
├── __init__.py  # initializes package
├── app.py  # main FastAPI app
├── authentication
│   ├── __init__.py  # initializes package
│   ├── config
│   │   ├── __init__.py  # initializes package
│   │   ├── bloom_filter.py
│   │   ├── celery_app.py
│   │   ├── database.py
│   │   ├── kafka1_config.py
│   │   ├── kafka2_config.py
│   │   ├── rate_limiting.py
│   │   └── redis_config.py
│   ├── fake_user.py
│   ├── helper
│   │   ├── __init__.py  # initializes package
│   │   ├── auth_token.py
│   │   ├── hashing.py
│   │   ├── oauth2.py
│   │   └── utils.py
│   ├── models
│   │   ├── __init__.py  # initializes package
│   │   └── models.py  # models
│   ├── otp_service
│   │   ├── __init__.py  # initializes package
│   │   ├── otp_verify.py
│   │   └── send_mail.py
│   ├── src
│   │   ├── __init__.py  # initializes package
│   │   ├── auth_user.py
│   │   └── google_auth.py
│   └── templates
│       ├── create_new_password.html
│       ├── google_login.html
│       ├── index.html
│       ├── login.html
│       ├── otp.html
│       ├── phone_number.html
│       ├── reset_password.html
│       ├── signup.html
│       ├── success.html
│       ├── user.html
│       └── user_login.html
├── credentials.json
├── docker-compose.yml
├── requirements.txt
├── run.sh
├── test_api
│   ├── __init__.py  # initializes package
│   ├── locust.py
│   ├── test_login.py
│   └── user_api_hit.py
└── token.pickle
```

---

## Future Enhancements
- Implement OAuth2 for social login (e.g., Github, Facebook).
- Enhance rate-limiting for login attempts to prevent brute-force attacks.

---

## Contribution Guidelines

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes and submit a pull request.

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Author
**Madhur Prakash**  
[GitHub](https://github.com/Madhur-Prakash) | [Medium](https://medium.com/@madhurprakash2005)

---
