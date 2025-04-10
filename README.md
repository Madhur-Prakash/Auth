# Authentication

**A FastAPI-Based Authentication System**

## Overview
This repository implements a robust authentication system using FastAPI and MongoDB. It supports three types of authentication:
- **Email and Password**
- **Username and Password**
- **Phone Number and Password**

The system securely hashes passwords before storing them in the database, ensuring the confidentiality of user credentials.

---

## Features
- **Multiple Authentication Methods**: Choose between email, username, or phone number for authentication.
- **Secure Password Handling**: Implements password hashing using industry-standard algorithms.
- **Fast and Scalable**: Built with FastAPI for high performance and scalability.
- **MongoDB Integration**: Stores user credentials and data in a reliable NoSQL database.

---

## Technology Stack
- **Backend Framework**: FastAPI
- **Database**: MongoDB
- **Password Hashing**: [bcrypt or any other hashing library used]
- **Programming Language**: Python

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
   - Install MongoDB and start the service.
   - Configure the MongoDB URI in the `.env` file.

---

## Usage

1. Start the FastAPI server:
   ```bash
   uvicorn main:app --reload
   ```
2. Access the API documentation at:
   ```
   http://127.0.0.1:8000/docs
   ```
3. Use the API to register, log in, and manage users with email-password, username-password, or phone number-password combinations.

---

## API Endpoints

### Authentication Endpoints
- **POST /signup**: Register a new user.
- **POST /login**: Log in an existing user.

---

## Project Structure

```plaintext
Auth/
├── Authentication/
│   ├── auth               # authentication logic and endpoints
│   ├── database.py        # Database setup
│   ├── hashing.py         # Hashing the password
│   ├── models.py          # Database models
│   ├── oauth.py           # To be used in future
│   ├── schemas.py         # Request and response schemas
│   ├── token.py           # creating the jwt token 
├── gitignore              # gitignore file for github
├── app.py                 # main fastapi app
└── README.md              # Project documentation
```

---

## Future Enhancements
- Add support for two-factor authentication (2FA).
- Implement OAuth2 for social login (e.g., Google, Facebook).
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
