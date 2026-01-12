# Authentication

**A Full-Fledged Authentication System with Production-Level Concepts**

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
You can get the project up and running using either **Docker Compose** (the easiest method) or by setting it up **manually** for more  control.

> 📌 **Important:**  
> - For Docker setup, set `DEVELOPMENT_ENV = "docker"` in your `.env` file.  
> - For local development, either set `DEVELOPMENT_ENV = "local"` or comment out the line entirely.  
>  
> This ensures the application loads the correct configuration and prevents environment-related issues.

---


## Method 1: Using Docker Compose (Recommended) 🐳

This is the simplest method and handles all service dependencies automatically. It will build the necessary images and start all services in one go.

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Madhur-Prakash/Auth.git
    cd Auth
    ```
2. **Set up environment variables**:
      ``` bash
      # Copy the .env.sample file to .env and fill in the required values.
      ```

3.  **Start Services**
    Use Docker Compose to launch the entire stack in detached mode (`-d`).
    ```bash
    docker-compose up -d --build
    ```

4.  **Access Services**
    Once running, you can access the different components at these endpoints:

      | Service | URL | Purpose |
      | :--- | :--- | :--- |
      |  FastAPI App | [`http://localhost:8005/docs`](http://localhost:8005/docs) | The main FastAPI application. |
      | Logging Service | [`http://localhost:8000/docs`](http://localhost:8000/docs) | Centralized request/response logs. |
      | Redis Stack UI | [`http://localhost:8001`](http://localhost:8001) | In-memory cache and message broker UI. |
      | Mailhog | [`http://localhost:8025`](http://localhost:8025) | Catches outgoing emails for testing. |
      | Kafka UI (Kafdrop) | [`http://localhost:9000`](http://localhost:9000) | Web UI for managing Kafka topics. |
      | MongoDB (Admin) | [`http://localhost:8081`](http://localhost:8081) | Database administration interface. |

---


## Method 2: Manual Installation 🛠️

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/Madhur-Prakash/Auth.git
    cd Auth
    ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up MongoDB:
   ```bash
   # Install MongoDB and start the service.
   ```

5. Set up Redis:
   ```bash
   # Run this command to start Redis Stack in detached mode:
   docker run -d --name redis -p 6379:6379 -p 8001:8001 redis/redis-stack:latest
   # access Redis Stack at 👉 http://localhost:8001
   ```

6. Set up Kafka and Zookeeper:
   ### For kafka + zookeeper setup run the following command:
   ```bash
   docker run -d \
      --name kafka \
      -p 2181:2181 \
      -p 9092:9092 \
      -e KAFKA_LISTENERS="INTERNAL://:29092,EXTERNAL://:9092" \
      -e KAFKA_ADVERTISED_LISTENERS="INTERNAL://kafka:29092,EXTERNAL://localhost:9092" \
      -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP="INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT" \
      -e KAFKA_INTER_BROKER_LISTENER_NAME="INTERNAL" \
      -e KAFKA_ZOOKEEPER_SESSION_TIMEOUT="6000" \
      -e KAFKA_RESTART_ATTEMPTS="10" \
      -e KAFKA_RESTART_DELAY="5" \
      -e ZOOKEEPER_AUTOPURGE_PURGE_INTERVAL="0" \
      obsidiandynamics/kafka
   ```

   ### Optional: Kafka Web UI
   ```bash
   docker run -d \
      --name kafdrop \
      -p 9000:9000 \
      --link kafka:kafka \
      -e KAFKA_BROKERCONNECT="kafka:29092" \
      obsidiandynamics/kafdrop

   # access Kafka at 👉 http://localhost:9000
   # --link kafka:kafka ensures Kafdrop can see the Kafka container by hostname kafka
   ```

7. Set up Mailhog:
   ```bash
   # Run this command to start Mailhog in detached mode:
   docker run -d --name mailhog -p 1025:1025 -p 8025:8025 mailhog/mailhog
   # access Mailhog at 👉 http://localhost:8025
   ```
8. Set up external logging service:
   - Clone the repository:
      ```bash
      git clone https://github.com/Madhur-Prakash/centralized-logging.git
      cd centralized-logging
      ```
   - Create docker image:
      ```bash
      docker build -t logging .
      ```
   - Run docker:
      ```bash
      docker run -d --name logging -p 8000:8000 logging
      # access the logging service at 👉 `http://localhost:8000/docs`
      ```

9. Set up environment variables:

      ``` bash
      # Copy the .env.sample file to .env and fill in the required values.
      ```
---

## Usage

1. Start the FastAPI server:
   ```bash
   uvicorn app:app --port 8005 --reload
   ```
2. Start the kafka worker:
   ```bash
   python authentication/config/kafka1_config.py
   ```
3. Access the API documentation at:
   ```bash
   http://127.0.0.1:8005/docs
   # for detailed docs visit 👉 http://127.0.0.1:8005/scalar
   ```

---
## For deeper understanding of the code visit
[What I Learned by Building a Full Auth System from Scratch - Medium](https://medium.com/@madhurprakash2005/what-i-learned-by-building-a-full-auth-system-from-scratch-654de5b8fb37)

---

## Project Structure

```plaintext
Auth/
├── .dockerignore
├── .env.sample
├── .gitignore  # gitignore file for GitHub
├── CHANGELOG.md
├── Dockerfile.auth
├── Dockerfile.kafka1
├── Dockerfile.kafka2
├── LICENSE
├── README.md  # Project documentation
├── __init__.py  # initializes package
├── app.py  # main FastAPI app
├── authentication
│   ├── __init__.py  # initializes package
│   ├── config
│   │   ├── __init__.py  # initializes package
│   │   ├── bloom_filter.py
│   │   ├── celery_app.py
│   │   ├── database.py  # database configuration
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
│   │   └── utils.py  # utility functions
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
├── test_api
│   ├── __init__.py  # initializes package
│   ├── locust.py
│   ├── test_login.py
│   └── user_api_hit.py
├── token.pickle
└── waitforkafka.sh
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
