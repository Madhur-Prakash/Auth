```
Auth/
├── .env
├── .gitignore  # gitignore file for GitHub
├── FOLDER_STRUCTURE.md
├── README.md  # Project documentation
├── __init__.py  # initializes package
├── app.py  # main FastAPI app
├── authentication
│   ├── __init__.py  # initializes package
│   ├── config
│   │   ├── __init__.py  # initializes package
│   │   ├── celery_app.py
│   │   ├── database.py
│   │   ├── kafka_consumer.py
│   │   ├── rate_limiting.py
│   │   └── redis.py
│   ├── fake_doctor.py
│   ├── fake_patient.py
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
│   │   ├── auth_doctor.py
│   │   ├── auth_patient.py
│   │   ├── google_doctor_auth.py
│   │   └── google_patient_auth.py
│   └── templates
│       ├── create_new_password.html
│       ├── doctor.html
│       ├── doctor_signup.html
│       ├── google_login.html
│       ├── index.html
│       ├── login.html
│       ├── otp.html
│       ├── patient.html
│       ├── patient_login.html
│       ├── phone_number.html
│       ├── reset_password.html
│       ├── signup.html
│       └── success.html
├── credentials.json
├── docker-compose.yml
├── requirements.txt
├── test_api
│   ├── __init__.py  # initializes package
│   ├── doctor_hit_api.py
│   ├── locust.py
│   ├── patient_api_hit.py
│   └── test_login.py
└── token.pickle
```