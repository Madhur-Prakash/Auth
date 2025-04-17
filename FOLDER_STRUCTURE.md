```
Auth/
├── .env
├── .gitignore  # gitignore file for GitHub
├── README.md  # Project documentation
├── __init__.py  # initializes package
├── app.py  # main FastAPI app
├── authentication
│   ├── __init__.py  # initializes package
│   ├── config
│   │   ├── __init__.py  # initializes package
│   │   ├── celery_app.py
│   │   ├── database.py
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
│   │   └── google_auth.py
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
├── logs
│   ├── .__auth.lock
│   ├── auth.log
│   ├── auth.log.1
│   ├── auth.log.10
│   ├── auth.log.11
│   ├── auth.log.12
│   ├── auth.log.13
│   ├── auth.log.14
│   ├── auth.log.15
│   ├── auth.log.16
│   ├── auth.log.17
│   ├── auth.log.18
│   ├── auth.log.19
│   ├── auth.log.2
│   ├── auth.log.20
│   ├── auth.log.21
│   ├── auth.log.3
│   ├── auth.log.4
│   ├── auth.log.5
│   ├── auth.log.6
│   ├── auth.log.7
│   ├── auth.log.8
│   └── auth.log.9
├── requirements.txt
├── structure.py
├── test_api
│   ├── __init__.py  # initializes package
│   ├── doctor_hit_api.py
│   ├── locust.py
│   ├── patient_api_hit.py
│   └── test_login.py
└── token.pickle
```