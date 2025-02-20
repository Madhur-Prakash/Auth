from fastapi import Depends, HTTPException, status, Form, BackgroundTasks, UploadFile, File, Request
import os
from fastapi.templating import Jinja2Templates
from .auth_token import create_access_token
from .models import Patient, Doctor
from typing import List
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
import json

from dotenv import load_dotenv
load_dotenv('.env')
templates = Jinja2Templates(directory="authemtication/templates")

conf = ConnectionConfig(
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_FROM=os.getenv("MAIL_FROM"),
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
)

async def send_email_async(subject: str, email_to: str, body: dict):
    message = MessageSchema(
        subject=subject,
        recipients=[email_to],
        body=json.dumps(body),  # Convert body to JSON string
        subtype='html',
    )
    
    fm = FastMail(conf)
    await fm.send_message(message, template_name='email.html')

def send_email_background(background_tasks: BackgroundTasks, subject: str, email_to: str, body: dict):
    message = MessageSchema(
        subject=subject,
        recipients=[email_to],
        body=json.dumps(body),  # Convert body to JSON string
        subtype='html',
    )
    fm = FastMail(conf)
    background_tasks.add_task(
       fm.send_message, message, template_name='email.html')