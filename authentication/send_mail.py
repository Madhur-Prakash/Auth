import os
import base64
import pickle
import time
from email.mime.text import MIMEText
import traceback
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Define the scope for Gmail API
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

def authenticate_gmail():
    """Authenticate and return Gmail API service."""
    creds = None

    # Load credentials from token.pickle if available
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)

    # If credentials are invalid or don't exist, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for future use
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)

    return build("gmail", "v1", credentials=creds)

async def send_email(to_email, subject, body, retries=3, delay=5):
    """Send an email using Gmail API with retry mechanism."""
    for attempt in range(retries):
        try:
            service = authenticate_gmail()

            # Create email message
            message = MIMEText(body, "html")  # Specify the MIME type as "html"
            message["to"] = to_email
            message["subject"] = subject
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

            # Send email using Gmail API
            message = {"raw": raw_message}
            sent_message = service.users().messages().send(userId="me", body=message).execute()
            print(f"Email sent! Message ID: {sent_message['id']}")
            return sent_message
        except Exception as e:
            print(f"Failed to send email due to timeout: {e}. Retrying in {delay} seconds...")
            print(f"Error: {traceback.format_exc()}")
            time.sleep(delay)
    print("Failed to send email after multiple attempts.")

# send_email("madhurprakash2005@gmail.com", "Welcome to CuraDocs. Lets build your health Profile", html_body)





# from fastapi import Depends, HTTPException, status, Form, BackgroundTasks, UploadFile, File, Request
# import os
# from fastapi.templating import Jinja2Templates
# from .auth_token import create_access_token
# from .models import Patient, Doctor
# from typing import List
# from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
# import json

# from dotenv import load_dotenv
# load_dotenv('.env')
# templates = Jinja2Templates(directory="authemtication/templates")

# conf = ConnectionConfig(
#     MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
#     MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
#     MAIL_FROM=os.getenv("MAIL_FROM"),
#     MAIL_PORT=587,
#     MAIL_SERVER="smtp.gmail.com",
#     MAIL_STARTTLS=True,
#     MAIL_SSL_TLS=False,
#     USE_CREDENTIALS=True,
# )

# async def send_email_async(subject: str, email_to: str, body: dict):
#     message = MessageSchema(
#         subject=subject,
#         recipients=[email_to],
#         body=json.dumps(body),  # Convert body to JSON string
#         subtype='html',
#     )
    
#     fm = FastMail(conf)
#     await fm.send_message(message, template_name='email.html')

# def send_email_background(background_tasks: BackgroundTasks, subject: str, email_to: str, body: dict):
#     message = MessageSchema(
#         subject=subject,
#         recipients=[email_to],
#         body=json.dumps(body),  # Convert body to JSON string
#         subtype='html',
#     )
#     fm = FastMail(conf)
#     background_tasks.add_task(
#        fm.send_message, message, template_name='email.html')





