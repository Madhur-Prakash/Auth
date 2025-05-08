import os
import base64
import pickle
import time
import boto3
import smtplib
# from ..config.celery_app import celery
from email.mime.text import MIMEText
import traceback
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from dotenv import load_dotenv
load_dotenv()

#  AWS credentials
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION_NAME = os.getenv("AWS_REGION_NAME", default="us-east-1")

# aws client
client = boto3.client(
    'ses',
    region_name=AWS_REGION_NAME,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)
NO_REPLY_EMAIL = os.getenv("NO_REPLY_EMAIL")

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

# @celery.task()
def send_email(to_email, subject, body, retries=3, delay=5):
    """Send an email using Gmail API with retry mechanism."""
    service = authenticate_gmail()
    for attempt in range(retries):
        try:

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


# @celery.task()
def send_email_ses(to_email, subject, body, retries=3, delay=5):
    """Send an email using AWS SES with retry mechanism."""
    for attempt in range(retries):
        try:
            response = client.send_email(
                Source=NO_REPLY_EMAIL,  # Must be a verified email in AWS SES
                Destination={
                    "ToAddresses": [to_email]  # Ensure it's a LIST
                },
                Message={
                    "Subject": {"Data": subject},
                    "Body": {
                        "Html": {"Data": body}
                    }
                }
            )
            print(f"Email sent! Message ID: {response['MessageId']}")
            return response
        except Exception as e:
            print(f"Failed to send email due to error: {e}. Retrying in {delay} seconds...")
            print(f"Error: {traceback.format_exc()}")
            time.sleep(delay)


def send_mail_to_mailhog(to_email, subject, body, retries=3, delay=5):
    """Send an email using MailHog (local SMTP server) with retry mechanism."""
    for attempt in range(retries):
        try:
            msg = MIMEText(body, "html")
            msg["Subject"] = subject
            msg["From"] = NO_REPLY_EMAIL
            msg["To"] = to_email

            with smtplib.SMTP("localhost", 1025) as server:
                server.sendmail(NO_REPLY_EMAIL, [to_email], msg.as_string())

            print(f"Email sent to {to_email} via MailHog!")
            return {"status": "success", "to": to_email}
        except Exception as e:
            print(f"Failed to send email to MailHog: {e}. Retrying in {delay} seconds...")
            print(f"Error: {traceback.format_exc()}")
            time.sleep(delay)
            return {"status": "failure", "error": str(e)}

    print("Failed to send email to MailHog after multiple attempts.")

