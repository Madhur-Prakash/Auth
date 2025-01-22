from mongoengine import Document, StringField, EmailField, BooleanField
from datetime import datetime

class user(Document):
    full_name = StringField()
    email = EmailField(required=True, unique=True)
    password = StringField(required=True, min_length=6)
    password2 = StringField(min_length=6)
    profile_picture = StringField(default='default.png')
    timestramp = StringField(default=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

class message(Document):
    sender = StringField()
    receiver = StringField()
    message = StringField()
    timestramp = StringField(default=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))