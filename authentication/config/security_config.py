"""
Security configuration and utilities for the authentication system.
"""
import os
import re
import html
from fastapi import HTTPException, status

class SecurityConfig:
    """Security configuration class"""
    
    # Password requirements
    MIN_PASSWORD_LENGTH = 6
    # set all these according to your needs
    REQUIRE_UPPERCASE = False
    REQUIRE_LOWERCASE = False
    REQUIRE_NUMBERS = False
    REQUIRE_SPECIAL_CHARS = False
    
    # Cookie security
    COOKIE_SECURE = os.getenv("ENVIRONMENT") == "production"
    COOKIE_SAMESITE = "strict"
    COOKIE_HTTPONLY = True

def validate_password(password: str) -> bool:
    """
    Validate password against security requirements.
    
    Args:
        password: The password to validate
        
    Returns:
        bool: True if password meets requirements
        
    Raises:
        HTTPException: If password doesn't meet requirements
    """
    if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password must be at least {SecurityConfig.MIN_PASSWORD_LENGTH} characters long"
        )
    if len(password) > 15:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must not exceed 15 characters"
        )
    
    if SecurityConfig.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one uppercase letter"
        )
    
    if SecurityConfig.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one lowercase letter"
        )
    
    if SecurityConfig.REQUIRE_NUMBERS and not re.search(r'\d', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one number"
        )
    
    if SecurityConfig.REQUIRE_SPECIAL_CHARS and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must contain at least one special character"
        )
    
    return True

def validate_email(email: str) -> bool:
    """
    Validate email format.
    
    Args:
        email: The email to validate
        
    Returns:
        bool: True if email is valid
        
    Raises:
        HTTPException: If email format is invalid
    """
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email format"
        )
    return True

def sanitize_input(input_str: str) -> str:
    """
    Sanitize input to prevent XSS attacks.
    
    Args:
        input_str: The string to sanitize
        
    Returns:
        str: Sanitized string
    """
    return html.escape(input_str.strip())

def validate_phone_number(phone: str) -> bool:
    """
    Validate phone number format.
    
    Args:
        phone: The phone number to validate
        
    Returns:
        bool: True if phone number is valid
        
    Raises:
        HTTPException: If phone number format is invalid
    """
    if not phone.isdigit() or len(phone) != 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number must be 10 digits"
        )
    return True

def get_secure_cookie_settings() -> dict:
    """
    Get secure cookie settings based on environment.
    
    Returns:
        dict: Cookie settings
    """
    return {
        "secure": SecurityConfig.COOKIE_SECURE,
        "samesite": SecurityConfig.COOKIE_SAMESITE,
        "httponly": SecurityConfig.COOKIE_HTTPONLY,
        "path": "/"
    }