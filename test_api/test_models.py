"""
Unit Tests for Pydantic Models

This module contains tests for all Pydantic models used in the authentication system,
including validation, constraints, and custom validators.
"""

import pytest
from pydantic import ValidationError
from fastapi import HTTPException
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestUserModel:
    """Tests for the user signup model."""
    
    def test_valid_user_model(self):
        """Test that valid user data creates a model instance."""
        from authentication.models.models import user
        
        user_data = user(
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            phone_number="1234567890",
            country_code="+1",
            password="SecurePass123"
        )
        
        assert user_data.first_name == "John"
        assert user_data.last_name == "Doe"
        assert user_data.email == "john.doe@example.com"
        assert user_data.phone_number == "1234567890"
        assert user_data.country_code == "+1"
        assert user_data.password == "SecurePass123"

    def test_user_model_missing_required_field(self):
        """Test that missing required field raises validation error."""
        from authentication.models.models import user
        
        with pytest.raises(ValidationError):
            user(
                first_name="John",
                last_name="Doe",
                email="john.doe@example.com",
                # Missing phone_number, country_code, password
            )

    def test_user_model_invalid_email(self):
        """Test that invalid email raises validation error."""
        from authentication.models.models import user
        
        with pytest.raises(ValidationError):
            user(
                first_name="John",
                last_name="Doe",
                email="invalid-email",
                phone_number="1234567890",
                country_code="+1",
                password="SecurePass123"
            )

    def test_user_model_short_phone_number(self):
        """Test that short phone number raises validation error."""
        from authentication.models.models import user
        
        with pytest.raises(ValidationError):
            user(
                first_name="John",
                last_name="Doe",
                email="john.doe@example.com",
                phone_number="123",  # Too short
                country_code="+1",
                password="SecurePass123"
            )


class TestVerifyOtpSignupModel:
    """Tests for the verify OTP signup model."""
    
    def test_valid_email_only(self):
        """Test with only email provided."""
        from authentication.models.models import verify_otp_signup
        
        model = verify_otp_signup(email="test@example.com")
        assert model.email == "test@example.com"
        assert model.phone_number is None

    def test_valid_phone_with_country_code(self):
        """Test with phone and country code provided."""
        from authentication.models.models import verify_otp_signup
        
        model = verify_otp_signup(
            phone_number="1234567890",
            country_code="+1"
        )
        assert model.phone_number == "1234567890"
        assert model.country_code == "+1"

    def test_phone_without_country_code_raises_error(self):
        """Test that phone without country code raises error."""
        from authentication.models.models import verify_otp_signup
        
        with pytest.raises(HTTPException) as exc_info:
            verify_otp_signup(phone_number="1234567890")
        
        assert exc_info.value.status_code == 422

    def test_both_email_and_phone(self):
        """Test with both email and phone provided."""
        from authentication.models.models import verify_otp_signup
        
        model = verify_otp_signup(
            email="test@example.com",
            phone_number="1234567890",
            country_code="+1"
        )
        assert model.email == "test@example.com"
        assert model.phone_number == "1234567890"


class TestOtpEmailModel:
    """Tests for the OTP email model."""
    
    def test_valid_otp_email(self):
        """Test valid OTP email model."""
        from authentication.models.models import otp_email
        
        model = otp_email(
            otp="123456",
            email="test@example.com"
        )
        assert model.otp == "123456"
        assert model.email == "test@example.com"

    def test_otp_email_missing_otp(self):
        """Test that missing OTP raises validation error."""
        from authentication.models.models import otp_email
        
        with pytest.raises(ValidationError):
            otp_email(email="test@example.com")

    def test_otp_email_invalid_email(self):
        """Test that invalid email raises validation error."""
        from authentication.models.models import otp_email
        
        with pytest.raises(ValidationError):
            otp_email(otp="123456", email="invalid")


class TestOtpPhoneModel:
    """Tests for the OTP phone model."""
    
    def test_valid_otp_phone(self):
        """Test valid OTP phone model."""
        from authentication.models.models import otp_phone
        
        model = otp_phone(
            otp="123456",
            phone_number="1234567890",
            country_code="+1"
        )
        assert model.otp == "123456"
        assert model.phone_number == "1234567890"
        assert model.country_code == "+1"

    def test_otp_phone_short_number(self):
        """Test that short phone number raises validation error."""
        from authentication.models.models import otp_phone
        
        with pytest.raises(ValidationError):
            otp_phone(
                otp="123456",
                phone_number="12345",
                country_code="+1"
            )


class TestLoginModel:
    """Tests for the login model."""
    
    def test_login_with_email(self):
        """Test login with email."""
        from authentication.models.models import login
        
        model = login(
            email="test@example.com",
            password="SecurePass123"
        )
        assert model.email == "test@example.com"
        assert model.password == "SecurePass123"

    def test_login_with_phone(self):
        """Test login with phone number."""
        from authentication.models.models import login
        
        model = login(
            phone_number="1234567890",
            password="SecurePass123"
        )
        assert model.phone_number == "1234567890"
        assert model.password == "SecurePass123"

    def test_login_missing_password(self):
        """Test that missing password raises validation error."""
        from authentication.models.models import login
        
        with pytest.raises(ValidationError):
            login(email="test@example.com")


class TestLoginOtpModel:
    """Tests for login OTP model."""
    
    def test_login_otp_with_email(self):
        """Test login OTP with email."""
        from authentication.models.models import login_otp
        
        model = login_otp(email="test@example.com")
        assert model.email == "test@example.com"

    def test_login_otp_with_phone(self):
        """Test login OTP with phone."""
        from authentication.models.models import login_otp
        
        model = login_otp(
            phone_number="1234567890",
            country_code="+1"
        )
        assert model.phone_number == "1234567890"
        assert model.country_code == "+1"

    def test_login_otp_phone_without_country_code(self):
        """Test that phone without country code raises error."""
        from authentication.models.models import login_otp
        
        with pytest.raises(HTTPException):
            login_otp(phone_number="1234567890")


class TestResetPasswordModel:
    """Tests for reset password model."""
    
    def test_valid_reset_password(self):
        """Test valid reset password model."""
        from authentication.models.models import reset_password
        
        model = reset_password(
            email="test@example.com",
            password="NewPass123",
            confirm_password="NewPass123"
        )
        assert model.email == "test@example.com"
        assert model.password == "NewPass123"
        assert model.confirm_password == "NewPass123"

    def test_reset_password_invalid_email(self):
        """Test that invalid email raises validation error."""
        from authentication.models.models import reset_password
        
        with pytest.raises(ValidationError):
            reset_password(
                email="invalid",
                password="NewPass123",
                confirm_password="NewPass123"
            )


class TestRefreshTokenModel:
    """Tests for refresh token model."""
    
    def test_refresh_token_model(self):
        """Test refresh token model."""
        from authentication.models.models import refresh_token
        
        model = refresh_token(
            refresh_token="some_token",
            session_id="some_session",
            device_fingerprint="some_fingerprint"
        )
        assert model.refresh_token == "some_token"
        assert model.session_id == "some_session"
        assert model.device_fingerprint == "some_fingerprint"

    def test_refresh_token_optional_fields(self):
        """Test that fields are optional."""
        from authentication.models.models import refresh_token
        
        model = refresh_token()
        assert model.refresh_token is None
        assert model.session_id is None


class TestLogoutModel:
    """Tests for logout model."""
    
    def test_valid_logout(self):
        """Test valid logout model."""
        from authentication.models.models import logout
        
        model = logout(data="test@example.com")
        assert model.data == "test@example.com"

    def test_logout_missing_data(self):
        """Test that missing data raises validation error."""
        from authentication.models.models import logout
        
        with pytest.raises(ValidationError):
            logout()


class TestEmailModel:
    """Tests for email model."""
    
    def test_valid_email_model(self):
        """Test valid email model."""
        from authentication.models.models import email
        
        model = email(email="test@example.com")
        assert model.email == "test@example.com"

    def test_invalid_email_format(self):
        """Test that invalid email raises validation error."""
        from authentication.models.models import email
        
        with pytest.raises(ValidationError):
            email(email="invalid-email")


class TestGoogleLoginModel:
    """Tests for Google login model."""
    
    def test_valid_google_login(self):
        """Test valid Google login model."""
        from authentication.models.models import google_login
        
        model = google_login(
            phone_number="1234567890",
            country_code="+1"
        )
        assert model.phone_number == "1234567890"
        assert model.country_code == "+1"

    def test_google_login_short_phone(self):
        """Test that short phone number raises validation error."""
        from authentication.models.models import google_login
        
        with pytest.raises(ValidationError):
            google_login(
                phone_number="12345",
                country_code="+1"
            )


class TestTokenDataModel:
    """Tests for TokenData model."""
    
    def test_token_data_with_email(self):
        """Test TokenData with email."""
        from authentication.models.models import TokenData
        
        model = TokenData(email="test@example.com")
        assert model.email == "test@example.com"

    def test_token_data_optional_email(self):
        """Test that email is optional."""
        from authentication.models.models import TokenData
        
        model = TokenData()
        assert model.email is None


class TestTokenModel:
    """Tests for Token model."""
    
    def test_valid_token(self):
        """Test valid token model."""
        from authentication.models.models import Token
        
        model = Token(
            access_token="some_access_token",
            token_type="bearer"
        )
        assert model.access_token == "some_access_token"
        assert model.token_type == "bearer"

    def test_token_missing_fields(self):
        """Test that missing fields raise validation error."""
        from authentication.models.models import Token
        
        with pytest.raises(ValidationError):
            Token(access_token="some_token")
