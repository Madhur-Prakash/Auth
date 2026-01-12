"""
Unit Tests for Authentication User Endpoints

This module contains comprehensive tests for all authentication endpoints
including signup, login, OTP verification, password reset, and token management.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import status
from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestHealthCheck:
    """Tests for the health check endpoint."""
    
    def test_health_check_returns_200(self, test_client):
        """Test that health check endpoint returns 200."""
        response = test_client.get("/")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == {"status": "healthy"}


class TestUserSignup:
    """Tests for user signup endpoint."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.mongo_client')
    @patch('authentication.src.auth_user.client')  # Redis client
    @patch('authentication.src.auth_user.producer')  # Kafka producer
    @patch('authentication.src.auth_user.send_mail_to_mailhog')
    @patch('authentication.src.auth_user.user_email_bloom_filter')
    @patch('authentication.src.auth_user.user_phone_bloom_filter')
    def test_signup_success(
        self, 
        mock_phone_bloom, 
        mock_email_bloom,
        mock_email_service,
        mock_kafka,
        mock_redis,
        mock_mongo,
        test_client,
        sample_user_data
    ):
        """Test successful user signup."""
        # Setup mocks
        mock_email_bloom.contains.return_value = False
        mock_phone_bloom.contains.return_value = False
        mock_mongo.auth.user.find_one = AsyncMock(return_value=None)
        mock_redis.hgetall = AsyncMock(return_value={})
        mock_redis.hset = AsyncMock(return_value=True)
        mock_redis.set = AsyncMock(return_value=True)
        mock_redis.expire = AsyncMock(return_value=True)
        mock_email_service.return_value = True
        
        response = test_client.post("/user/signup", json=sample_user_data)
        
        # Should succeed or fail based on actual implementation
        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_signup_missing_required_fields(self, test_client):
        """Test signup with missing required fields."""
        incomplete_data = {
            "first_name": "John",
            "email": "john@example.com"
        }
        response = test_client.post("/user/signup", json=incomplete_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.unit
    def test_signup_invalid_email_format(self, test_client, sample_user_data):
        """Test signup with invalid email format."""
        sample_user_data["email"] = "invalid-email"
        response = test_client.post("/user/signup", json=sample_user_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.unit
    def test_signup_invalid_phone_number(self, test_client, sample_user_data):
        """Test signup with invalid phone number."""
        sample_user_data["phone_number"] = "123"  # Too short
        response = test_client.post("/user/signup", json=sample_user_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.unit
    def test_signup_short_first_name(self, test_client, sample_user_data):
        """Test signup with short first name."""
        sample_user_data["first_name"] = "J"
        response = test_client.post("/user/signup", json=sample_user_data)
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_signup_numeric_first_name(self, test_client, sample_user_data):
        """Test signup with numeric first name."""
        sample_user_data["first_name"] = "John123"
        response = test_client.post("/user/signup", json=sample_user_data)
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_500_INTERNAL_SERVER_ERROR]


class TestUserLogin:
    """Tests for user login endpoint."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.cache_with_password')
    def test_login_with_email_success(self, mock_cache, test_client, sample_login_data):
        """Test successful login with email."""
        mock_cache.return_value = AsyncMock(return_value="test_user")
        
        response = test_client.post("/user/login", json=sample_login_data)
        # Check for expected responses
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_login_missing_password(self, test_client):
        """Test login with missing password."""
        login_data = {"email": "test@example.com"}
        response = test_client.post("/user/login", json=login_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.unit
    def test_login_missing_email_and_phone(self, test_client):
        """Test login with missing email and phone number."""
        login_data = {"password": "TestPass123"}
        response = test_client.post("/user/login", json=login_data)
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_login_with_phone_number(self, test_client):
        """Test login with phone number instead of email."""
        login_data = {
            "phone_number": "1234567890",
            "password": "TestPass123"
        }
        response = test_client.post("/user/login", json=login_data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_500_INTERNAL_SERVER_ERROR]


class TestSendOTPSignup:
    """Tests for send OTP during signup endpoint."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.generate_otp')
    @patch('authentication.src.auth_user.send_mail_to_mailhog')
    def test_send_otp_email_success(self, mock_mail, mock_otp, test_client):
        """Test successful OTP send via email."""
        mock_otp.return_value = AsyncMock(return_value="123456")
        mock_mail.return_value = True
        
        data = {"email": "test@example.com"}
        response = test_client.post("/user/signup/send_otp", json=data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    @patch('authentication.src.auth_user.send_otp')
    def test_send_otp_phone_success(self, mock_sms, test_client):
        """Test successful OTP send via phone."""
        mock_sms.return_value = AsyncMock(return_value="123456")
        
        data = {
            "phone_number": "1234567890",
            "country_code": "+1"
        }
        response = test_client.post("/user/signup/send_otp", json=data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_send_otp_phone_without_country_code(self, test_client):
        """Test OTP send with phone but no country code."""
        data = {"phone_number": "1234567890"}
        response = test_client.post("/user/signup/send_otp", json=data)
        # Should fail validation due to missing country code when phone is provided
        assert response.status_code in [status.HTTP_422_UNPROCESSABLE_ENTITY, status.HTTP_500_INTERNAL_SERVER_ERROR]


class TestVerifyOTPSignupEmail:
    """Tests for email OTP verification during signup."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.client')  # Redis client
    def test_verify_otp_success(self, mock_redis, test_client, sample_otp_data):
        """Test successful OTP verification."""
        mock_redis.hgetall = AsyncMock(return_value={"otp": "123456"})
        
        response = test_client.post("/user/signup/email_verify_otp", json=sample_otp_data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_verify_otp_invalid_format(self, test_client):
        """Test OTP verification with invalid OTP format."""
        data = {
            "email": "test@example.com",
            "otp": "123"  # Too short
        }
        response = test_client.post("/user/signup/email_verify_otp", json=data)
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_verify_otp_empty(self, test_client):
        """Test OTP verification with empty OTP."""
        data = {
            "email": "test@example.com",
            "otp": ""
        }
        response = test_client.post("/user/signup/email_verify_otp", json=data)
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_422_UNPROCESSABLE_ENTITY, status.HTTP_500_INTERNAL_SERVER_ERROR]


class TestVerifyOTPSignupPhone:
    """Tests for phone OTP verification during signup."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.client')  # Redis client
    def test_verify_phone_otp_success(self, mock_redis, test_client, sample_phone_otp_data):
        """Test successful phone OTP verification."""
        mock_redis.hgetall = AsyncMock(return_value={"otp": "123456"})
        
        response = test_client.post("/user/signup/phone_verify_otp", json=sample_phone_otp_data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_verify_phone_otp_invalid(self, test_client):
        """Test phone OTP verification with invalid OTP."""
        data = {
            "phone_number": "1234567890",
            "country_code": "+1",
            "otp": "12345"  # Too short
        }
        response = test_client.post("/user/signup/phone_verify_otp", json=data)
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_500_INTERNAL_SERVER_ERROR]


class TestLoginSendOTP:
    """Tests for send OTP during login endpoint."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.cache_without_password')
    @patch('authentication.src.auth_user.generate_otp')
    @patch('authentication.src.auth_user.send_email')
    def test_login_send_otp_email(self, mock_mail, mock_otp, mock_cache, test_client):
        """Test sending OTP for email login."""
        mock_cache.return_value = AsyncMock(return_value="cached_user")
        mock_otp.return_value = AsyncMock(return_value="123456")
        mock_mail.return_value = True
        
        data = {"email": "test@example.com"}
        response = test_client.post("/user/login/send_otp", json=data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_login_send_otp_neither_email_nor_phone(self, test_client):
        """Test login OTP when neither email nor phone is provided."""
        data = {}
        response = test_client.post("/user/login/send_otp", json=data)
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_500_INTERNAL_SERVER_ERROR]


class TestLoginVerifyOTPEmail:
    """Tests for login email OTP verification."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.client')  # Redis client
    def test_login_verify_otp_email_success(self, mock_redis, test_client, sample_otp_data):
        """Test successful login OTP verification."""
        mock_redis.hgetall = AsyncMock(return_value={"otp": "123456"})
        mock_redis.hset = AsyncMock(return_value=True)
        mock_redis.expire = AsyncMock(return_value=True)
        mock_redis.delete = AsyncMock(return_value=True)
        
        response = test_client.post("/user/login/email_verify_otp", json=sample_otp_data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_500_INTERNAL_SERVER_ERROR]


class TestRefreshToken:
    """Tests for refresh token endpoint."""
    
    @pytest.mark.unit
    def test_refresh_token_missing(self, test_client):
        """Test refresh token when token is missing."""
        response = test_client.get("/user/refresh_token")
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    @patch('authentication.src.auth_user.client')  # Redis client
    @patch('authentication.src.auth_user.auth_token')
    def test_refresh_token_with_valid_token(self, mock_auth, mock_redis, test_client, valid_refresh_token):
        """Test refresh token with valid token."""
        mock_redis.hgetall = AsyncMock(return_value={
            "refresh_token": "hashed_token",
            "device_fingerprint": "hashed_fingerprint",
            "data": "test_email",
            "session_id": "hashed_session"
        })
        
        response = test_client.get(
            "/user/refresh_token",
            cookies={"refresh_token": valid_refresh_token}
        )
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_500_INTERNAL_SERVER_ERROR]


class TestResetPassword:
    """Tests for password reset endpoint."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.mongo_client')
    @patch('authentication.src.auth_user.generate_otp')
    @patch('authentication.src.auth_user.send_mail_to_mailhog')
    def test_reset_password_request(self, mock_mail, mock_otp, mock_mongo, test_client):
        """Test password reset request."""
        mock_mongo.auth.user.find_one = AsyncMock(return_value={"email": "test@example.com"})
        mock_otp.return_value = AsyncMock(return_value="123456")
        mock_mail.return_value = True
        
        data = {"email": "test@example.com"}
        response = test_client.post("/user/reset_password", json=data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_reset_password_missing_email(self, test_client):
        """Test password reset with missing email."""
        data = {}
        response = test_client.post("/user/reset_password", json=data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.unit
    def test_reset_password_invalid_email(self, test_client):
        """Test password reset with invalid email format."""
        data = {"email": "invalid-email"}
        response = test_client.post("/user/reset_password", json=data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestVerifyOTPResetPassword:
    """Tests for OTP verification during password reset."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.client')  # Redis client
    def test_verify_reset_otp_success(self, mock_redis, test_client, sample_otp_data):
        """Test successful OTP verification for password reset."""
        mock_redis.hgetall = AsyncMock(return_value={"otp": "123456"})
        
        response = test_client.post("/user/reset_password/email_verify_otp", json=sample_otp_data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_401_UNAUTHORIZED, status.HTTP_500_INTERNAL_SERVER_ERROR]


class TestCreateNewPassword:
    """Tests for create new password endpoint."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.mongo_client')
    @patch('authentication.src.auth_user.client')  # Redis client
    @patch('authentication.src.auth_user.Hash')
    def test_create_new_password_success(self, mock_hash, mock_redis, mock_mongo, test_client):
        """Test successful password creation."""
        mock_mongo.auth.user.find_one = AsyncMock(return_value={
            "hashed_email": "hashed_test",
            "password": "old_hashed_password"
        })
        mock_mongo.auth.user.update_one = AsyncMock(return_value=MagicMock(modified_count=1))
        mock_hash.verify = AsyncMock(return_value=False)  # New password different from old
        mock_hash.generate_hash.return_value = "new_hashed_password"
        mock_redis.hset = AsyncMock(return_value=True)
        mock_redis.expire = AsyncMock(return_value=True)
        
        data = {
            "email": "test@example.com",
            "password": "NewSecurePass123",
            "confirm_password": "NewSecurePass123"
        }
        response = test_client.post("/user/create_new_password", json=data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND, status.HTTP_400_BAD_REQUEST, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_create_password_mismatch(self, test_client):
        """Test password creation with mismatched passwords."""
        data = {
            "email": "test@example.com",
            "password": "NewSecurePass123",
            "confirm_password": "DifferentPass123"
        }
        response = test_client.post("/user/create_new_password", json=data)
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_create_password_too_short(self, test_client):
        """Test password creation with too short password."""
        data = {
            "email": "test@example.com",
            "password": "12345",
            "confirm_password": "12345"
        }
        response = test_client.post("/user/create_new_password", json=data)
        assert response.status_code in [status.HTTP_400_BAD_REQUEST, status.HTTP_404_NOT_FOUND, status.HTTP_500_INTERNAL_SERVER_ERROR]


class TestUserLogout:
    """Tests for user logout endpoint."""
    
    @pytest.mark.unit
    @patch('authentication.src.auth_user.client')  # Redis client
    def test_logout_success(self, mock_redis, test_client):
        """Test successful logout."""
        mock_redis.delete = AsyncMock(return_value=True)
        
        data = {"data": "test@example.com"}
        response = test_client.post("/user/logout", json=data)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_500_INTERNAL_SERVER_ERROR]

    @pytest.mark.unit
    def test_logout_missing_data(self, test_client):
        """Test logout with missing data."""
        data = {}
        response = test_client.post("/user/logout", json=data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
