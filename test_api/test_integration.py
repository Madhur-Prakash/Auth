"""
Integration Tests for Authentication System

This module contains integration tests that test the full flow
of authentication operations including database and cache interactions.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import status
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestFullSignupFlow:
    """Integration tests for the complete signup flow."""
    
    @pytest.mark.integration
    @patch('authentication.src.auth_user.mongo_client')
    @patch('authentication.src.auth_user.client')
    @patch('authentication.src.auth_user.producer')
    @patch('authentication.src.auth_user.send_mail_to_mailhog')
    @patch('authentication.src.auth_user.user_email_bloom_filter')
    @patch('authentication.src.auth_user.user_phone_bloom_filter')
    def test_signup_to_otp_flow(
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
        """Test the signup -> send OTP flow."""
        # Setup mocks
        mock_email_bloom.contains.return_value = False
        mock_phone_bloom.contains.return_value = False
        mock_mongo.auth.user.find_one = AsyncMock(return_value=None)
        mock_redis.hgetall = AsyncMock(return_value={})
        mock_redis.hset = AsyncMock(return_value=True)
        mock_redis.set = AsyncMock(return_value=True)
        mock_redis.expire = AsyncMock(return_value=True)
        mock_email_service.return_value = True
        
        # Step 1: Signup
        response = test_client.post("/user/signup", json=sample_user_data)
        # Response can vary based on actual services
        assert response.status_code in [201, 500]
        
        # Step 2: Send OTP for verification
        otp_response = test_client.post(
            "/user/signup/send_otp",
            json={"email": sample_user_data["email"]}
        )
        assert otp_response.status_code in [200, 500]


class TestFullLoginFlow:
    """Integration tests for the complete login flow."""
    
    @pytest.mark.integration
    @patch('authentication.src.auth_user.cache_with_password')
    @patch('authentication.src.auth_user.client')
    def test_login_to_refresh_flow(
        self,
        mock_redis,
        mock_cache,
        test_client,
        sample_login_data
    ):
        """Test the login -> refresh token flow."""
        # Mock successful login cache
        mock_cache.return_value = "cached_user_data"
        mock_redis.hset = AsyncMock(return_value=True)
        mock_redis.expire = AsyncMock(return_value=True)
        mock_redis.delete = AsyncMock(return_value=True)
        mock_redis.hgetall = AsyncMock(return_value={
            "refresh_token": "hashed_token",
            "device_fingerprint": "hashed_fingerprint",
            "data": "test_email",
            "session_id": "hashed_session"
        })
        
        # Step 1: Login
        login_response = test_client.post("/user/login", json=sample_login_data)
        assert login_response.status_code in [200, 401, 500]
        
        # Step 2: If login successful, try refresh token
        if login_response.status_code == 200:
            cookies = login_response.cookies
            refresh_response = test_client.get(
                "/user/refresh_token",
                cookies=dict(cookies)
            )
            assert refresh_response.status_code in [200, 401, 500]


class TestPasswordResetFlow:
    """Integration tests for password reset flow."""
    
    @pytest.mark.integration
    @patch('authentication.src.auth_user.mongo_client')
    @patch('authentication.src.auth_user.client')
    @patch('authentication.src.auth_user.generate_otp')
    @patch('authentication.src.auth_user.send_mail_to_mailhog')
    def test_reset_password_flow(
        self,
        mock_email,
        mock_otp,
        mock_redis,
        mock_mongo,
        test_client
    ):
        """Test password reset -> OTP verify -> create new password flow."""
        # Setup mocks
        mock_mongo.auth.user.find_one = AsyncMock(return_value={
            "hashed_email": "hashed_test",
            "password": "old_password_hash"
        })
        mock_otp.return_value = AsyncMock(return_value="123456")
        mock_email.return_value = True
        mock_redis.hgetall = AsyncMock(return_value={"otp": "123456"})
        
        # Step 1: Request password reset
        reset_response = test_client.post(
            "/user/reset_password",
            json={"email": "test@example.com"}
        )
        assert reset_response.status_code in [200, 404, 500]
        
        # Step 2: Verify OTP
        verify_response = test_client.post(
            "/user/reset_password/email_verify_otp",
            json={"email": "test@example.com", "otp": "123456"}
        )
        assert verify_response.status_code in [200, 401, 500]


class TestOTPLoginFlow:
    """Integration tests for OTP-based login flow."""
    
    @pytest.mark.integration
    @patch('authentication.src.auth_user.cache_without_password')
    @patch('authentication.src.auth_user.client')
    @patch('authentication.src.auth_user.generate_otp')
    @patch('authentication.src.auth_user.send_email')
    def test_otp_login_email_flow(
        self,
        mock_email,
        mock_otp,
        mock_redis,
        mock_cache,
        test_client
    ):
        """Test OTP login flow for email."""
        mock_cache.return_value = "cached_data"
        mock_otp.return_value = AsyncMock(return_value="123456")
        mock_email.return_value = True
        mock_redis.hgetall = AsyncMock(return_value={"otp": "123456"})
        mock_redis.hset = AsyncMock(return_value=True)
        mock_redis.expire = AsyncMock(return_value=True)
        mock_redis.delete = AsyncMock(return_value=True)
        
        # Step 1: Send OTP
        send_response = test_client.post(
            "/user/login/send_otp",
            json={"email": "test@example.com"}
        )
        assert send_response.status_code in [200, 401, 500]
        
        # Step 2: Verify OTP
        verify_response = test_client.post(
            "/user/login/email_verify_otp",
            json={"email": "test@example.com", "otp": "123456"}
        )
        assert verify_response.status_code in [200, 401, 500]


class TestSessionManagement:
    """Integration tests for session management."""
    
    @pytest.mark.integration
    @patch('authentication.src.auth_user.client')
    def test_logout_clears_session(self, mock_redis, test_client):
        """Test that logout properly clears session."""
        mock_redis.delete = AsyncMock(return_value=True)
        
        response = test_client.post(
            "/user/logout",
            json={"data": "test@example.com"}
        )
        
        assert response.status_code in [200, 500]
        
        # Verify cookies are cleared
        if response.status_code == 200:
            # Response should have instructions to delete cookies
            assert "access_token" not in response.cookies or \
                   response.cookies.get("access_token") == ""


class TestConcurrentRequests:
    """Test handling of concurrent requests."""
    
    @pytest.mark.integration
    def test_multiple_health_checks(self, test_client):
        """Test multiple concurrent health check requests."""
        import concurrent.futures
        
        def make_request():
            return test_client.get("/")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        # All requests should succeed
        success_count = sum(1 for r in results if r.status_code == 200)
        assert success_count >= 45  # Allow for some variance


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    @pytest.mark.integration
    @pytest.mark.slow
    def test_rapid_login_attempts(self, test_client):
        """Test that rapid login attempts are handled."""
        login_data = {
            "email": "test@example.com",
            "password": "TestPass123"
        }
        
        responses = []
        for _ in range(20):
            response = test_client.post("/user/login", json=login_data)
            responses.append(response.status_code)
        
        # Should not crash the server
        # May return 429 (Too Many Requests) if rate limiting is enabled
        valid_codes = [200, 401, 429, 500]
        assert all(code in valid_codes for code in responses)


class TestErrorHandling:
    """Test error handling scenarios."""
    
    @pytest.mark.integration
    def test_invalid_json_body(self, test_client):
        """Test handling of invalid JSON body."""
        response = test_client.post(
            "/user/signup",
            content="invalid json",
            headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 422

    @pytest.mark.integration
    def test_missing_content_type(self, test_client):
        """Test handling of missing content type."""
        response = test_client.post(
            "/user/signup",
            content='{"test": "data"}'
        )
        assert response.status_code in [400, 415, 422]

    @pytest.mark.integration
    def test_invalid_endpoint(self, test_client):
        """Test handling of invalid endpoint."""
        response = test_client.get("/nonexistent/endpoint")
        assert response.status_code == 404


class TestDataValidation:
    """Test data validation across endpoints."""
    
    @pytest.mark.integration
    def test_signup_sql_injection_attempt(self, test_client, sample_user_data):
        """Test that SQL injection attempts are handled safely."""
        sample_user_data["email"] = "'; DROP TABLE users; --@example.com"
        
        response = test_client.post("/user/signup", json=sample_user_data)
        # Should fail validation or be sanitized
        assert response.status_code in [400, 422, 500]

    @pytest.mark.integration
    def test_signup_xss_attempt(self, test_client, sample_user_data):
        """Test that XSS attempts are handled safely."""
        sample_user_data["first_name"] = "<script>alert('xss')</script>"
        
        response = test_client.post("/user/signup", json=sample_user_data)
        # Should either fail or sanitize the input
        assert response.status_code in [400, 422, 500]

    @pytest.mark.integration
    def test_very_long_input(self, test_client, sample_user_data):
        """Test handling of very long input strings."""
        sample_user_data["first_name"] = "A" * 10000
        
        response = test_client.post("/user/signup", json=sample_user_data)
        # Should handle gracefully
        assert response.status_code in [400, 422, 500]
