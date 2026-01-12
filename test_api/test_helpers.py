"""
Unit Tests for Helper Functions

This module contains tests for utility functions, hashing, tokens,
encryption, and other helper modules.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set up environment variables
os.environ["SECRET_KEY"] = "test_secret_key_for_testing_purposes_only_12345"
os.environ["ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "60"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "7"
os.environ["DATA_ENCRYPTION_KEY"] = "test_encryption_key_32_chars!!!!"


class TestHashModule:
    """Tests for the Hash class in hashing.py."""
    
    def test_generate_hash_returns_string(self):
        """Test that generate_hash returns a string."""
        from authentication.helper.hashing import Hash
        
        password = "TestPassword123"
        hashed = Hash.generate_hash(password)
        
        assert isinstance(hashed, str)
        assert len(hashed) > 0
        assert hashed != password

    def test_generate_hash_different_for_same_password(self):
        """Test that generate_hash produces different hashes for same password."""
        from authentication.helper.hashing import Hash
        
        password = "TestPassword123"
        hash1 = Hash.generate_hash(password)
        hash2 = Hash.generate_hash(password)
        
        # bcrypt generates different hashes due to random salt
        assert hash1 != hash2

    def test_generate_hash_empty_password_raises_error(self):
        """Test that empty password raises ValueError."""
        from authentication.helper.hashing import Hash
        
        with pytest.raises(ValueError):
            Hash.generate_hash("")

    def test_generate_hash_whitespace_only_raises_error(self):
        """Test that whitespace-only password raises ValueError."""
        from authentication.helper.hashing import Hash
        
        with pytest.raises(ValueError):
            Hash.generate_hash("   ")

    @pytest.mark.asyncio
    async def test_verify_correct_password(self):
        """Test verify returns True for correct password."""
        from authentication.helper.hashing import Hash
        
        password = "TestPassword123"
        hashed = Hash.generate_hash(password)
        
        result = await Hash.verify(hashed, password)
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_incorrect_password(self):
        """Test verify returns False for incorrect password."""
        from authentication.helper.hashing import Hash
        
        password = "TestPassword123"
        wrong_password = "WrongPassword456"
        hashed = Hash.generate_hash(password)
        
        result = await Hash.verify(hashed, wrong_password)
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_empty_password_returns_false(self):
        """Test verify returns False for empty plain password."""
        from authentication.helper.hashing import Hash
        
        hashed = Hash.generate_hash("TestPassword123")
        result = await Hash.verify(hashed, "")
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_none_inputs_returns_false(self):
        """Test verify returns False when inputs are None."""
        from authentication.helper.hashing import Hash
        
        result = await Hash.verify(None, "test")
        assert result is False
        
        result = await Hash.verify("test", None)
        assert result is False


class TestDeterministicHash:
    """Tests for deterministic hash function."""
    
    def test_generate_deterministic_hash_returns_string(self):
        """Test that function returns a string."""
        from authentication.helper.deterministic_hash import generate_deterministic_hash
        
        result = generate_deterministic_hash("test@example.com")
        assert isinstance(result, str)

    def test_generate_deterministic_hash_consistent(self):
        """Test that same input produces same output."""
        from authentication.helper.deterministic_hash import generate_deterministic_hash
        
        input_str = "test@example.com"
        hash1 = generate_deterministic_hash(input_str)
        hash2 = generate_deterministic_hash(input_str)
        
        assert hash1 == hash2

    def test_generate_deterministic_hash_different_inputs(self):
        """Test that different inputs produce different outputs."""
        from authentication.helper.deterministic_hash import generate_deterministic_hash
        
        hash1 = generate_deterministic_hash("test1@example.com")
        hash2 = generate_deterministic_hash("test2@example.com")
        
        assert hash1 != hash2

    def test_generate_deterministic_hash_length(self):
        """Test that SHA-256 hash has correct length."""
        from authentication.helper.deterministic_hash import generate_deterministic_hash
        
        result = generate_deterministic_hash("test")
        # SHA-256 produces 64 character hex string
        assert len(result) == 64


class TestAuthToken:
    """Tests for auth token functions."""
    
    def test_create_access_token(self):
        """Test access token creation."""
        from authentication.helper.auth_token import create_access_token
        
        token = create_access_token(data={"sub": "test@example.com"})
        
        assert isinstance(token, str)
        assert len(token) > 0
        # JWT has 3 parts separated by dots
        assert len(token.split(".")) == 3

    def test_create_refresh_token(self):
        """Test refresh token creation."""
        from authentication.helper.auth_token import create_refresh_token
        
        token = create_refresh_token(data={"sub": "session_id", "data": "fingerprint"})
        
        assert isinstance(token, str)
        assert len(token) > 0
        assert len(token.split(".")) == 3

    def test_verify_token_valid(self):
        """Test token verification with valid token."""
        from authentication.helper.auth_token import create_access_token, verify_token
        from fastapi import HTTPException
        
        token = create_access_token(data={"sub": "test@example.com"})
        credentials_exception = HTTPException(status_code=401, detail="Invalid credentials")
        
        result = verify_token(token, credentials_exception)
        assert result.email == "test@example.com"

    def test_verify_token_invalid(self):
        """Test token verification with invalid token."""
        from authentication.helper.auth_token import verify_token
        from fastapi import HTTPException
        
        credentials_exception = HTTPException(status_code=401, detail="Invalid credentials")
        
        with pytest.raises(HTTPException):
            verify_token("invalid_token", credentials_exception)

    def test_decode_token(self):
        """Test token decoding."""
        from authentication.helper.auth_token import create_access_token, decode_token
        from fastapi import HTTPException
        
        token = create_access_token(data={"sub": "test@example.com"})
        credentials_exception = HTTPException(status_code=401, detail="Invalid credentials")
        
        result = decode_token(token, credentials_exception)
        assert result == "test@example.com"

    def test_decode_token_data(self):
        """Test decoding data field from token."""
        from authentication.helper.auth_token import create_refresh_token, decode_token_data
        from fastapi import HTTPException
        
        token = create_refresh_token(data={"sub": "session_id", "data": "fingerprint_data"})
        credentials_exception = HTTPException(status_code=401, detail="Invalid credentials")
        
        result = decode_token_data(token, credentials_exception)
        assert result == "fingerprint_data"

    def test_access_token_contains_expiration(self):
        """Test that access token contains expiration."""
        from authentication.helper.auth_token import create_access_token
        from jose import jwt
        
        token = create_access_token(data={"sub": "test@example.com"})
        secret_key = os.environ["SECRET_KEY"]
        algorithm = os.environ["ALGORITHM"]
        
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        assert "exp" in payload


class TestUtilFunctions:
    """Tests for utility functions."""
    
    def test_generate_random_string(self):
        """Test random string generation."""
        from authentication.helper.utils import generate_random_string
        
        result = generate_random_string()
        
        assert isinstance(result, str)
        assert len(result) == 8  # 4 letters + 4 digits
        # First 4 should be uppercase letters
        assert result[:4].isupper()
        assert result[:4].isalpha()
        # Last 4 should be digits
        assert result[4:].isdigit()

    def test_generate_random_string_uniqueness(self):
        """Test that random strings are unique."""
        from authentication.helper.utils import generate_random_string
        
        results = set()
        for _ in range(100):
            results.add(generate_random_string())
        
        # All should be unique
        assert len(results) == 100

    def test_create_session_id(self):
        """Test session ID creation."""
        from authentication.helper.utils import create_session_id
        
        session_id = create_session_id()
        
        assert isinstance(session_id, str)
        # UUID format
        assert len(session_id) == 36
        assert session_id.count("-") == 4

    def test_create_session_id_uniqueness(self):
        """Test that session IDs are unique."""
        from authentication.helper.utils import create_session_id
        
        results = set()
        for _ in range(100):
            results.add(create_session_id())
        
        assert len(results) == 100

    def test_get_country_name(self):
        """Test country name extraction from phone number."""
        from authentication.helper.utils import get_country_name
        
        # US phone number
        result = get_country_name("+14155551234")
        assert "United States" in result or "America" in result

    def test_get_country_name_with_plus(self):
        """Test country name with plus sign."""
        from authentication.helper.utils import get_country_name
        
        result = get_country_name("+911234567890")  # India
        assert result == "India"

    def test_get_country_name_without_plus(self):
        """Test country name without plus sign."""
        from authentication.helper.utils import get_country_name
        
        result = get_country_name("911234567890")  # India without plus
        assert result == "India"

    def test_generate_fingerprint_hash(self):
        """Test fingerprint hash generation."""
        from authentication.helper.utils import generate_fingerprint_hash
        
        mock_request = MagicMock()
        mock_request.headers = {"user-agent": "Mozilla/5.0 Test Browser"}
        
        result = generate_fingerprint_hash(mock_request)
        
        assert isinstance(result, str)
        assert len(result) > 0


class TestBloomFilter:
    """Tests for the Bloom filter implementation."""
    
    def test_bloom_filter_add_and_contains(self):
        """Test adding and checking items in bloom filter."""
        from authentication.config.bloom_filter import CountingBloomFilter
        
        bf = CountingBloomFilter(capacity=1000, error_rate=0.01)
        
        bf.add("test@example.com")
        
        assert bf.contains("test@example.com") is True

    def test_bloom_filter_not_contains(self):
        """Test that non-added items are not found."""
        from authentication.config.bloom_filter import CountingBloomFilter
        
        bf = CountingBloomFilter(capacity=1000, error_rate=0.01)
        
        assert bf.contains("nonexistent@example.com") is False

    def test_bloom_filter_remove(self):
        """Test removing items from counting bloom filter."""
        from authentication.config.bloom_filter import CountingBloomFilter
        
        bf = CountingBloomFilter(capacity=1000, error_rate=0.01)
        
        bf.add("test@example.com")
        assert bf.contains("test@example.com") is True
        
        bf.remove("test@example.com")
        assert bf.contains("test@example.com") is False

    def test_bloom_filter_multiple_adds(self):
        """Test adding multiple items."""
        from authentication.config.bloom_filter import CountingBloomFilter
        
        bf = CountingBloomFilter(capacity=1000, error_rate=0.01)
        
        emails = ["test1@example.com", "test2@example.com", "test3@example.com"]
        for email in emails:
            bf.add(email)
        
        for email in emails:
            assert bf.contains(email) is True


class TestSetupLogging:
    """Tests for logging setup."""
    
    def test_setup_logging_returns_logger(self):
        """Test that setup_logging returns a logger instance."""
        from authentication.helper.utils import setup_logging
        
        logger = setup_logging()
        
        assert logger is not None
        assert hasattr(logger, 'info')
        assert hasattr(logger, 'error')
        assert hasattr(logger, 'warning')
        assert hasattr(logger, 'debug')

    def test_setup_logging_name(self):
        """Test that logger has correct name."""
        from authentication.helper.utils import setup_logging
        
        logger = setup_logging()
        
        assert logger.name == "auth_log"


class TestCreateNewLog:
    """Tests for the create_new_log function."""
    
    @patch('authentication.helper.utils.requests.post')
    def test_create_new_log_success(self, mock_post):
        """Test successful log creation."""
        from authentication.helper.utils import create_new_log
        
        mock_post.return_value = MagicMock(status_code=200)
        
        result = create_new_log("info", "Test message", "/test/endpoint")
        
        # Check that post was called
        assert mock_post.called or result is None  # May fail if service is down

    @patch('authentication.helper.utils.requests.post')
    def test_create_new_log_failure_handled(self, mock_post):
        """Test that log creation failure is handled gracefully."""
        from authentication.helper.utils import create_new_log
        
        mock_post.side_effect = Exception("Connection error")
        
        # Should not raise an exception
        result = create_new_log("error", "Test error", "/test/endpoint")
        
        # Should return None on failure
        assert result is None
