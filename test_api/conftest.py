"""
Pytest Configuration and Fixtures for Authentication System Tests

This module contains shared fixtures, mocks, and configuration for testing
the authentication system.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set test environment variables before importing app
os.environ["SECRET_KEY"] = "test_secret_key_for_testing_purposes_only_12345"
os.environ["ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "60"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "7"
os.environ["DATA_ENCRYPTION_KEY"] = "test_encryption_key_32_chars!!!!"
os.environ["SESSION_SECRET_KEY"] = "test_session_secret_key"
os.environ["DEVELOPMENT_ENV"] = "local"
os.environ["ENVIRONMENT"] = "test"


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_redis_client():
    """Mock Redis client for testing."""
    mock_client = AsyncMock()
    mock_client.hgetall = AsyncMock(return_value={})
    mock_client.hset = AsyncMock(return_value=True)
    mock_client.set = AsyncMock(return_value=True)
    mock_client.get = AsyncMock(return_value=None)
    mock_client.delete = AsyncMock(return_value=True)
    mock_client.expire = AsyncMock(return_value=True)
    return mock_client


@pytest.fixture
def mock_mongo_client():
    """Mock MongoDB client for testing."""
    mock_client = MagicMock()
    mock_user_collection = AsyncMock()
    mock_user_collection.find_one = AsyncMock(return_value=None)
    mock_user_collection.insert_one = AsyncMock(return_value=MagicMock(inserted_id="test_id"))
    mock_user_collection.update_one = AsyncMock(return_value=MagicMock(modified_count=1))
    mock_user_collection.delete_one = AsyncMock(return_value=MagicMock(deleted_count=1))
    
    mock_client.auth.user = mock_user_collection
    return mock_client


@pytest.fixture
def mock_kafka_producer():
    """Mock Kafka producer for testing."""
    mock_producer = MagicMock()
    mock_producer.send = MagicMock(return_value=MagicMock())
    mock_producer.flush = MagicMock()
    return mock_producer


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john.doe@example.com",
        "phone_number": "1234567890",
        "country_code": "+1",
        "password": "SecurePass123"
    }


@pytest.fixture
def sample_login_data():
    """Sample login data for testing."""
    return {
        "email": "john.doe@example.com",
        "password": "SecurePass123"
    }


@pytest.fixture
def sample_otp_data():
    """Sample OTP data for testing."""
    return {
        "email": "john.doe@example.com",
        "otp": "123456"
    }


@pytest.fixture
def sample_phone_otp_data():
    """Sample phone OTP data for testing."""
    return {
        "phone_number": "1234567890",
        "country_code": "+1",
        "otp": "123456"
    }


@pytest.fixture
def mock_email_service():
    """Mock email service for testing."""
    with patch('authentication.otp_service.send_mail.send_mail_to_mailhog') as mock:
        mock.return_value = True
        yield mock


@pytest.fixture
def mock_sms_service():
    """Mock SMS service for testing."""
    with patch('authentication.otp_service.otp_verify.send_otp') as mock:
        mock.return_value = "123456"
        yield mock


@pytest.fixture
def test_app():
    """Create test application with mocked dependencies."""
    # Import app after setting environment variables
    from app import app
    return app


@pytest.fixture
def test_client(test_app):
    """Create test client for synchronous tests."""
    return TestClient(test_app)


@pytest.fixture
async def async_test_client(test_app):
    """Create async test client for asynchronous tests."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
def valid_access_token():
    """Generate a valid access token for testing."""
    from authentication.helper.auth_helper.auth_token import create_access_token
    return create_access_token(data={"sub": "test_user@example.com"})


@pytest.fixture
def valid_refresh_token():
    """Generate a valid refresh token for testing."""
    from authentication.helper.auth_helper.auth_token import create_refresh_token
    return create_refresh_token(data={"sub": "test_session_id", "data": "test_fingerprint"})


@pytest.fixture
def expired_token():
    """Generate an expired token for testing."""
    from datetime import datetime, timedelta
    from jose import jwt
    
    secret_key = os.getenv("SECRET_KEY")
    algorithm = os.getenv("ALGORITHM")
    
    expire = datetime.now() - timedelta(hours=1)
    data = {"sub": "test@example.com", "exp": expire}
    return jwt.encode(data, secret_key, algorithm=algorithm)


@pytest.fixture
def mock_request():
    """Create a mock FastAPI request object."""
    mock = MagicMock()
    mock.headers = {"user-agent": "test-agent"}
    mock.cookies = {}
    mock.query_params = {}
    return mock


@pytest.fixture
def mock_response():
    """Create a mock FastAPI response object."""
    mock = MagicMock()
    mock.set_cookie = MagicMock()
    mock.delete_cookie = MagicMock()
    return mock


# Helper functions for tests
def generate_test_user(
    email="test@example.com",
    phone="1234567890",
    first_name="Test",
    last_name="User",
    password="TestPass123"
):
    """Generate test user data with customizable fields."""
    return {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "phone_number": phone,
        "country_code": "+1",
        "password": password
    }


def generate_random_email():
    """Generate a random email for testing."""
    import uuid
    return f"test_{uuid.uuid4().hex[:8]}@example.com"


def generate_random_phone():
    """Generate a random phone number for testing."""
    import random
    return f"{random.randint(1000000000, 9999999999)}"


# Pytest configuration
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line("markers", "slow: mark test as slow running")
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "unit: mark test as unit test")
    config.addinivalue_line("markers", "stress: mark test as stress test")
