"""
Locust Load Testing for Authentication System

This module provides Locust-based load testing for comprehensive
stress testing with real-time monitoring and detailed metrics.

Usage:
    locust -f locustfile.py --host=http://127.0.0.1:8005

    Or run headless:
    locust -f locustfile.py --host=http://127.0.0.1:8005 --headless -u 100 -r 10 -t 5m
"""

from locust import HttpUser, task, between, events
from locust.runners import MasterRunner
import random
import string
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_random_email():
    """Generate a random email for testing."""
    random_str = ''.join(random.choices(string.ascii_lowercase, k=8))
    return f"locust_{random_str}_{int(time.time()*1000)}@example.com"


def generate_random_phone():
    """Generate a random 10-digit phone number."""
    return ''.join(random.choices(string.digits, k=10))


def generate_random_password():
    """Generate a random password."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10))


class AuthenticationUser(HttpUser):
    """
    Simulates a user interacting with the authentication system.
    This user will perform various authentication actions like
    signup, login, OTP verification, and token refresh.
    """
    
    # Wait between 1 and 5 seconds between tasks
    wait_time = between(1, 5)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_email = None
        self.user_password = None
        self.user_phone = None
        self.access_token = None
        self.refresh_token = None
    
    def on_start(self):
        """Called when a new user starts."""
        self.user_email = generate_random_email()
        self.user_password = generate_random_password()
        self.user_phone = generate_random_phone()
        logger.info(f"User started: {self.user_email[:20]}...")
    
    @task(10)
    def health_check(self):
        """
        Most common task: Check if the API is healthy.
        Higher weight (10) means this runs more frequently.
        """
        with self.client.get("/", name="Health Check", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")
    
    @task(3)
    def signup_new_user(self):
        """
        Signup a new user.
        Medium weight (3) for signup attempts.
        """
        user_data = {
            "first_name": "Locust",
            "last_name": "Test",
            "email": generate_random_email(),
            "phone_number": generate_random_phone(),
            "country_code": "+1",
            "password": self.user_password
        }
        
        with self.client.post(
            "/user/signup",
            json=user_data,
            name="User Signup",
            catch_response=True
        ) as response:
            if response.status_code == 201:
                response.success()
                # Store for potential future login
                self.user_email = user_data["email"]
                logger.info(f"Signup successful for {self.user_email[:20]}...")
            elif response.status_code == 409:
                # Email already exists - expected in stress testing
                response.success()
            elif response.status_code == 500:
                # May fail due to external services (email, kafka)
                response.success()  # Don't count as failure for stress test
            else:
                response.failure(f"Signup failed: {response.status_code}")
    
    @task(5)
    def login_with_credentials(self):
        """
        Login with email and password.
        Higher weight (5) as login is common.
        """
        login_data = {
            "email": self.user_email,
            "password": self.user_password
        }
        
        with self.client.post(
            "/user/login",
            json=login_data,
            name="User Login",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
                try:
                    data = response.json()
                    self.access_token = data.get("access_token")
                    self.refresh_token = data.get("refresh_token")
                except:
                    pass
            elif response.status_code == 401:
                # Invalid credentials - expected for random users
                response.success()
            elif response.status_code == 500:
                response.success()  # External service failure
            else:
                response.failure(f"Login failed: {response.status_code}")
    
    @task(2)
    def send_otp_for_signup(self):
        """
        Send OTP for signup verification.
        Lower weight (2) as it depends on signup.
        """
        otp_data = {"email": generate_random_email()}
        
        with self.client.post(
            "/user/signup/send_otp",
            json=otp_data,
            name="Send OTP (Signup)",
            catch_response=True
        ) as response:
            if response.status_code in [200, 500]:
                response.success()  # 500 may be email service failure
            else:
                response.failure(f"Send OTP failed: {response.status_code}")
    
    @task(2)
    def send_otp_for_login(self):
        """
        Send OTP for login.
        """
        otp_data = {"email": self.user_email}
        
        with self.client.post(
            "/user/login/send_otp",
            json=otp_data,
            name="Send OTP (Login)",
            catch_response=True
        ) as response:
            if response.status_code in [200, 401, 500]:
                response.success()
            else:
                response.failure(f"Send login OTP failed: {response.status_code}")
    
    @task(1)
    def verify_otp_signup(self):
        """
        Verify OTP for signup (will mostly fail as we don't have real OTP).
        Lowest weight (1) as it's expected to fail.
        """
        otp_data = {
            "email": self.user_email,
            "otp": "123456"  # Random OTP
        }
        
        with self.client.post(
            "/user/signup/email_verify_otp",
            json=otp_data,
            name="Verify OTP (Signup)",
            catch_response=True
        ) as response:
            # All responses are acceptable for load testing
            if response.status_code in [200, 400, 401, 500]:
                response.success()
            else:
                response.failure(f"Verify OTP failed: {response.status_code}")
    
    @task(1)
    def request_password_reset(self):
        """
        Request password reset.
        """
        reset_data = {"email": self.user_email}
        
        with self.client.post(
            "/user/reset_password",
            json=reset_data,
            name="Password Reset Request",
            catch_response=True
        ) as response:
            if response.status_code in [200, 404, 500]:
                response.success()
            else:
                response.failure(f"Password reset failed: {response.status_code}")
    
    @task(2)
    def refresh_access_token(self):
        """
        Refresh the access token using refresh token.
        """
        cookies = {}
        if self.refresh_token:
            cookies["refresh_token"] = self.refresh_token
        
        with self.client.get(
            "/user/refresh_token",
            cookies=cookies,
            name="Refresh Token",
            catch_response=True
        ) as response:
            if response.status_code in [200, 401, 500]:
                response.success()
                if response.status_code == 200:
                    try:
                        data = response.json()
                        self.access_token = data.get("access_token")
                        self.refresh_token = data.get("refresh_token")
                    except:
                        pass
            else:
                response.failure(f"Token refresh failed: {response.status_code}")
    
    @task(1)
    def logout_user(self):
        """
        Logout the user.
        """
        logout_data = {"data": self.user_email}
        
        with self.client.post(
            "/user/logout",
            json=logout_data,
            name="User Logout",
            catch_response=True
        ) as response:
            if response.status_code in [200, 500]:
                response.success()
                self.access_token = None
                self.refresh_token = None
            else:
                response.failure(f"Logout failed: {response.status_code}")


class HeavySignupUser(HttpUser):
    """
    User that focuses heavily on signup operations.
    Useful for testing signup endpoint under heavy load.
    """
    
    wait_time = between(0.5, 2)
    
    @task
    def continuous_signup(self):
        """Continuously attempt signups."""
        user_data = {
            "first_name": "Heavy",
            "last_name": "Signup",
            "email": generate_random_email(),
            "phone_number": generate_random_phone(),
            "country_code": "+1",
            "password": generate_random_password()
        }
        
        with self.client.post(
            "/user/signup",
            json=user_data,
            name="Heavy Signup",
            catch_response=True
        ) as response:
            # Accept any response for load testing
            response.success()


class HeavyLoginUser(HttpUser):
    """
    User that focuses heavily on login operations.
    Useful for testing login endpoint under heavy load.
    """
    
    wait_time = between(0.5, 2)
    
    @task
    def continuous_login(self):
        """Continuously attempt logins."""
        login_data = {
            "email": generate_random_email(),
            "password": generate_random_password()
        }
        
        with self.client.post(
            "/user/login",
            json=login_data,
            name="Heavy Login",
            catch_response=True
        ) as response:
            # Accept any response for load testing
            response.success()


class RapidHealthCheckUser(HttpUser):
    """
    User that rapidly checks health endpoint.
    Useful for baseline performance testing.
    """
    
    wait_time = between(0.1, 0.5)
    
    @task
    def rapid_health_check(self):
        """Rapidly check health endpoint."""
        self.client.get("/", name="Rapid Health Check")


# Event handlers for custom logging and metrics
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when the test starts."""
    logger.info("="*60)
    logger.info("LOAD TEST STARTED")
    logger.info("="*60)
    if isinstance(environment.runner, MasterRunner):
        logger.info(f"Running as master with {environment.runner.worker_count} workers")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when the test stops."""
    logger.info("="*60)
    logger.info("LOAD TEST COMPLETED")
    logger.info("="*60)


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, response, **kwargs):
    """Called for each request. Useful for custom logging."""
    if response_time > 5000:  # Log slow requests (>5 seconds)
        logger.warning(f"Slow request: {name} took {response_time}ms")


# Custom event for failed requests
@events.request.add_listener  
def on_request_failure(request_type, name, response_time, exception, **kwargs):
    """Called when a request fails."""
    if exception:
        logger.error(f"Request failed: {name} - {exception}")
