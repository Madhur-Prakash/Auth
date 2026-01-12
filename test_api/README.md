# Authentication System Test Suite

This directory contains comprehensive tests for the authentication system including unit tests, integration tests, and stress testing scripts.

## Test Structure

```
test_api/
├── conftest.py              # Pytest configuration and fixtures
├── test_auth_endpoints.py   # Unit tests for auth endpoints
├── test_helpers.py          # Unit tests for helper functions
├── test_security.py         # Unit tests for security module
├── test_models.py           # Unit tests for Pydantic models
├── test_integration.py      # Integration tests
├── stress_test.py           # Custom stress testing script
├── locustfile.py            # Locust load testing configuration
├── run_tests.py             # Test runner script
├── test_requirements.txt    # Test dependencies
└── README.md                # This file
```

## Setup

### 1. Install Test Dependencies

```bash
pip install -r test_api/test_requirements.txt
```

### 2. Ensure Services Are Running

Before running tests, ensure the following services are available:
- Redis (default: localhost:6379)
- MongoDB (default: localhost:27017)
- Kafka (default: localhost:9092) - for integration tests
- The API server (default: http://127.0.0.1:8005)

## Running Tests

### Quick Commands

```bash
# Run all tests
python test_api/run_tests.py --all

# Run unit tests only
python test_api/run_tests.py --unit

# Run with verbose output
python test_api/run_tests.py --unit -v

# Run integration tests
python test_api/run_tests.py --integration

# Run tests with coverage
python test_api/run_tests.py --coverage

# Run quick smoke test
python test_api/run_tests.py --quick
```

### Using Pytest Directly

```bash
# Run all tests
pytest test_api/ -v

# Run specific test file
pytest test_api/test_auth_endpoints.py -v

# Run specific test class
pytest test_api/test_auth_endpoints.py::TestUserSignup -v

# Run specific test
pytest test_api/test_auth_endpoints.py::TestUserSignup::test_signup_success -v

# Run with markers
pytest test_api/ -m unit -v
pytest test_api/ -m integration -v

# Run with coverage
pytest test_api/ --cov=authentication --cov-report=html

# Run in parallel (faster)
pytest test_api/ -n auto
```

## Stress Testing

### Using Custom Stress Test Script

```bash
# Full stress test
python test_api/stress_test.py --test full --users 100 --concurrent 20

# Health check burst test
python test_api/stress_test.py --test health --users 1000 --concurrent 100

# Signup load test
python test_api/stress_test.py --test signup --users 100 --concurrent 10

# Login stress test
python test_api/stress_test.py --test login --users 500 --concurrent 50
```

### Using Locust

```bash
# Run Locust with web UI
locust -f test_api/locustfile.py --host=http://127.0.0.1:8005

# Run headless (without UI)
locust -f test_api/locustfile.py --host=http://127.0.0.1:8005 \
    --headless -u 100 -r 10 -t 5m

# Run with specific user class
locust -f test_api/locustfile.py --host=http://127.0.0.1:8005 \
    --headless -u 50 -r 5 -t 2m AuthenticationUser
```

**Locust Web UI:** After starting Locust, open http://localhost:8089 to access the web interface.

## Test Categories

### Unit Tests (`@pytest.mark.unit`)
- Test individual functions/methods in isolation
- Mock external dependencies (database, cache, etc.)
- Fast execution

### Integration Tests (`@pytest.mark.integration`)
- Test complete flows
- May require running services
- Test interaction between components

### Stress Tests (`@pytest.mark.stress`)
- Test system under load
- Measure performance metrics
- Identify bottlenecks

### Slow Tests (`@pytest.mark.slow`)
- Tests that take longer to execute
- Rate limiting tests
- Timeout tests

## Test Coverage

Generate coverage reports:

```bash
# Terminal report
pytest test_api/ --cov=authentication --cov-report=term-missing

# HTML report
pytest test_api/ --cov=authentication --cov-report=html
# Open htmlcov/index.html in browser

# XML report (for CI/CD)
pytest test_api/ --cov=authentication --cov-report=xml
```

## Writing New Tests

### 1. Use Fixtures from conftest.py

```python
def test_example(test_client, sample_user_data, mock_redis_client):
    # test_client: FastAPI TestClient
    # sample_user_data: Pre-configured user data
    # mock_redis_client: Mocked Redis client
    pass
```

### 2. Use Appropriate Markers

```python
import pytest

@pytest.mark.unit
def test_unit_example():
    pass

@pytest.mark.integration
def test_integration_example():
    pass

@pytest.mark.slow
def test_slow_example():
    pass
```

### 3. Mock External Dependencies

```python
from unittest.mock import patch, AsyncMock

@patch('authentication.src.auth_user.client')
def test_with_mock(mock_redis, test_client):
    mock_redis.hgetall = AsyncMock(return_value={"key": "value"})
    # Your test code
```

## Troubleshooting

### Import Errors
Ensure you're running tests from the project root directory:
```bash
cd Auth
pytest test_api/
```

### Service Connection Errors
Check that Redis, MongoDB, and other services are running:
```bash
# Check Redis
redis-cli ping

# Check MongoDB
mongosh --eval "db.adminCommand('ping')"
```

### Timeout Issues
Increase timeout for slow tests:
```bash
pytest test_api/ --timeout=120
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis
        ports:
          - 6379:6379
      mongodb:
        image: mongo
        ports:
          - 27017:27017

    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pip install -r test_api/test_requirements.txt
      - run: pytest test_api/ --cov=authentication --cov-report=xml
      - uses: codecov/codecov-action@v3
```

## Performance Benchmarks

Expected performance targets:
- Health check: < 50ms response time
- Login: < 500ms response time
- Signup: < 1s response time (includes email)
- System should handle: 100 concurrent users
- Throughput: 50+ requests/second

## Contributing

1. Write tests for new features
2. Ensure all tests pass before submitting PR
3. Maintain >80% code coverage
4. Follow existing test patterns
