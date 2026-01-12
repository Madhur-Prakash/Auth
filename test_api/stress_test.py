"""
Stress Testing Scripts for Authentication System

This module contains stress tests using locust and custom scripts
to test the authentication system under heavy load.
"""

import asyncio
import aiohttp
import time
import random
import string
import statistics
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Any
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class StressTestConfig:
    """Configuration for stress tests."""
    base_url: str = "http://127.0.0.1:8005"
    num_users: int = 100
    requests_per_user: int = 10
    concurrent_users: int = 20
    ramp_up_time: float = 5.0  # seconds
    test_duration: float = 60.0  # seconds
    timeout: float = 30.0  # seconds per request


@dataclass
class RequestResult:
    """Result of a single request."""
    endpoint: str
    method: str
    status_code: int
    response_time: float
    success: bool
    error: str = None
    timestamp: float = None


class StressTestRunner:
    """Stress test runner for authentication endpoints."""
    
    def __init__(self, config: StressTestConfig = None):
        self.config = config or StressTestConfig()
        self.results: List[RequestResult] = []
        self.start_time = None
        self.end_time = None
    
    def generate_random_email(self) -> str:
        """Generate a random email address."""
        random_str = ''.join(random.choices(string.ascii_lowercase, k=8))
        return f"test_{random_str}_{int(time.time())}@example.com"
    
    def generate_random_phone(self) -> str:
        """Generate a random phone number."""
        return ''.join(random.choices(string.digits, k=10))
    
    def generate_random_password(self) -> str:
        """Generate a random password."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    
    def generate_user_data(self) -> Dict[str, Any]:
        """Generate random user data for signup."""
        return {
            "first_name": "Test",
            "last_name": "User",
            "email": self.generate_random_email(),
            "phone_number": self.generate_random_phone(),
            "country_code": "+1",
            "password": self.generate_random_password()
        }
    
    async def make_request(
        self, 
        session: aiohttp.ClientSession,
        method: str,
        endpoint: str,
        data: Dict = None
    ) -> RequestResult:
        """Make a single HTTP request and record results."""
        url = f"{self.config.base_url}{endpoint}"
        start = time.time()
        
        try:
            if method == "GET":
                async with session.get(url, timeout=self.config.timeout) as response:
                    status = response.status
                    await response.text()
            elif method == "POST":
                async with session.post(url, json=data, timeout=self.config.timeout) as response:
                    status = response.status
                    await response.text()
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response_time = time.time() - start
            success = 200 <= status < 500  # Consider 4xx as handled errors
            
            return RequestResult(
                endpoint=endpoint,
                method=method,
                status_code=status,
                response_time=response_time,
                success=success,
                timestamp=start
            )
        except asyncio.TimeoutError:
            return RequestResult(
                endpoint=endpoint,
                method=method,
                status_code=0,
                response_time=self.config.timeout,
                success=False,
                error="Timeout",
                timestamp=start
            )
        except Exception as e:
            return RequestResult(
                endpoint=endpoint,
                method=method,
                status_code=0,
                response_time=time.time() - start,
                success=False,
                error=str(e),
                timestamp=start
            )
    
    async def health_check_test(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test the health check endpoint."""
        return await self.make_request(session, "GET", "/")
    
    async def signup_test(self, session: aiohttp.ClientSession) -> RequestResult:
        """Test the signup endpoint with random data."""
        user_data = self.generate_user_data()
        return await self.make_request(session, "POST", "/user/signup", user_data)
    
    async def login_test(self, session: aiohttp.ClientSession, email: str, password: str) -> RequestResult:
        """Test the login endpoint."""
        login_data = {"email": email, "password": password}
        return await self.make_request(session, "POST", "/user/login", login_data)
    
    async def send_otp_test(self, session: aiohttp.ClientSession, email: str) -> RequestResult:
        """Test the send OTP endpoint."""
        data = {"email": email}
        return await self.make_request(session, "POST", "/user/signup/send_otp", data)
    
    async def run_user_session(self, user_id: int) -> List[RequestResult]:
        """Simulate a single user's session."""
        results = []
        
        async with aiohttp.ClientSession() as session:
            for _ in range(self.config.requests_per_user):
                # Random endpoint selection
                endpoint_choice = random.choice([
                    "health_check",
                    "signup",
                    "login",
                    "send_otp"
                ])
                
                if endpoint_choice == "health_check":
                    result = await self.health_check_test(session)
                elif endpoint_choice == "signup":
                    result = await self.signup_test(session)
                elif endpoint_choice == "login":
                    email = self.generate_random_email()
                    password = self.generate_random_password()
                    result = await self.login_test(session, email, password)
                elif endpoint_choice == "send_otp":
                    email = self.generate_random_email()
                    result = await self.send_otp_test(session, email)
                else:
                    result = await self.health_check_test(session)
                
                results.append(result)
                
                # Small delay between requests
                await asyncio.sleep(random.uniform(0.1, 0.5))
        
        return results
    
    async def run_concurrent_users(self, num_users: int) -> List[RequestResult]:
        """Run multiple concurrent user sessions."""
        tasks = [self.run_user_session(i) for i in range(num_users)]
        all_results = await asyncio.gather(*tasks)
        return [result for user_results in all_results for result in user_results]
    
    async def run_stress_test(self) -> Dict[str, Any]:
        """Run the complete stress test."""
        print(f"\n{'='*60}")
        print(f"Starting Stress Test")
        print(f"{'='*60}")
        print(f"Configuration:")
        print(f"  - Base URL: {self.config.base_url}")
        print(f"  - Number of Users: {self.config.num_users}")
        print(f"  - Requests per User: {self.config.requests_per_user}")
        print(f"  - Concurrent Users: {self.config.concurrent_users}")
        print(f"{'='*60}\n")
        
        self.start_time = time.time()
        self.results = []
        
        # Run in batches of concurrent users
        batches = self.config.num_users // self.config.concurrent_users
        remaining = self.config.num_users % self.config.concurrent_users
        
        for batch in range(batches):
            print(f"Running batch {batch + 1}/{batches}...")
            batch_results = await self.run_concurrent_users(self.config.concurrent_users)
            self.results.extend(batch_results)
        
        if remaining > 0:
            print(f"Running remaining {remaining} users...")
            batch_results = await self.run_concurrent_users(remaining)
            self.results.extend(batch_results)
        
        self.end_time = time.time()
        
        return self.generate_report()
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate a stress test report."""
        if not self.results:
            return {"error": "No results to report"}
        
        total_requests = len(self.results)
        successful_requests = sum(1 for r in self.results if r.success)
        failed_requests = total_requests - successful_requests
        
        response_times = [r.response_time for r in self.results]
        
        # Group by endpoint
        endpoints = {}
        for result in self.results:
            if result.endpoint not in endpoints:
                endpoints[result.endpoint] = {
                    "total": 0,
                    "success": 0,
                    "failed": 0,
                    "response_times": [],
                    "status_codes": {}
                }
            
            endpoints[result.endpoint]["total"] += 1
            endpoints[result.endpoint]["response_times"].append(result.response_time)
            
            if result.success:
                endpoints[result.endpoint]["success"] += 1
            else:
                endpoints[result.endpoint]["failed"] += 1
            
            status = str(result.status_code)
            endpoints[result.endpoint]["status_codes"][status] = \
                endpoints[result.endpoint]["status_codes"].get(status, 0) + 1
        
        # Calculate endpoint statistics
        for endpoint, data in endpoints.items():
            times = data["response_times"]
            data["avg_response_time"] = statistics.mean(times)
            data["min_response_time"] = min(times)
            data["max_response_time"] = max(times)
            data["p50_response_time"] = statistics.median(times)
            if len(times) >= 2:
                data["p95_response_time"] = times[int(len(times) * 0.95)]
                data["p99_response_time"] = times[int(len(times) * 0.99)]
            else:
                data["p95_response_time"] = times[-1] if times else 0
                data["p99_response_time"] = times[-1] if times else 0
            del data["response_times"]  # Remove raw data from report
        
        test_duration = self.end_time - self.start_time
        
        report = {
            "summary": {
                "test_duration_seconds": test_duration,
                "total_requests": total_requests,
                "successful_requests": successful_requests,
                "failed_requests": failed_requests,
                "success_rate": (successful_requests / total_requests) * 100 if total_requests > 0 else 0,
                "requests_per_second": total_requests / test_duration if test_duration > 0 else 0,
                "avg_response_time": statistics.mean(response_times),
                "min_response_time": min(response_times),
                "max_response_time": max(response_times),
                "median_response_time": statistics.median(response_times),
            },
            "endpoints": endpoints,
            "config": {
                "base_url": self.config.base_url,
                "num_users": self.config.num_users,
                "requests_per_user": self.config.requests_per_user,
                "concurrent_users": self.config.concurrent_users,
            }
        }
        
        return report


class TargetedStressTest:
    """Targeted stress tests for specific endpoints."""
    
    def __init__(self, base_url: str = "http://127.0.0.1:8005"):
        self.base_url = base_url
    
    async def health_check_burst(self, num_requests: int = 1000, concurrent: int = 100) -> Dict:
        """Burst test for health check endpoint."""
        print(f"\n{'='*60}")
        print(f"Health Check Burst Test - {num_requests} requests, {concurrent} concurrent")
        print(f"{'='*60}\n")
        
        results = []
        start = time.time()
        
        async def single_request(session):
            req_start = time.time()
            try:
                async with session.get(f"{self.base_url}/", timeout=10) as response:
                    await response.text()
                    return {"status": response.status, "time": time.time() - req_start, "success": True}
            except Exception as e:
                return {"status": 0, "time": time.time() - req_start, "success": False, "error": str(e)}
        
        async with aiohttp.ClientSession() as session:
            for i in range(0, num_requests, concurrent):
                batch_size = min(concurrent, num_requests - i)
                tasks = [single_request(session) for _ in range(batch_size)]
                batch_results = await asyncio.gather(*tasks)
                results.extend(batch_results)
                print(f"Completed {i + batch_size}/{num_requests} requests")
        
        total_time = time.time() - start
        success_count = sum(1 for r in results if r["success"])
        
        return {
            "endpoint": "/",
            "total_requests": num_requests,
            "concurrent": concurrent,
            "total_time": total_time,
            "requests_per_second": num_requests / total_time,
            "success_count": success_count,
            "failure_count": num_requests - success_count,
            "success_rate": (success_count / num_requests) * 100,
            "avg_response_time": statistics.mean([r["time"] for r in results]),
            "max_response_time": max([r["time"] for r in results]),
            "min_response_time": min([r["time"] for r in results]),
        }
    
    async def signup_load_test(self, num_signups: int = 100, concurrent: int = 10) -> Dict:
        """Load test for signup endpoint."""
        print(f"\n{'='*60}")
        print(f"Signup Load Test - {num_signups} signups, {concurrent} concurrent")
        print(f"{'='*60}\n")
        
        results = []
        start = time.time()
        
        def generate_user():
            random_str = ''.join(random.choices(string.ascii_lowercase, k=8))
            return {
                "first_name": "LoadTest",
                "last_name": "User",
                "email": f"loadtest_{random_str}_{int(time.time()*1000)}@example.com",
                "phone_number": ''.join(random.choices(string.digits, k=10)),
                "country_code": "+1",
                "password": "LoadTest123"
            }
        
        async def single_signup(session):
            user_data = generate_user()
            req_start = time.time()
            try:
                async with session.post(
                    f"{self.base_url}/user/signup",
                    json=user_data,
                    timeout=30
                ) as response:
                    await response.text()
                    return {
                        "status": response.status,
                        "time": time.time() - req_start,
                        "success": response.status in [201, 409, 500]  # 409 = already exists
                    }
            except Exception as e:
                return {"status": 0, "time": time.time() - req_start, "success": False, "error": str(e)}
        
        async with aiohttp.ClientSession() as session:
            for i in range(0, num_signups, concurrent):
                batch_size = min(concurrent, num_signups - i)
                tasks = [single_signup(session) for _ in range(batch_size)]
                batch_results = await asyncio.gather(*tasks)
                results.extend(batch_results)
                print(f"Completed {i + batch_size}/{num_signups} signups")
        
        total_time = time.time() - start
        success_count = sum(1 for r in results if r["success"])
        
        # Count status codes
        status_codes = {}
        for r in results:
            status = str(r["status"])
            status_codes[status] = status_codes.get(status, 0) + 1
        
        return {
            "endpoint": "/user/signup",
            "total_requests": num_signups,
            "concurrent": concurrent,
            "total_time": total_time,
            "requests_per_second": num_signups / total_time,
            "success_count": success_count,
            "failure_count": num_signups - success_count,
            "success_rate": (success_count / num_signups) * 100,
            "avg_response_time": statistics.mean([r["time"] for r in results]),
            "max_response_time": max([r["time"] for r in results]),
            "min_response_time": min([r["time"] for r in results]),
            "status_codes": status_codes
        }
    
    async def login_stress_test(self, num_attempts: int = 500, concurrent: int = 50) -> Dict:
        """Stress test for login endpoint."""
        print(f"\n{'='*60}")
        print(f"Login Stress Test - {num_attempts} attempts, {concurrent} concurrent")
        print(f"{'='*60}\n")
        
        results = []
        start = time.time()
        
        async def single_login(session):
            login_data = {
                "email": f"stress_test_{random.randint(1, 1000)}@example.com",
                "password": "StressTest123"
            }
            req_start = time.time()
            try:
                async with session.post(
                    f"{self.base_url}/user/login",
                    json=login_data,
                    timeout=30
                ) as response:
                    await response.text()
                    return {
                        "status": response.status,
                        "time": time.time() - req_start,
                        "success": response.status in [200, 401, 500]
                    }
            except Exception as e:
                return {"status": 0, "time": time.time() - req_start, "success": False, "error": str(e)}
        
        async with aiohttp.ClientSession() as session:
            for i in range(0, num_attempts, concurrent):
                batch_size = min(concurrent, num_attempts - i)
                tasks = [single_login(session) for _ in range(batch_size)]
                batch_results = await asyncio.gather(*tasks)
                results.extend(batch_results)
                print(f"Completed {i + batch_size}/{num_attempts} login attempts")
        
        total_time = time.time() - start
        success_count = sum(1 for r in results if r["success"])
        
        return {
            "endpoint": "/user/login",
            "total_requests": num_attempts,
            "concurrent": concurrent,
            "total_time": total_time,
            "requests_per_second": num_attempts / total_time,
            "success_count": success_count,
            "avg_response_time": statistics.mean([r["time"] for r in results]),
            "max_response_time": max([r["time"] for r in results]),
            "min_response_time": min([r["time"] for r in results]),
        }


def print_report(report: Dict):
    """Print a formatted stress test report."""
    print(f"\n{'='*60}")
    print("STRESS TEST REPORT")
    print(f"{'='*60}\n")
    
    summary = report.get("summary", {})
    print("SUMMARY:")
    print(f"  Test Duration: {summary.get('test_duration_seconds', 0):.2f} seconds")
    print(f"  Total Requests: {summary.get('total_requests', 0)}")
    print(f"  Successful: {summary.get('successful_requests', 0)}")
    print(f"  Failed: {summary.get('failed_requests', 0)}")
    print(f"  Success Rate: {summary.get('success_rate', 0):.2f}%")
    print(f"  Requests/Second: {summary.get('requests_per_second', 0):.2f}")
    print(f"\nRESPONSE TIMES:")
    print(f"  Average: {summary.get('avg_response_time', 0)*1000:.2f} ms")
    print(f"  Min: {summary.get('min_response_time', 0)*1000:.2f} ms")
    print(f"  Max: {summary.get('max_response_time', 0)*1000:.2f} ms")
    print(f"  Median: {summary.get('median_response_time', 0)*1000:.2f} ms")
    
    endpoints = report.get("endpoints", {})
    if endpoints:
        print(f"\nENDPOINT DETAILS:")
        for endpoint, data in endpoints.items():
            print(f"\n  {endpoint}:")
            print(f"    Total: {data.get('total', 0)}")
            print(f"    Success: {data.get('success', 0)}")
            print(f"    Failed: {data.get('failed', 0)}")
            print(f"    Avg Response: {data.get('avg_response_time', 0)*1000:.2f} ms")
            print(f"    Status Codes: {data.get('status_codes', {})}")
    
    print(f"\n{'='*60}\n")


async def main():
    """Main function to run stress tests."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Run stress tests on authentication system")
    parser.add_argument("--url", default="http://127.0.0.1:8005", help="Base URL of the API")
    parser.add_argument("--users", type=int, default=50, help="Number of users to simulate")
    parser.add_argument("--requests", type=int, default=5, help="Requests per user")
    parser.add_argument("--concurrent", type=int, default=10, help="Concurrent users")
    parser.add_argument("--test", choices=["full", "health", "signup", "login"], default="full",
                       help="Type of test to run")
    
    args = parser.parse_args()
    
    if args.test == "full":
        config = StressTestConfig(
            base_url=args.url,
            num_users=args.users,
            requests_per_user=args.requests,
            concurrent_users=args.concurrent
        )
        runner = StressTestRunner(config)
        report = await runner.run_stress_test()
        print_report(report)
        
        # Save report to file
        with open("stress_test_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print("Report saved to stress_test_report.json")
    
    elif args.test == "health":
        tester = TargetedStressTest(args.url)
        report = await tester.health_check_burst(args.users * args.requests, args.concurrent)
        print(json.dumps(report, indent=2))
    
    elif args.test == "signup":
        tester = TargetedStressTest(args.url)
        report = await tester.signup_load_test(args.users, args.concurrent)
        print(json.dumps(report, indent=2))
    
    elif args.test == "login":
        tester = TargetedStressTest(args.url)
        report = await tester.login_stress_test(args.users * args.requests, args.concurrent)
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
