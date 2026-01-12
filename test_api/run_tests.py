#!/usr/bin/env python
"""
Test Runner Script for Authentication System

This script provides a unified interface to run all tests including:
- Unit tests
- Integration tests
- Stress tests
- Coverage reports

Usage:
    python run_tests.py --all           # Run all tests
    python run_tests.py --unit          # Run unit tests only
    python run_tests.py --integration   # Run integration tests only
    python run_tests.py --stress        # Run stress tests
    python run_tests.py --coverage      # Run tests with coverage
"""

import argparse
import subprocess
import sys
import os
import time
from pathlib import Path


def get_project_root():
    """Get the project root directory."""
    return Path(__file__).parent.parent


def run_command(command, description):
    """Run a shell command and print the result."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(command)}")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    result = subprocess.run(command, cwd=get_project_root())
    end_time = time.time()
    
    print(f"\n{'='*60}")
    print(f"Completed: {description}")
    print(f"Time: {end_time - start_time:.2f} seconds")
    print(f"Exit Code: {result.returncode}")
    print(f"{'='*60}\n")
    
    return result.returncode


def run_unit_tests(verbose=False):
    """Run unit tests."""
    cmd = [
        sys.executable, "-m", "pytest",
        "test_api/",
        "-m", "unit or not integration and not stress and not slow",
        "--ignore=test_api/stress_test.py",
        "--ignore=test_api/locustfile.py",
        "-v" if verbose else "-q",
    ]
    return run_command(cmd, "Unit Tests")


def run_integration_tests(verbose=False):
    """Run integration tests."""
    cmd = [
        sys.executable, "-m", "pytest",
        "test_api/test_integration.py",
        "-m", "integration",
        "-v" if verbose else "-q",
    ]
    return run_command(cmd, "Integration Tests")


def run_all_tests(verbose=False):
    """Run all tests except stress tests."""
    cmd = [
        sys.executable, "-m", "pytest",
        "test_api/",
        "--ignore=test_api/stress_test.py",
        "--ignore=test_api/locustfile.py",
        "-v" if verbose else "-q",
    ]
    return run_command(cmd, "All Tests")


def run_tests_with_coverage():
    """Run tests with coverage report."""
    cmd = [
        sys.executable, "-m", "pytest",
        "test_api/",
        "--ignore=test_api/stress_test.py",
        "--ignore=test_api/locustfile.py",
        "--cov=authentication",
        "--cov-report=html",
        "--cov-report=term-missing",
        "-v",
    ]
    return run_command(cmd, "Tests with Coverage")


def run_stress_tests(url="http://127.0.0.1:8005", users=50, concurrent=10):
    """Run custom stress tests."""
    cmd = [
        sys.executable,
        "test_api/stress_test.py",
        "--url", url,
        "--users", str(users),
        "--concurrent", str(concurrent),
        "--test", "full",
    ]
    return run_command(cmd, "Stress Tests")


def run_locust_tests(url="http://127.0.0.1:8005", users=100, spawn_rate=10, duration="1m"):
    """Run Locust load tests."""
    cmd = [
        sys.executable, "-m", "locust",
        "-f", "test_api/locustfile.py",
        "--host", url,
        "--headless",
        "-u", str(users),
        "-r", str(spawn_rate),
        "-t", duration,
        "--only-summary",
    ]
    return run_command(cmd, "Locust Load Tests")


def run_quick_test():
    """Run a quick smoke test."""
    cmd = [
        sys.executable, "-m", "pytest",
        "test_api/test_auth_endpoints.py::TestHealthCheck",
        "test_api/test_security.py::TestPasswordValidation",
        "-v",
    ]
    return run_command(cmd, "Quick Smoke Test")


def check_dependencies():
    """Check if required dependencies are installed."""
    print("\nChecking dependencies...")
    required = ["pytest", "pytest-asyncio", "pytest-cov", "httpx", "aiohttp"]
    missing = []
    
    for package in required:
        try:
            __import__(package.replace("-", "_"))
            print(f"  ✓ {package} installed")
        except ImportError:
            print(f"  ✗ {package} NOT installed")
            missing.append(package)
    
    if missing:
        print(f"\nMissing packages: {', '.join(missing)}")
        print("Install with: pip install " + " ".join(missing))
        return False
    
    print("\nAll dependencies satisfied!")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Test Runner for Authentication System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_tests.py --all           # Run all tests
    python run_tests.py --unit -v       # Run unit tests verbosely
    python run_tests.py --stress        # Run stress tests
    python run_tests.py --coverage      # Run with coverage report
    python run_tests.py --locust        # Run Locust load tests
        """
    )
    
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests")
    parser.add_argument("--stress", action="store_true", help="Run stress tests")
    parser.add_argument("--locust", action="store_true", help="Run Locust load tests")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage")
    parser.add_argument("--quick", action="store_true", help="Run quick smoke test")
    parser.add_argument("--check", action="store_true", help="Check dependencies")
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--url", default="http://127.0.0.1:8005", help="API URL for stress tests")
    parser.add_argument("--users", type=int, default=50, help="Number of users for stress test")
    parser.add_argument("--concurrent", type=int, default=10, help="Concurrent users")
    parser.add_argument("--duration", default="1m", help="Duration for Locust tests")
    
    args = parser.parse_args()
    
    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    
    exit_code = 0
    
    if args.check:
        if not check_dependencies():
            return 1
        return 0
    
    # Ensure we're in the right directory
    os.chdir(get_project_root())
    
    if args.quick:
        exit_code = run_quick_test()
    elif args.unit:
        exit_code = run_unit_tests(args.verbose)
    elif args.integration:
        exit_code = run_integration_tests(args.verbose)
    elif args.coverage:
        exit_code = run_tests_with_coverage()
    elif args.stress:
        exit_code = run_stress_tests(args.url, args.users, args.concurrent)
    elif args.locust:
        exit_code = run_locust_tests(args.url, args.users, args.concurrent, args.duration)
    elif args.all:
        exit_code = run_all_tests(args.verbose)
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
