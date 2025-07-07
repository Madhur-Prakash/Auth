from locust import HttpUser, task, between
from pymongo import MongoClient
import logging
import matplotlib.pyplot as plt
import time
import psutil
import requests
import concurrent.futures
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=f'load_test_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
)

class APILoadTest(HttpUser):
    """Locust load testing class for API endpoints"""
    wait_time = between(1, 3)  # Wait 1-3 seconds between tasks
    
    def on_start(self):
        """Setup run before starting tests"""
        self.login_data = {
            "email": "Jhon@mail.com",
            "password": "123456"
        }
    
    @task(1)
    def test_login(self):
        """Test login endpoint"""
        with self.client.post("http://34.229.135.184/user/login", 
                            data=self.login_data, 
                            catch_response=True) as response:
            if response.status_code == 200:
                logging.info(f"Successful login - Response time: {response.elapsed.total_seconds()}s")
            else:
                logging.error(f"Failed login - Status code: {response.status_code}")

class MongoDBStressTest:
    """MongoDB specific stress testing"""
    def __init__(self, uri="mongodb://ec2-3-84-251-0.compute-1.amazonaws.com:27017/auth"):
        self.client = MongoClient(uri)
        self.db = self.client.test_database
        self.collection = self.db.test_collection
        
    def generate_test_data(self, size=1000):
        """Generate test documents"""
        return [{"index": i, 
                "data": "x" * 1000,  # 1KB of data
                "timestamp": datetime.now()} 
                for i in range(size)]
    
    def run_write_test(self, num_docs=1000):
        """Test write operations"""
        try:
            test_data = self.generate_test_data(num_docs)
            result = self.collection.insert_many(test_data)
            logging.info(f"Successfully inserted {len(result.inserted_ids)} documents")
        except Exception as e:
            logging.error(f"Write test failed: {str(e)}")
    
    def run_read_test(self, num_queries=1000):
        """Test read operations"""
        try:
            for i in range(num_queries):
                self.collection.find_one({"index": i % 1000})
            logging.info(f"Successfully completed {num_queries} read queries")
        except Exception as e:
            logging.error(f"Read test failed: {str(e)}")
    
    def cleanup(self):
        """Clean up test data"""
        self.collection.drop()
        self.client.close()

class GradualLoadTester:
    """Implements gradual load increase with monitoring"""
    def __init__(self, base_url="34.229.135.184/user/login"):
        self.base_url = base_url
        self.session = requests.Session()
        
    def monitor_system_metrics(self):
        """Basic system monitoring"""
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent
        disk = psutil.disk_usage()
        ram = psutil.virtual_memory()
        return {
            "cpu_usage": cpu_percent,
            "memory_usage": memory_percent,
            "ram_usage": ram.percent,
            "disk_usage": disk.percent,
            "timestamp": datetime.now()
        }
    
    def run_gradual_load_test(self, 
                             start_users=1,
                             max_users=100,
                             step_size=10,
                             step_duration=60):
        """
        Gradually increase load while monitoring system
        """
        current_users = start_users
        
        while current_users <= max_users:
            logging.info(f"Testing with {current_users} concurrent users")
            
            # Create thread pool with current number of users
            with concurrent.futures.ThreadPoolExecutor(max_workers=current_users) as executor:
                futures = []
                for _ in range(current_users):
                    futures.append(executor.submit(self.send_test_request))
                
                # Wait for all requests to complete
                concurrent.futures.wait(futures)
            
            # Monitor system metrics
            metrics = self.monitor_system_metrics()
            logging.info(f"System metrics: {metrics}")
            
            # Check if system is overwhelmed
            if metrics["cpu_usage"] > 90 or metrics["memory_usage"] > 90:
                logging.warning("System resources critically high, stopping test")
                break
            
            # Increase users for next iteration
            current_users += step_size
            time.sleep(step_duration)
    
    def send_test_request(self):
        """Send a single test request"""
        try:
            response = self.session.post(f"{self.base_url}/user/login",
                                       json={"email": "Jhon@mail.com",
                                            "password": "123456"})
            return response.status_code
        except Exception as e:
            logging.error(f"Request failed: {str(e)}")
            return None

def run_comprehensive_test():
    """Run all tests in sequence"""
    # 1. Start with MongoDB stress test
    mongo_tester = MongoDBStressTest()
    mongo_tester.run_write_test(1000)
    mongo_tester.run_read_test(1000)
    
    # 2. Run gradual load test
    load_tester = GradualLoadTester()
    load_tester.run_gradual_load_test()
    
    # 3. Clean up
    mongo_tester.cleanup()

def plot_system_metrics():
    """Continuously plot system usage"""
    cpu_usage = []
    memory_usage = []
    timestamps = []

    plt.ion()  # Turn on interactive mode
    fig, ax = plt.subplots()

    while True:
        metrics = {
            "cpu": psutil.cpu_percent(),
            "memory": psutil.virtual_memory().percent
        }

        cpu_usage.append(metrics["cpu"])
        memory_usage.append(metrics["memory"])
        timestamps.append(datetime.now().strftime("%H:%M:%S"))

        ax.clear()
        ax.plot(timestamps, cpu_usage, label="CPU Usage (%)", color="r")
        ax.plot(timestamps, memory_usage, label="Memory Usage (%)", color="b")
        ax.set_xlabel("Time")
        ax.set_ylabel("Usage (%)")
        ax.legend()
        plt.xticks(rotation=45)

        plt.pause(1)  # Update every second

        if len(timestamps) > 20:  # Keep last 20 data points
            cpu_usage.pop(0)
            memory_usage.pop(0)
            timestamps.pop(0)


if __name__ == "__main__":
    # To run Locust tests:
    # locust -f authntication/test_api/test.py --host=http://localhost:8000
    
    # To run other tests:
    plot_system_metrics()
    run_comprehensive_test()