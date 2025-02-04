import requests
import concurrent.futures

# API endpoint
url = "http://127.0.0.1:8000/login"

# Login data
data = {
    "user_name": "mpm",
    "password": "123456"
}

# Function to send a request
def send_request(i):
    response = requests.post(url, data=data)
    print(f"Request {i}: Status {response.status_code}")
    return response.status_code

# Use multithreading to send 1,000 requests
def hit_api_concurrently():
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:  # 50 parallel requests
        results = list(executor.map(send_request, range(1, 200)))

    print("\nCompleted 1,000 API hits.")

# Run the function
if __name__ == "__main__":
    hit_api_concurrently()
