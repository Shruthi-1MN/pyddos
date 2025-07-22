from flask import Flask, request, jsonify
from collections import defaultdict, deque
import time
import threading
import pytz
from datetime import datetime
import matplotlib.pyplot as plt
from ip2geotools.databases.noncommercial import DbIpCity

print("Initializing defense server...")
app = Flask(__name__)

# Defense Configuration
RATE_LIMITS = {
    'DEFAULT': (10, 5),    # 10 requests per 5 seconds
    'LOGIN': (5, 30),      # 5 login attempts per 30 seconds
    'API': (50, 10)        # 50 API calls per 10 seconds
}

BAN_TIME = 300  # 5 minutes //300
WHITELIST = ['127.0.0.1']  # Trusted IPs

# Attack Detection
request_history = defaultdict(deque)
ip_ban_list = {}
ip_location_cache = {}
attack_log = []

# Visualization Data
timestamps = []
request_counts = []

# Replace:
# from ip2geotools.databases.noncommercial import DbIpCity
# With:
# IP_LOCATIONS = {
#     "192.168.1.1": "Local Network",
#     "8.8.8.8": "Google DNS, US",
#     "235.219.108.157": "example.com, US"
# }

# def get_ip_location(ip):
#     return IP_LOCATIONS.get(ip, "Unknown")

# 403 - client forbidden
# 503 - service unavailable
class IPDefender:
    @staticmethod
    def check_rate_limit(ip, endpoint):
        print(f"Checking rate limit for {ip} on {endpoint}")
        now = time.time()
        print("Current time:", now)
        print(f"Rate limits for RATE_LIMITS: {RATE_LIMITS}")
        # Clear old requests
        while (request_history[ip] and 
               now - request_history[ip][0] > RATE_LIMITS[endpoint][1]):
            print(f"request_history before cleanup for {ip}: {list(request_history[ip])}")
            print(f"now: {now}, oldest request: {request_history[ip][0]}")
            print(f"result now minus :  {now - request_history[ip][0]}")
            print(f"rate limit endpoint [1] at {RATE_LIMITS[endpoint][1]}")
            print(f"Cleaning up old requests for {ip}")
            request_history[ip].popleft()
        print(f"Request history for {ip}: {list(request_history[ip])}")  
        print(f"Rate limits for {endpoint}: {RATE_LIMITS[endpoint]}")

        print(f"ip ban list: {ip_ban_list}")
        # Check if IP is banned
        if ip in ip_ban_list:
            if now < ip_ban_list[ip]:
                return False
            del ip_ban_list[ip]
        print(f"ip ban list after check: {ip_ban_list}")
    
        print(f"Request history after cleanup for {ip}: {list(request_history[ip])}")
        # Enforce rate limit
        if len(request_history[ip]) >= RATE_LIMITS[endpoint][0]:
            ip_ban_list[ip] = now + BAN_TIME
            attack_log.append({
                'ip': ip,
                'time': datetime.now(pytz.utc),
                'endpoint': endpoint,
                'action': 'BANNED'
            })
            return False
        print(f"Request count for {ip}: {len(request_history[ip])}")
        
        request_history[ip].append(now)
        return True
    
    @staticmethod
    def get_ip_location(ip):
        print(f"Fetching location for IP: {ip}")
        print(f"Current cache: {ip_location_cache}")
        if ip not in ip_location_cache:
            try:
                response = DbIpCity.get(ip, api_key='free')
                ip_location_cache[ip] = f"{response.city}, {response.country}"
                print(f"response: {response}")
            except:
                ip_location_cache[ip] = "Unknown"
        return ip_location_cache[ip]

# @app.before_request
# def is_spoofed_ip(request):
#     real_ip = request.remote_addr
#     forwarded_ip = request.headers.get("X-Forwarded-For")
#     return forwarded_ip and (forwarded_ip != real_ip)

# @app.before_request
# def track_ips():
#     # Get real IP even behind proxies
#     client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
#     if ',' in client_ip:  # Handle multiple IPs in X-Forwarded-For
#         client_ip = client_ip.split(',')[0].strip()
    
#     print(f"Request from IP: {client_ip}")
    # Add to your tracking logic

@app.before_request
def firewall():
    print("Firewall check initiated")
    client_ip = request.remote_addr
    endpoint = 'LOGIN' if '/login' in request.path else 'API' if '/api' in request.path else 'DEFAULT'
    
    print(f"Initial Client IP: {client_ip}, Endpoint: {endpoint}")

     # Get real IP even behind proxies
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in client_ip:  # Handle multiple IPs in X-Forwarded-For
            client_ip = client_ip.split(',')[0].strip()
    
    print(f"Request from IP: {client_ip}")
    # Add to your tracking logic
        
    # if client_ip != ip:
    #         print(f"Warning: Mismatched IPs! Request IP: {client_ip}, Expected IP: {ip}")
    #         ip = client_ip 

    if client_ip in WHITELIST:
        return None     

    print(f"Checking rate limit for {client_ip} on {endpoint}")
    if not IPDefender.check_rate_limit(client_ip, endpoint):
        location = IPDefender.get_ip_location(client_ip)
        app.logger.warning(f"Blocked potential attack from {client_ip} ({location})")
        return jsonify({
            "error": "Rate limit exceeded",
            "status": 429
        }), 429
    
    print(f"Rate limit check passed for {client_ip} on {endpoint}")
    # Track for visualization
    timestamps.append(datetime.now())
    request_counts.append(len(request_history[client_ip]))

@app.route('/')
def home():
    print("Accessed home endpoint")
    return "Protected Server"

@app.route('/login', methods=['POST'])
def login():
    print("Accessed login endpoint")
    return "Login Endpoint"

@app.route('/api/data')
def api_data():
    print("Accessed API data endpoint")
    return jsonify({"data": "sensitive information"})

def monitor_traffic():
    print("Starting real-time traffic monitoring...")
    """Real-time monitoring thread"""
    while True:
        time.sleep(5)
        current_time = datetime.now().strftime("%H:%M:%S")
        total_reqs = sum(len(v) for v in request_history.values())
        print(f"\n[{current_time}] Traffic Report:")
        print(f"Active IPs: {len(request_history)}")
        print(f"Total Requests: {total_reqs}")
        print(f"Banned IPs: {len(ip_ban_list)}")
        
        if attack_log:
            print("\nRecent Attacks:")
            for log in attack_log[-3:]:
                print(f"{log['time']} - {log['ip']} - {log['endpoint']}")

def visualize_traffic():
    """Generate traffic visualization"""
    plt.figure(figsize=(10, 5))
    plt.plot(timestamps, request_counts, 'b-')
    plt.title('Request Traffic Pattern')
    plt.xlabel('Time')
    plt.ylabel('Requests per IP')
    plt.grid()
    plt.savefig('traffic_pattern.png')
    print("Saved traffic visualization to traffic_pattern.png")

if __name__ == '__main__':
    # Start monitoring thread
    threading.Thread(target=monitor_traffic, daemon=True).start()
    
    # Start Flask app
    app.run(port=5000)
    
    # On shutdown, generate report
    visualize_traffic()