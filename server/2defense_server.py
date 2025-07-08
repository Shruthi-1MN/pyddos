from flask import Flask, request, jsonify
from collections import defaultdict, deque
import time
import threading
import pytz
from datetime import datetime
import matplotlib.pyplot as plt
from ip2geotools.databases.noncommercial import DbIpCity

app = Flask(__name__)

# Defense Configuration
RATE_LIMITS = {
    'DEFAULT': (10, 5),    # 10 requests per 5 seconds
    'LOGIN': (5, 30),      # 5 login attempts per 30 seconds
    'API': (50, 10)        # 50 API calls per 10 seconds
}
BAN_TIME = 300  # 5 minutes
WHITELIST = ['127.0.0.5']  # Trusted IPs

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


class IPDefender:
    @staticmethod
    def check_rate_limit(ip, endpoint):
        now = time.time()
        
        # Clear old requests
        while (request_history[ip] and 
               now - request_history[ip][0] > RATE_LIMITS[endpoint][1]):
            request_history[ip].popleft()
            
        # Check if IP is banned
        if ip in ip_ban_list:
            if now < ip_ban_list[ip]:
                return False
            del ip_ban_list[ip]
        
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
        
        request_history[ip].append(now)
        return True
    
    @staticmethod
    def get_ip_location(ip):
        if ip not in ip_location_cache:
            try:
                response = DbIpCity.get(ip, api_key='free')
                ip_location_cache[ip] = f"{response.city}, {response.country}"
            except:
                ip_location_cache[ip] = "Unknown"
        return ip_location_cache[ip]

@app.before_request
def firewall():
    client_ip = request.remote_addr
    endpoint = 'LOGIN' if '/login' in request.path else 'API' if '/api' in request.path else 'DEFAULT'
    
    if client_ip in WHITELIST:
        return None
        
    if not IPDefender.check_rate_limit(client_ip, endpoint):
        location = IPDefender.get_ip_location(client_ip)
        app.logger.warning(f"Blocked potential attack from {client_ip} ({location})")
        return jsonify({
            "error": "Rate limit exceeded",
            "status": 429
        }), 429
    
    # Track for visualization
    timestamps.append(datetime.now())
    request_counts.append(len(request_history[client_ip]))

@app.route('/')
def home():
    return "Protected Server"

@app.route('/login', methods=['POST'])
def login():
    return "Login Endpoint"

@app.route('/api/data')
def api_data():
    return jsonify({"data": "sensitive information"})

def monitor_traffic():
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