import subprocess
import json
import time
import requests
from user_agents import parse  # Requires `pip install pyyaml ua-parser user-agents`

def capture_http_traffic(interface='ens5', port=80, duration=10):
    command = f"tshark -i {interface} -f 'tcp port {port}' -T fields -e frame.time -e ip.src -e ip.dst -e http.user_agent -e frame.number -a duration:{duration}"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)

    if result.returncode == 0:
        lines = result.stdout.strip().split('\n')
        data = []
        for line in lines:
            fields = line.split('\t')
            if len(fields) < 5:
                continue

            timestamp, ip_src, ip_dst, user_agent, frame_num = fields
            parsed_user_agent = parse(user_agent)
            src_location = get_ip_location(ip_src)

            data.append({
                "timestamp": timestamp,
                "ip_src": ip_src,
                "src_location": src_location,
                "user_agent": user_agent,
                "browser": parsed_user_agent.browser.family,
                "os": parsed_user_agent.os.family,
            })
        return data
    else:
        print(f"Error capturing traffic: {result.stderr}")
        return []

def get_ip_location(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return f"{data.get('city')}, {data.get('country')}"
        else:
            return "Unknown"
    except Exception as e:
        return "Error"

def write_to_json(data, filename='http_traffic.json'):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

if __name__ == '__main__':
    while True:
        traffic_data = capture_http_traffic()
        write_to_json(traffic_data)
        print("Captured traffic data written to http_traffic.json")
        time.sleep(10)  # Capture traffic every 10 seconds
