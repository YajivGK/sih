import requests
from user_agents import parse

def get_ip_info(ip_address, token):
    """Fetch geolocation data for a given IP address."""
    url = f"https://ipinfo.io/{ip_address}?token={token}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        # Extract latitude and longitude if available
        loc = data.get("loc", "")
        latitude, longitude = loc.split(",") if loc else (None, None)
        return {
            "ip_address": data.get("ip", "Unknown"),
            "country": data.get("country", "Unknown"),
            "region": data.get("region", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("org", "Unknown"),
            "latitude": latitude,
            "longitude": longitude,
        }
    else:
        return {"error": f"Failed to fetch IP info: {response.status_code}"}

def parse_user_agent(user_agent_string):
    """Extract browser and device information from a user-agent string."""
    user_agent = parse(user_agent_string)
    return {
        "browser": user_agent.browser.family,
        "browser_version": user_agent.browser.version_string,
        "device_type": user_agent.device.family,
        "os": user_agent.os.family,
        "os_version": user_agent.os.version_string,
    }

def main():
    token = "34f21d6c7845e7"  # Replace with your IPInfo token

    # Input: IP address
    ip_address = input("Enter the IP address: ")

    # Fetch IP geolocation data
    ip_info = get_ip_info(ip_address, token)

    # Output geolocation data
    if "error" in ip_info:
        print(ip_info["error"])
        return

    print("\n--- Geolocation Data ---")
    print(f"IP Address: {ip_info['ip_address']}")
    print(f"Country: {ip_info['country']}")
    print(f"Region: {ip_info['region']}")
    print(f"City: {ip_info['city']}")
    print(f"ISP: {ip_info['isp']}")
    print(f"Latitude: {ip_info['latitude']}")
    print(f"Longitude: {ip_info['longitude']}")

    # Input: User-Agent string
    user_agent_string = input("\nEnter the User-Agent string: ")

    # Parse User-Agent data
    user_agent_info = parse_user_agent(user_agent_string)

    # Output User-Agent data
    print("\n--- Device and Browser Info ---")
    print(f"Browser: {user_agent_info['browser']}")
    print(f"Browser Version: {user_agent_info['browser_version']}")
    print(f"Device Type: {user_agent_info['device_type']}")
    print(f"Operating System: {user_agent_info['os']}")
    print(f"OS Version: {user_agent_info['os_version']}")

if _name_ == "_main_":
    main()