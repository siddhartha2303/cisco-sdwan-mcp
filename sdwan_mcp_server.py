from fastmcp import FastMCP
import requests
import urllib3
import json
import os
import sys
import argparse
import logging
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration from environment variables
VMANAGE_IP = os.getenv("VMANAGE_IP")
USERNAME = os.getenv("VMANAGE_USERNAME")
PASSWORD = os.getenv("VMANAGE_PASSWORD")
BASE_URL = f"https://{VMANAGE_IP}" if VMANAGE_IP else None

# Initialize MCP Server
mcp = FastMCP("Cisco SD-WAN MCP Server", website_url="https://web.techmaker.in/")

class VManageClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.logged_in = False

    def login(self):
        if not all([VMANAGE_IP, USERNAME, PASSWORD]):
            raise Exception("Missing credentials. Please set VMANAGE_IP, VMANAGE_USERNAME, and VMANAGE_PASSWORD environment variables.")
        
        print(f"Logging in to {BASE_URL}...")
        try:
            # 1. Auth
            login_url = f"{BASE_URL}/j_security_check"
            payload = {'j_username': USERNAME, 'j_password': PASSWORD}
            resp = self.session.post(login_url, data=payload, timeout=10)
            
            if 'JSESSIONID' not in self.session.cookies:
                raise Exception(f"Login failed: JSESSIONID not returned. Status: {resp.status_code}")

            # 2. Token
            token_url = f"{BASE_URL}/dataservice/client/token"
            token_resp = self.session.get(token_url, timeout=10)
            if token_resp.status_code == 200:
                self.session.headers.update({'X-XSRF-TOKEN': token_resp.text})
            
            self.logged_in = True
            print("Login successful.")
        except Exception as e:
            print(f"Login error: {e}")
            raise

    def get_data(self, endpoint, params=None):
        if not self.logged_in:
            self.login()
        
        url = f"{BASE_URL}{endpoint}"
        try:
            resp = self.session.get(url, params=params, timeout=15)
            if resp.status_code == 401 or resp.status_code == 403:
                # Session might be expired, retry once
                print("Session expired or invalid, re-logging in...")
                self.login()
                resp = self.session.get(url, params=params, timeout=15)

            if resp.status_code == 200:
                try:
                    return resp.json()
                except json.JSONDecodeError:
                    return resp.text # Handle plain text responses like Config
            else:
                return {"error": f"API Error {resp.status_code}", "body": resp.text}
        except Exception as e:
            return {"error": str(e)}

client = VManageClient()

# --- Tools ---

@mcp.tool()
def get_devices() -> str:
    """Retrieves the full inventory of devices (vManage, vSmart, vEdge, etc.)."""
    data = client.get_data("/dataservice/device")
    if isinstance(data, dict) and 'data' in data:
        return json.dumps(data['data'], indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
def get_wan_edge_inventory() -> str:
    """Retrieves the WAN Edge inventory including Serial Numbers and Chassis IDs."""
    data = client.get_data("/dataservice/system/device/vedges")
    if isinstance(data, dict) and 'data' in data:
        return json.dumps(data['data'], indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
def get_device_templates() -> str:
    """Lists all Device Templates defined in vManage."""
    data = client.get_data("/dataservice/template/device")
    if isinstance(data, dict) and 'data' in data:
        # Simplify output to just name, id, and deviceType
        simplified = [
            {k: v for k, v in item.items() if k in ['templateId', 'templateName', 'deviceType', 'devicesAttached']} 
            for item in data['data']
        ]
        return json.dumps(simplified, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
def get_feature_templates() -> str:
    """Lists all Feature Templates."""
    data = client.get_data("/dataservice/template/feature")
    if isinstance(data, dict) and 'data' in data:
         simplified = [
            {k: v for k, v in item.items() if k in ['templateId', 'templateName', 'deviceType', 'templateType']} 
            for item in data['data']
        ]
         return json.dumps(simplified, indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
def get_centralized_policies() -> str:
    """Lists Centralized Policy definitions (vSmart policies)."""
    data = client.get_data("/dataservice/template/policy/vsmart")
    return json.dumps(data, indent=2)

@mcp.tool()
def get_alarms() -> str:
    """Retrieves active alarms from the fabric."""
    data = client.get_data("/dataservice/alarms")
    return json.dumps(data, indent=2)

@mcp.tool()
def get_events(limit: int = 20) -> str:
    """Retrieves recent events/logs. Use limit to control output size (default 20)."""
    # The API might just dump all, so we can slice the list in Python if API doesn't support limit param easily
    data = client.get_data("/dataservice/event")
    if isinstance(data, dict) and 'data' in data:
        return json.dumps(data['data'][:limit], indent=2)
    return json.dumps(data, indent=2)

@mcp.tool()
def get_interface_stats(device_id: str) -> str:
    """Retrieves interface statistics for a specific device. Requires device_id (system-ip)."""
    data = client.get_data("/dataservice/statistics/interface", params={'deviceId': device_id})
    return json.dumps(data, indent=2)

@mcp.tool()
def get_bfd_sessions(device_id: str) -> str:
    """Retrieves BFD sessions for a device. Requires device_id."""
    data = client.get_data(f"/dataservice/device/bfd/sessions?deviceId={device_id}")
    return json.dumps(data, indent=2)

@mcp.tool()
def get_omp_routes(device_id: str, type: str = "received") -> str:
    """Retrieves OMP routes for a device. Type can be 'received' or 'advertised' (default 'received')."""
    # Endpoint structure: /dataservice/device/omp/routes/received or .../advertised
    endpoint = f"/dataservice/device/omp/routes/{type}?deviceId={device_id}"
    data = client.get_data(endpoint)
    return json.dumps(data, indent=2)

@mcp.tool()
def get_control_connections(device_id: str) -> str:
    """Retrieves control connections (DTLS/TLS) for a device."""
    data = client.get_data(f"/dataservice/device/control/connections?deviceId={device_id}")
    return json.dumps(data, indent=2)

@mcp.tool()
def get_running_config(device_id: str) -> str:
    """Retrieves the full running configuration of a device."""
    data = client.get_data(f"/dataservice/device/config?deviceId={device_id}")
    # This usually returns raw text, not JSON
    return str(data)

import sys
import argparse

# ... (Previous code)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cisco SD-WAN MCP Server")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse", "streamable-http"], help="Transport mode")
    parser.add_argument("--host", default="0.0.0.0", help="Host for HTTP/SSE")
    parser.add_argument("--port", type=int, default=8000, help="Port for HTTP/SSE")
    
    args = parser.parse_args()

    # Force stdout to utf-8 to avoid encoding errors with the banner on Windows
    sys.stdout.reconfigure(encoding='utf-8')

    transport_str = args.transport.upper()
    server_url = f"http://{args.host}:{args.port}/sse" if args.transport == "sse" else "N/A (Stdio)"

    print("┌──────────────────────────────────────────────────────────────────────────────┐")
    print("│                                                                              │")
    print("│  ████████╗███████╗ ██████╗██╗  ██╗███╗   ███╗ █████╗ ██╗  ██╗███████╗██████╗   │")
    print("│  ╚══██╔══╝██╔════╝██╔════╝██║  ██║████╗ ████║██╔══██╗██║ ██╔╝██╔════╝██╔══██╗  │")
    print("│     ██║   █████╗  ██║     ███████║██╔████╔██║███████║█████╔╝ █████╗  ██████╔╝  │")
    print("│     ██║   ██╔══╝  ██║     ██╔══██║██║╚██╔╝██║██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗  │")
    print("│     ██║   ███████╗╚██████╗██║  ██║██║ ╚═╝ ██║██║  ██║██║  ██╗███████╗██║  ██║  │")
    print("│     ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  │")
    print("│                                                                              │")
    print(f"│    Name: Cisco SD-WAN MCP Server                                             │")
    print(f"│    Website: https://web.techmaker.in/                                        │")
    print(f"│    📦 Transport:  {transport_str:<58} │")
    if args.transport == "sse":
        print(f"│    🔗 Server URL: {server_url:<58} │")
    print("│                                                                              │")
    print("└──────────────────────────────────────────────────────────────────────────────┘")

    # Run the server
    try:
        # Suppress uvicorn error logging to avoid messy shutdown tracebacks
        for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.CRITICAL)
            logger.propagate = False
        
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            # Note: If show_banner is not supported in your version, it will fallback to default
            try:
                mcp.run(transport=args.transport, host=args.host, port=args.port, show_banner=False)
            except TypeError:
                mcp.run(transport=args.transport, host=args.host, port=args.port)
    except KeyboardInterrupt:
        # Explicitly handle Ctrl+C if caught directly
        print("\n⚠️  Server stopped by user. Exiting gracefully...")
        sys.exit(0)
    except BaseException:
        # Catch-all for any other shutdown noise (SystemExit, async cancellation errors, etc.)
        # We suppress the traceback here to keep the CLI clean
        print("\n⚠️  Server stopped. Exiting...")
        sys.exit(0)
