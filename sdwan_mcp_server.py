import re
from typing import List, Dict, Any
from fastmcp import FastMCP
import requests
import urllib3
import json
import os
import sys
import yaml
import argparse
import logging
from dotenv import load_dotenv
import jsonschema

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
mcp = FastMCP("Cisco SD-WAN MCP Server")

class VManageClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.logged_in = False

    def login(self):
        if not all([VMANAGE_IP, USERNAME, PASSWORD]):
            raise Exception("Missing credentials. Please set VMANAGE_IP, VMANAGE_USERNAME, and VMANAGE_PASSWORD environment variables.")
        
        print(f"Logging in to {BASE_URL}...", file=sys.stderr)
        try:
            # 1. Auth - Clear cookies first
            self.session.cookies.clear()
            login_url = f"{BASE_URL}/j_security_check"
            payload = {'j_username': USERNAME, 'j_password': PASSWORD}
            resp = self.session.post(login_url, data=payload, timeout=10)
            
            # vManage sometimes returns 200 OK with login page on failure
            if 'JSESSIONID' not in self.session.cookies:
                # Log warning but continue, as some versions might set it differently
                print("Warning: JSESSIONID not found in cookies immediately after login.", file=sys.stderr)

            # 2. Token
            token_url = f"{BASE_URL}/dataservice/client/token"
            token_resp = self.session.get(token_url, timeout=10)
            if token_resp.status_code == 200:
                self.session.headers.update({'X-XSRF-TOKEN': token_resp.text})
            
            self.logged_in = True
            print("Login successful.", file=sys.stderr)
        except Exception as e:
            print(f"Login error: {e}", file=sys.stderr)
            raise

    def get_data(self, endpoint, params=None):
        if not self.logged_in:
            self.login()
        
        url = f"{BASE_URL}{endpoint}"
        try:
            resp = self.session.get(url, params=params, timeout=15)
            
            # Detect redirection to login page
            content_type = resp.headers.get('Content-Type', '')
            if 'text/html' in content_type and '<body' in resp.text:
                print("Detected redirection to login page, re-authenticating...", file=sys.stderr)
                self.login()
                resp = self.session.get(url, params=params, timeout=15)

            if resp.status_code == 401 or resp.status_code == 403:
                # Session might be expired, retry once
                print("Session expired or invalid, re-logging in...", file=sys.stderr)
                self.session.cookies.clear()
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
def get_device_template_details(template_id: str) -> str:
    """Retrieves the full configuration object for a specific Device Template."""
    data = client.get_data(f"/dataservice/template/device/object/{template_id}")
    return json.dumps(data, indent=2)

@mcp.tool()
def get_feature_template_details(template_id: str) -> str:
    """Retrieves the full definition of a Feature Template, including variable names."""
    data = client.get_data(f"/dataservice/template/feature/object/{template_id}")
    return json.dumps(data, indent=2)

@mcp.tool()
def get_template_variables(template_id: str) -> str:
    """Recursively extracts all variable names from a Device Template and its attached Feature Templates, including CLI templates."""
    # 1. Get Device Template
    dt_resp = client.get_data(f"/dataservice/template/device/object/{template_id}")
    if isinstance(dt_resp, dict) and "error" in dt_resp:
        return json.dumps(dt_resp)
    
    if isinstance(dt_resp, str): # Handle error cases returning strings
         try:
             dt_data = json.loads(dt_resp)
         except:
             return json.dumps({"error": "Failed to parse device template response", "raw": dt_resp})
    else:
        dt_data = dt_resp

    variables = set()

    def extract_vars_from_obj(obj):
        """Recursively search for vipVariableName and CLI {{vars}}"""
        if isinstance(obj, dict):
            if 'vipVariableName' in obj:
                variables.add(obj['vipVariableName'])
            
            # Check for CLI config value
            if 'vipType' in obj and obj['vipType'] == 'constant' and 'vipValue' in obj:
                val = obj['vipValue']
                if isinstance(val, str) and '{{' in val:
                    matches = re.findall(r'\{\{(.*?)\}\}', val)
                    for m in matches:
                        variables.add(m.strip())

            for k, v in obj.items():
                extract_vars_from_obj(v)
        elif isinstance(obj, list):
            for item in obj:
                extract_vars_from_obj(item)

    def process_feature_templates(templates):
        """Iterate through linked feature templates"""
        for t in templates:
            t_id = t.get('templateId')
            if t_id:
                # Fetch Feature Template details
                ft_resp = client.get_data(f"/dataservice/template/feature/object/{t_id}")
                if isinstance(ft_resp, dict) and "error" not in ft_resp:
                     ft_data = ft_resp
                elif isinstance(ft_resp, str):
                    try:
                        ft_data = json.loads(ft_resp)
                    except:
                        continue
                else:
                    continue
                
                extract_vars_from_obj(ft_data.get('templateDefinition', {}))
            
            # Recurse for sub-templates
            if 'subTemplates' in t:
                process_feature_templates(t['subTemplates'])

    # Start processing
    process_feature_templates(dt_data.get('generalTemplates', []))
    
    return json.dumps(sorted(list(variables)), indent=2)

@mcp.tool()
def generate_site_config(
    site_id: int,
    routers: List[Dict[str, Any]],
    filename: str = "generated_sites.nac.yaml",
    overwrite: bool = False
) -> str:
    """
    Generates or updates the site configuration file (e.g., sites.nac.yaml) for SD-WAN site deployment.
    
    Args:
        site_id: The unique ID of the site.
        routers: A list of router configurations. Each router dict must contain:
            - chassis_id (str): Serial number/Chassis ID.
            - model (str): Device model (e.g., "C8000V").
            - device_template (str): Name of the device template.
            - all_template_variables (List[str]): List of ALL variables required by the template (fetch this from sdwan_mcp_server).
            - user_variables (Dict[str, Any]): Key-value pairs of variables you want to set explicitly (e.g., {"system_ip": "1.1.1.1"}).
            - policy_variables (Dict[str, Any], optional): Key-value pairs for policy variables.
        filename: The name of the output YAML file. Defaults to "generated_sites.nac.yaml".
        overwrite: If True, replaces the site config if it exists. If False, updates/merges.
    """
    
    data = {}
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            data = {}
    
    # Ensure root structure
    if "sdwan" not in data:
        data["sdwan"] = {}
    if "sites" not in data["sdwan"]:
        data["sdwan"]["sites"] = []
        
    sites = data["sdwan"]["sites"]
    
    # Find existing site or create new
    target_site = None
    for s in sites:
        if s.get("id") == site_id:
            target_site = s
            break
            
    if target_site and overwrite:
        sites.remove(target_site)
        target_site = None
        
    if target_site is None:
        target_site = {"id": site_id, "routers": []}
        sites.append(target_site)
        
    # Process routers
    processed_routers = []
    
    for r in routers:
        chassis_id = r.get("chassis_id")
        model = r.get("model")
        dev_template = r.get("device_template")
        all_vars = r.get("all_template_variables", [])
        user_vars = r.get("user_variables", {})
        policy_vars = r.get("policy_variables", {})
        
        # Logic: Map variables. If not in user_vars, set to TEMPLATE_IGNORE
        final_device_vars = {}
        
        # 1. Fill with TEMPLATE_IGNORE by default for all known template variables
        for var_name in all_vars:
            final_device_vars[var_name] = "TEMPLATE_IGNORE"
            
        # 2. Overwrite with user provided values
        for k, v in user_vars.items():
            # Auto-convert string booleans to actual booleans to prevent YAML quoting
            if isinstance(v, str):
                if v.lower() == 'true':
                    v = True
                elif v.lower() == 'false':
                    v = False
            
            # Handle controller_groups list to string conversion
            if k == 'controller_groups' and isinstance(v, list):
                v = ",".join(map(str, v))

            # Handle ondemand_tunnel_idle_timeout to ensure it's an integer
            if k == 'ondemand_tunnel_idle_timeout':
                try:
                    v = int(v)
                except (ValueError, TypeError):
                    pass

            final_device_vars[k] = v
            
        router_entry = {
            "chassis_id": chassis_id,
            "model": model,
            "device_template": dev_template,
            "device_variables": final_device_vars
        }
        
        if policy_vars:
             router_entry["policy_variables"] = policy_vars
             
        processed_routers.append(router_entry)

    # Update routers in the site object
    # If not overwriting, we might want to append, but usually for a site config generation
    # we replace the router list for that site to ensure it matches intent.
    target_site["routers"] = processed_routers
    
    # Validate against schema.json if it exists
    schema_path = os.path.join(os.path.dirname(__file__), "schema.json")
    if os.path.exists(schema_path):
        try:
            with open(schema_path, 'r') as sf:
                schema = json.load(sf)
            jsonschema.validate(instance=data, schema=schema)
        except jsonschema.ValidationError as e:
            return f"Error: Generated configuration violates schema.json: {e.message}"
        except Exception as e:
            return f"Warning: Could not validate against schema.json: {str(e)}"

    # Custom representer for clean string output (no quotes)
    def str_presenter(dumper, data):
        if len(data.splitlines()) > 1:  # check for multiline string
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='')

    class IndentDumper(yaml.SafeDumper):
        def increase_indent(self, flow=False, indentless=False):
            return super(IndentDumper, self).increase_indent(flow, False)

    yaml.add_representer(str, str_presenter)

    with open(filename, 'w') as f:
        f.write("---\n# SD-WAN Sites\n")
        yaml.dump(data, f, Dumper=IndentDumper, default_flow_style=False, sort_keys=False)
    
    return f"Successfully generated config for Site {site_id} in {filename}"

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cisco SD-WAN MCP Server")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse", "streamable-http"], help="Transport mode")
    parser.add_argument("--host", default="0.0.0.0", help="Host for HTTP/SSE")
    parser.add_argument("--port", type=int, default=8000, help="Port for HTTP/SSE")
    
    args = parser.parse_args()

    # Force stdout to utf-8 to avoid encoding errors with the banner on Windows
    sys.stdout.reconfigure(encoding='utf-8')

    # --- Stdout/Stderr Filter for Clean Exit ---
    class CleanStderr:
        """Filters out noisy asyncio/uvicorn tracebacks during shutdown."""
        def __init__(self, original_stderr):
            self.original = original_stderr
        def write(self, msg):
            if isinstance(msg, bytes):
                msg_str = msg.decode('utf-8', errors='ignore')
            else:
                msg_str = msg
            
            # Expanded noise list
            noise = ["Traceback", "Exception in ASGI", "anyio.WouldBlock", "Task cancelled", 
                     "timeout graceful shutdown", "memory.py", "h11_impl.py", "receive_nowait"]
            
            if any(x in msg_str for x in noise):
                return
            try:
                self.original.write(msg)
            except:
                pass
        def flush(self):
            try:
                self.original.flush()
            except:
                pass
    
    sys.stderr = CleanStderr(sys.stderr)
    # -------------------------------------------

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
        # Configure loggers
        # 1. Allow traffic logs (INFO)
        logging.getLogger("uvicorn.access").setLevel(logging.INFO)
        logging.getLogger("fastmcp").setLevel(logging.INFO)
        
        # 2. Suppress noise and internal errors (CRITICAL)
        for logger_name in ("uvicorn.error", "anyio", "asyncio", "starlette"):
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