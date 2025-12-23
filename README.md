# Cisco SD-WAN MCP Server

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Status](https://img.shields.io/badge/status-unofficial-orange)
![Platform](https://img.shields.io/badge/platform-cisco%20sd--wan-green)

> **⚠️ Disclaimer:** This project is a **completely personal work** developed independently for educational and open-source purposes. It is **not** an official product of Cisco Systems, Inc. and is not affiliated with, endorsed by, or sponsored by any company. This project relies solely on public documentation and APIs, and contains no proprietary intellectual property or confidential information. There is no conflict of interest with any employer.

---

A robust **Model Context Protocol (MCP)** server for **Cisco SD-WAN (vManage)**. 

This server bridges the gap between AI agents (like Claude, Gemini, or custom LLMs) and your Cisco SD-WAN fabric. It enables secure, read-only access to operational data, allowing agents to perform tasks like inventory audits, health checks, and policy verification without risking configuration drift.

## 📋 Table of Contents

- [About](#about)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Client Integration](#client-integration)
- [Available Tools](#available-tools)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 📖 About

The **Cisco SD-WAN MCP Server** abstracts the complexity of the vManage REST API into a set of clean, semantic tools that AI models can understand. 

**Why use this?**
* 🛡️ **Safety First:** Designed as a Read-Only interface to prevent accidental changes.
* 🧠 **Simplified Context:** Raw API responses are parsed and simplified to save token usage for LLMs.
* 🔌 **Multi-Transport:** Supports standard Stdio (for local apps) and SSE (for remote/web agents).
* 🐳 **Container Ready:** Includes a production-ready Dockerfile for easy deployment.

## 🚀 Features

* **Inventory Management:** List all controllers (vSmart, vBond, vManage) and WAN Edges.
* **Template Analysis:** View attached device and feature templates.
* **Policy Inspection:** Retrieve Centralized and Localized policy definitions.
* **Operational Health:** Check alarms, events, BFD sessions, and control connections.
* **Deep Dives:** Fetch running configurations, interface statistics, and OMP routes.

## 🎥 Demo

<video src="https://github.com/siddhartha2303/cisco-sdwan-mcp/raw/main/src/cisco-sdwan-mcp.mp4" autoplay loop muted width="100%"></video>

## ✅ Prerequisites

* Python 3.10 or higher
* Access to a Cisco vManage instance (on-prem or cloud)
* Credentials with at least `read-only` privileges

## 🛠️ Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/techmaker/cisco-sdwan-mcp.git
    cd cisco-sdwan-mcp
    ```

2. **Install dependencies:**
    ```bash
    pip install fastmcp requests python-dotenv
    ```

## ⚙️ Configuration

The server requires three key pieces of information to connect to your vManage instance.

### Environment Variables

You can set these directly in your shell or pass them to the Docker container.

| Variable | Description | 
| :--- | :--- | 
| `VMANAGE_IP` | IP address or Hostname of your vManage instance. | 
| `VMANAGE_USERNAME` | Username for authentication. | 
| `VMANAGE_PASSWORD` | Password for authentication. | 

### .env File

For local development, create a `.env` file in the project root:

```ini
VMANAGE_IP=ip_address
VMANAGE_USERNAME=username
VMANAGE_PASSWORD=password
```
*(Note: Never commit your `.env` file to version control.)*

## 💻 Usage

### Stdio Mode
Ideal for integration with desktop applications like **Claude Desktop**.

```bash
python sdwan_mcp_server.py --transport stdio
```

### SSE Mode
Best for remote connections, web agents, or debugging.

```bash
python sdwan_mcp_server.py --transport sse --host 0.0.0.0 --port 8000
```
* **Server URL:** `http://localhost:8000/sse`

### Docker

**Build the image:**
```bash
docker build -t cisco-sdwan-mcp .
```

**Run in Stdio Mode:**
```bash
docker run -i --rm \
  -e VMANAGE_IP=ip_address \
  -e VMANAGE_USERNAME=username \
  -e VMANAGE_PASSWORD=password \
  cisco-sdwan-mcp --transport stdio
```

**Run in SSE Mode:**
```bash
docker run -d -p 8000:8000 \
  -e VMANAGE_IP=ip_address \
  -e VMANAGE_USERNAME=username \
  -e VMANAGE_PASSWORD=password \
  cisco-sdwan-mcp --transport sse --host 0.0.0.0
```

## 🔌 Client Integration

### Claude Desktop

Add the following to your config file:
* **MacOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
* **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cisco-sdwan": {
      "command": "python",
      "args": ["/absolute/path/to/sdwan_mcp_server.py", "--transport", "stdio"],
      "env": {
        "VMANAGE_IP": "ip_address",
        "VMANAGE_USERNAME": "username",
        "VMANAGE_PASSWORD": "password"
      }
    }
  }
}
```

### Gemini CLI

Add to your `settings.json`:

```json
{
  "mcpServers": {
    "cisco-sdwan": {
      "command": "python",
      "args": ["sdwan_mcp_server.py", "--transport", "stdio"],
      "env": {
        "VMANAGE_IP": "ip_address",
        "VMANAGE_USERNAME": "username",
        "VMANAGE_PASSWORD": "password"
      }
    }
  }
}
```

## 🛠️ Available Tools

| Tool Name | Description | 
| :--- | :--- | 
| `get_devices` | Full inventory of fabric devices (vManage, vSmart, vBond, vEdge). | 
| `get_wan_edge_inventory` | WAN Edge specific details (Serial, Chassis ID). | 
| `get_device_templates` | List all device templates. | 
| `get_feature_templates` | List all feature templates. | 
| `get_centralized_policies` | List Centralized Policy definitions. | 
| `get_alarms` | Retrieve active system alarms. | 
| `get_events` | Fetch recent audit logs and events. | 
| `get_interface_stats` | Get interface statistics for a specific device. | 
| `get_bfd_sessions` | View BFD session status for a device. | 
| `get_omp_routes` | Inspect OMP routes (received/advertised). | 
| `get_control_connections` | Check DTLS/TLS control connections. | 
| `get_running_config` | Fetch the full running configuration. | 

## ❓ Troubleshooting

**Q: Connection Refused or Timeout**
* Ensure `VMANAGE_IP` is reachable from your machine or container.
* If using Docker on Linux, add `--network host` or ensure routing is correct.

**Q: SSL Certificate Warnings**
* The server suppresses insecure warnings by default (`verify=False`). If you have a valid certificate, you can modify the client code to verify it.

**Q: Login Failed**
* Double-check your username and password.
* Ensure your account has API access privileges.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the **MIT License**.
