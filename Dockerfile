# Use official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install dependencies
# fastmcp includes most things, but we need requests specifically if not transitively pulled (it usually is by fastmcp->httpx but let's be safe)
RUN pip install --no-cache-dir fastmcp requests

# Copy the server script
COPY sdwan_mcp_server.py .

# Expose the port for SSE/HTTP modes
EXPOSE 8000

# Default command to run the server (defaulting to stdio, override for sse)
ENTRYPOINT ["python", "sdwan_mcp_server.py"]
