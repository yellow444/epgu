#!/bin/sh

# Note: This script requires Windows/.NET tools (certmgr, csptest)
# These are not available in Linux. Consider using OpenSSL alternatives
# or running this setup on Windows before containerization.

# Temporarily skip certificate operations for Linux container
echo "Running in Linux container - certificate installation skipped"
echo "Install certificates on Windows host if needed"

# Create empty envfile to prevent "No such file" errors
touch ./envfile

# Start the Python application
exec python /app/app.py
