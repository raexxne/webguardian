#!/bin/bash
echo "========================================="
echo "Stopping OWASP ZAP"
echo "========================================="

# Read PID from file
if [ -f /tmp/zap_webguardian.pid ]; then
    ZAP_PID=$(cat /tmp/zap_webguardian.pid)
    echo "Stopping ZAP process (PID: $ZAP_PID)..."
    kill $ZAP_PID 2>/dev/null
    sleep 2
    
    # Force kill if still running
    if ps -p $ZAP_PID > /dev/null; then
        echo "Force killing ZAP..."
        kill -9 $ZAP_PID 2>/dev/null
    fi
    
    rm -f /tmp/zap_webguardian.pid
fi

# Also kill any other ZAP processes
pkill -f zaproxy 2>/dev/null

# Clean up home directory
if [ -f /tmp/zap_webguardian.home ]; then
    ZAP_HOME=$(cat /tmp/zap_webguardian.home)
    echo "Cleaning up ZAP home: $ZAP_HOME"
    rm -rf "$ZAP_HOME"
    rm -f /tmp/zap_webguardian.home
fi

# Check if ZAP is still running
if curl -s http://127.0.0.1:8080 > /dev/null 2>&1; then
    echo "ZAP is still running on port 8080"
    echo "Freeing port 8080..."
    sudo fuser -k 8080/tcp 2>/dev/null
fi

echo "ZAP stopped successfully"