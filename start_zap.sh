#!/bin/bash
# Start ZAP in daemon mode with API enabled

echo "Starting OWASP ZAP daemon..."
echo "====================================="

# Kill existing ZAP processes
pkill -f zaproxy 2>/dev/null
sleep 2

# Start ZAP with API key disabled
zaproxy -daemon \
        -host 127.0.0.1 \
        -port 8080 \
        -config api.disablekey=true \
        -config api.addrs.addr.name=.* \
        -config api.addrs.addr.regex=true \
        -config database.recoverylog=false \
        -config connection.timeoutInSecs=120 \
        -homedir /tmp/zap_webguardian_$(date +%s) &

sleep 3

# Wait for ZAP to start
echo "⏳ Waiting for ZAP to initialize..."
for i in {1..20}; do
    if curl -s http://127.0.0.1:8080 > /dev/null; then
        echo "ZAP is running on http://127.0.0.1:8080"
        echo "API is enabled (key disabled)"
        echo "====================================="
        exit 0
    fi
    sleep 1
done

echo "Failed to start ZAP"
exit 1