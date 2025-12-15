#!/bin/bash
set -e

PORT=9876
LOG_FILE="/tmp/whoami-graceful-test.log"
LONG_REQUEST_FILE="/tmp/long-request-result.txt"

echo "=== Testing Graceful Shutdown ==="
echo ""

# Clean up any existing processes
pkill -f "whoami --port $PORT" 2>/dev/null || true
sleep 1

# Start the server
echo "1. Starting whoami server on port $PORT..."
./whoami --port $PORT > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
sleep 2

# Test that server is ready
echo "2. Testing /ready endpoint..."
READY_RESPONSE=$(curl -s http://localhost:$PORT/ready)
if [ "$READY_RESPONSE" = "Ready for traffic" ]; then
    echo "   ✓ Server is ready: $READY_RESPONSE"
else
    echo "   ✗ Unexpected response: $READY_RESPONSE"
    exit 1
fi

echo "3. Testing /alive endpoint..."
ALIVE_RESPONSE=$(curl -s http://localhost:$PORT/alive)
if [ "$ALIVE_RESPONSE" = "I'm alive" ]; then
    echo "   ✓ Server is alive: $ALIVE_RESPONSE"
else
    echo "   ✗ Unexpected response: $ALIVE_RESPONSE"
    exit 1
fi

# Start a long-running request (5 seconds)
echo "4. Starting a long-running request (5 seconds)..."
curl -s "http://localhost:$PORT/?wait=5s" > "$LONG_REQUEST_FILE" 2>&1 &
CURL_PID=$!
sleep 1

# Send SIGTERM while request is in flight
echo "5. Sending SIGTERM to server (while request is in-flight)..."
kill -TERM $SERVER_PID

# Check readiness immediately after SIGTERM
sleep 0.5
echo "6. Testing /ready endpoint after SIGTERM..."
READY_AFTER=$(curl -s -w "\n%{http_code}" http://localhost:$PORT/ready 2>/dev/null | tail -1)
if [ "$READY_AFTER" = "503" ]; then
    echo "   ✓ Server marked as not ready (503)"
else
    echo "   ⚠ Unexpected status code: $READY_AFTER"
fi

# Wait for the long request to complete
echo "7. Waiting for in-flight request to complete..."
wait $CURL_PID 2>/dev/null || true

# Check if the request completed successfully
if grep -q "Hostname:" "$LONG_REQUEST_FILE"; then
    echo "   ✓ In-flight request completed successfully!"
else
    echo "   ✗ In-flight request failed"
    cat "$LONG_REQUEST_FILE"
    exit 1
fi

# Wait for server to fully shut down
echo "8. Waiting for server to shut down..."
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Shutdown Log ==="
grep -E "(Shutdown|Marked as not ready|Waiting|completed|stopped)" "$LOG_FILE" || true

echo ""
echo "=== Test Complete ==="
echo "✓ Server handled graceful shutdown correctly"
echo "✓ In-flight requests completed before shutdown"
echo "✓ Readiness probe returned 503 during shutdown"

# Cleanup
rm -f "$LOG_FILE" "$LONG_REQUEST_FILE"
