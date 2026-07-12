#!/bin/bash
# Drives a stress run: starts an echo target and socks5d, fires N concurrent
# tunnels through the proxy with stress_client, then tears everything down.
set -u

N="${STRESS_N:-500}"
SOCKS_PORT="${STRESS_SOCKS_PORT:-11500}"
MNG_PORT="${STRESS_MNG_PORT:-18500}"
ECHO_PORT="${STRESS_ECHO_PORT:-18600}"
USER="stressuser"
PASS="stresspass"

BIN_DIR="$(dirname "$0")/../../bin"
ACCESS_LOG="$(mktemp)"

ulimit -n 4096 2>/dev/null

"$BIN_DIR/stress_echo" "$ECHO_PORT" &
ECHO_PID=$!

"$BIN_DIR/socks5d" -u "$USER:$PASS" -p "$SOCKS_PORT" -P "$MNG_PORT" \
    -a stress-admin-secret -m "$((N + 10))" -o "$ACCESS_LOG" &
SERVER_PID=$!

sleep 1

"$BIN_DIR/stress_client" 127.0.0.1 "$SOCKS_PORT" "$USER" "$PASS" \
    127.0.0.1 "$ECHO_PORT" "$N"
STATUS=$?

# Graceful shutdown (drains active sessions); force after a grace period so a
# stuck session can never hang this script or the wider make/CI run.
kill "$SERVER_PID" 2>/dev/null
for _ in $(seq 1 10); do
    kill -0 "$SERVER_PID" 2>/dev/null || break
    sleep 1
done
kill -9 "$SERVER_PID" 2>/dev/null
kill -9 "$ECHO_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null
wait "$ECHO_PID" 2>/dev/null
rm -f "$ACCESS_LOG"

exit "$STATUS"
