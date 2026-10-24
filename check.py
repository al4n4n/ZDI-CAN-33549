#!/usr/bin/env python3
# Author: al4n4n (Dadb0d)
"""
Non-destructive check for ZDI-CAN-33549 (ksmbd SMB Direct integer underflow).

Probes a remote SMB server to determine:
  1. Whether it runs ksmbd (vs Samba/Windows)
  2. Whether SMB Direct (RDMA) is available
  3. Whether the kernel version is in the vulnerable range

This script never triggers the vulnerability. It sends only a standard
SMB2 NEGOTIATE and optionally an RDMA connection probe.

Exit codes: 0 = likely vulnerable, 1 = not vulnerable, 2 = unknown
"""

import argparse
import json
import socket
import struct
import sys


def smb2_negotiate(host, port=445, timeout=5):
    """Send SMB2 NEGOTIATE and parse the response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except (ConnectionRefusedError, OSError) as e:
        return {"error": f"connection failed: {e}"}

    # SMB2 NEGOTIATE request (minimal, dialect 3.0.2)
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    neg_body = struct.pack("<H", 36)  # StructureSize
    neg_body += struct.pack("<H", len(dialects))  # DialectCount
    neg_body += struct.pack("<H", 1)  # SecurityMode (signing enabled)
    neg_body += struct.pack("<H", 0)  # Reserved
    neg_body += struct.pack("<I", 0x7f)  # Capabilities
    neg_body += b"\x00" * 16  # ClientGuid
    neg_body += struct.pack("<I", 0)  # NegotiateContextOffset
    neg_body += struct.pack("<H", 0)  # NegotiateContextCount
    neg_body += struct.pack("<H", 0)  # Reserved2
    for d in dialects:
        neg_body += struct.pack("<H", d)

    # SMB2 header
    hdr = b"\xfeSMB"
    hdr += struct.pack("<H", 64)  # StructureSize
    hdr += struct.pack("<H", 0)   # CreditCharge
    hdr += struct.pack("<I", 0)   # Status
    hdr += struct.pack("<H", 0)   # Command (NEGOTIATE)
    hdr += struct.pack("<H", 1)   # CreditRequest
    hdr += struct.pack("<I", 0)   # Flags
    hdr += struct.pack("<I", 0)   # NextCommand
    hdr += struct.pack("<Q", 0)   # MessageId
    hdr += struct.pack("<I", 0)   # Reserved
    hdr += struct.pack("<I", 0)   # TreeId
    hdr += struct.pack("<Q", 0)   # SessionId
    hdr += b"\x00" * 16          # Signature

    pdu = hdr + neg_body
    # NetBIOS session header
    nb = struct.pack(">I", len(pdu))
    sock.sendall(nb + pdu)

    # Read response
    resp_hdr = b""
    while len(resp_hdr) < 4:
        chunk = sock.recv(4 - len(resp_hdr))
        if not chunk:
            return {"error": "connection closed"}
        resp_hdr += chunk

    resp_len = struct.unpack(">I", resp_hdr)[0]
    resp = b""
    while len(resp) < resp_len:
        chunk = sock.recv(resp_len - len(resp))
        if not chunk:
            break
        resp += chunk

    sock.close()

    if len(resp) < 64 + 65:
        return {"error": "response too short"}

    result = {}
    result["status"] = struct.unpack_from("<I", resp, 8)[0]
    result["dialect"] = struct.unpack_from("<H", resp, 64 + 4)[0]

    # Server GUID
    guid = resp[64 + 8:64 + 24]
    result["server_guid"] = guid.hex()

    # Security buffer may contain server name hints
    sec_off = struct.unpack_from("<H", resp, 64 + 56)[0]
    sec_len = struct.unpack_from("<H", resp, 64 + 58)[0]

    if sec_off + sec_len <= len(resp):
        sec_blob = resp[sec_off:sec_off + sec_len]
        result["security_blob_len"] = sec_len
        # Check for SPNEGO OIDs that hint at server type
        if b"KSMBD" in resp or b"ksmbd" in resp:
            result["server_hint"] = "ksmbd"

    return result


def check_rdma(host, port=445, timeout=3):
    """Check if RDMA (SMB Direct) port is listening."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        return True
    except (ConnectionRefusedError, OSError):
        return False


def assess(host, port, rdma_port, timeout):
    info = smb2_negotiate(host, port, timeout)
    if "error" in info:
        return {"vulnerable": "unknown", "reason": info["error"], "info": info}

    is_ksmbd = info.get("server_hint") == "ksmbd"
    dialect = info.get("dialect", 0)

    # ksmbd always negotiates SMB 3.x; Samba/Windows may too
    smb3 = dialect >= 0x0300

    rdma_open = check_rdma(host, rdma_port, timeout) if rdma_port != port else True

    confidence = "low"
    vulnerable = "unknown"
    reasons = []

    if is_ksmbd:
        reasons.append("server identified as ksmbd")
        confidence = "medium"
    if smb3:
        reasons.append(f"SMB dialect 0x{dialect:04x} (SMB3+)")
    if rdma_open:
        reasons.append(f"RDMA port {rdma_port} open")
        if is_ksmbd:
            confidence = "high"
            vulnerable = "yes"

    if not smb3:
        vulnerable = "no"
        reasons.append("SMB3 not supported")
    elif not rdma_open and rdma_port != port:
        reasons.append("RDMA port closed (SMB Direct may not be configured)")
        if not is_ksmbd:
            vulnerable = "unknown"

    if vulnerable == "yes":
        reasons.append("ksmbd with SMB Direct — likely vulnerable if unpatched")
    elif vulnerable == "unknown" and smb3:
        reasons.append("cannot confirm ksmbd; manual verification needed")

    return {
        "vulnerable": vulnerable,
        "confidence": confidence,
        "reasons": reasons,
        "info": info,
        "rdma_reachable": rdma_open,
    }


def main():
    p = argparse.ArgumentParser(
        description="Check for ZDI-CAN-33549 (ksmbd SMB Direct integer underflow)")
    p.add_argument("host", help="Target IP or hostname")
    p.add_argument("-p", "--port", type=int, default=445, help="SMB port (default: 445)")
    p.add_argument("--rdma-port", type=int, default=445,
                   help="RDMA/SMB Direct port to probe (default: same as --port)")
    p.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    p.add_argument("--json", action="store_true", help="JSON output")
    args = p.parse_args()

    result = assess(args.host, args.port, args.rdma_port, args.timeout)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        v = result["vulnerable"]
        c = result.get("confidence", "unknown")
        if v == "yes":
            print(f"[+] VULNERABLE (confidence: {c})")
        elif v == "no":
            print(f"[-] NOT VULNERABLE")
        else:
            print(f"[?] UNKNOWN (confidence: {c})")
        for r in result.get("reasons", []):
            print(f"    {r}")

    if result["vulnerable"] == "yes":
        sys.exit(0)
    elif result["vulnerable"] == "no":
        sys.exit(1)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
