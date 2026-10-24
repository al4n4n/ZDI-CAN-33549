#!/bin/bash
# Author: al4n4n (Dadb0d)
# Lab setup for ZDI-CAN-33549 reproduction.
#
# This script sets up the ksmbd + soft-RoCE environment inside a QEMU VM.
# Run it as root inside the VM after booting a kernel built with:
#   CONFIG_SMB_SERVER=y, CONFIG_SMB_SERVER_SMBDIRECT=y, CONFIG_RDMA_RXE=y, CONFIG_KASAN=y
#
# After setup completes, run the PoC:
#   ./poc.sh <vm-ip> s3guest test
#
# Or run verification:
#   ./verify.sh <vm-ip> s3guest test ./poc/s3rig
set -x

# Ensure we're root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run this as root inside the QEMU VM."
    exit 1
fi

# Create soft-RoCE RDMA device over eth0
rdma link add rxe0 type rxe netdev eth0 2>/dev/null || true
RXE_STATE=$(rdma link show rxe0 2>/dev/null | grep -o 'state [A-Z]*')
echo "[*] RDMA device: rxe0 $RXE_STATE"

# Create share directory and target file
mkdir -p /srv/share
chmod 777 /srv/share
dd if=/dev/zero of=/srv/share/s3-victim.bin bs=1 count=20 2>/dev/null

# Write ksmbd configuration
mkdir -p /etc/ksmbd
cat > /etc/ksmbd/ksmbd.conf << 'KCONF'
[global]
        server string = ksmbd-lab
        netbios name = KSMBD-LAB
        server min protocol = SMB3
        smb direct = yes

[share]
        path = /srv/share
        valid users = s3guest
        read only = no
        writable = yes
KCONF

# Add test user (password: test)
printf "test\ntest\n" | ksmbd.adduser -a s3guest 2>/dev/null || true

# Start ksmbd daemon
ksmbd.mountd -n &
sleep 2

# Build s3rig if source is present
if [ -f /root/poc/s3rig.c ]; then
    echo "[*] Building s3rig..."
    cd /root/poc
    gcc -O2 -Wall -Wno-unused-variable -o s3rig s3rig.c \
        -lrdmacm -libverbs -lpthread -lssl -lcrypto 2>&1
    echo "[*] s3rig built: $(ls -la s3rig 2>/dev/null)"
fi

# Print summary
VM_IP=$(hostname -I | awk '{print $1}')
echo ""
echo "============================================"
echo "  Lab ready."
echo "  ksmbd: running, share=/srv/share"
echo "  RDMA:  rxe0 $RXE_STATE"
echo "  User:  s3guest / test"
echo "  VM IP: $VM_IP"
echo ""
echo "  Run the PoC from inside the VM:"
echo "    ./poc/s3rig -h $VM_IP -u s3guest -p test -m control"
echo "    ./poc/s3rig -h $VM_IP -u s3guest -p test -m dirA"
echo ""
echo "  Or use the wrapper scripts:"
echo "    bash poc.sh $VM_IP"
echo "    bash verify.sh $VM_IP"
echo "============================================"
