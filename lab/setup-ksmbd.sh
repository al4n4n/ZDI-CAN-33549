#!/bin/bash
# Author: al4n4n (Dadb0d)
# In-VM setup for ksmbd + soft-RoCE (run as root inside the QEMU guest)
set -x

# Create soft-RoCE RDMA device
rdma link add rxe0 type rxe netdev eth0 2>/dev/null || true
rdma link show

# Create SMB share directory
mkdir -p /srv/share
chmod 777 /srv/share

# Create the target file s3rig writes to
dd if=/dev/zero of=/srv/share/s3-victim.bin bs=1 count=20 2>/dev/null

# Write ksmbd configuration
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

# Start ksmbd
ksmbd.mountd -n &
sleep 2

echo "ksmbd ready: share=/srv/share user=s3guest rxe0=$(rdma link show rxe0 2>/dev/null | grep -o 'state [A-Z]*')"
