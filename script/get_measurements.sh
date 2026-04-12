#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Generate random SSH key
ssh-keygen -t ed25519 -f /tmp/eve_ssh_key -N "" -q

# Add public key to authorized_keys
mkdir -p conf
cp /tmp/eve_ssh_key.pub conf/authorized_keys

# Build system
make clean pkgs live

# Boot system with TPM
make run TPM=y &
QEMU_PID=$!

# Wait for system to boot
sleep 30

SSH_CMD="ssh -i /tmp/eve_ssh_key -p 2222 -o StrictHostKeyChecking=no root@localhost"

# get the current and other partition
CURPART=$($SSH_CMD "eve exec pillar zboot curpart")
OTHERPART=$([ "$CURPART" = "IMGA" ] && echo "IMGB" || echo "IMGA")

# get the current active part tpm logs
$SSH_CMD "cat /sys/kernel/security/tpm0/binary_bios_measurements" > binary_bios_measurements_${CURPART}_active

# set the current partition to updating
$SSH_CMD "eve exec pillar zboot set_partstate ${CURPART} updating && reboot"

# Wait for system to boot
sleep 30

# get the current partition updating tpm logs
$SSH_CMD "cat /sys/kernel/security/tpm0/binary_bios_measurements" > binary_bios_measurements_${CURPART}_updating

# copy rootfs to other partition
$SSH_CMD << 'EOF'
PARTITIONS=$(lsblk -rno NAME,SIZE | awk '$2 ~ /512M/ {print $1}')
ROOTFS_PART=""
OTHER_PART=""
for part in $PARTITIONS; do
    if findmnt /dev/$part | grep -q "/"; then
        ROOTFS_PART=$part
    else
        OTHER_PART=$part
    fi
done

if [ -n "$ROOTFS_PART" ] && [ -n "$OTHER_PART" ]; then
    echo "Copying /dev/$ROOTFS_PART to /dev/$OTHER_PART"
    dd if=/dev/$ROOTFS_PART of=/dev/$OTHER_PART bs=4M
    sync
fi
EOF

# set the other partition to active
$SSH_CMD "eve exec pillar zboot set_partstate ${OTHERPART} active && reboot"

# Wait for system to boot
sleep 30

# get the other part active tpm logs
$SSH_CMD  "cat /sys/kernel/security/tpm0/binary_bios_measurements" > binary_bios_measurements_${OTHERPART}_active

# set the other partition to updating
$SSH_CMD "eve exec pillar zboot set_partstate ${OTHERPART} updating && reboot"

# Wait for system to boot
sleep 30

# get the other part updating tpm logs
$SSH_CMD "cat /sys/kernel/security/tpm0/binary_bios_measurements" > binary_bios_measurements_${OTHERPART}_updating

echo "done"