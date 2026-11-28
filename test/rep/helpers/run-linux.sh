#!/bin/sh
# 比較用の Ubuntu 26.04 の仮想マシン。ssh は 127.0.0.1:2223、試験の線は 10.99.0.6
cd "$(dirname "$0")"
exec sg kvm -c "qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 2G \
 -drive file=linux.qcow2,if=virtio -cdrom cidata-linux.iso \
 -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2223-:22 -device virtio-net-pci,netdev=n0,mac=52:54:00:a0:d0:16 \
 -netdev tap,id=n1,ifname=aodtap1,script=no,downscript=no -device virtio-net-pci,netdev=n1,mac=52:54:00:a0:d0:06 \
 -display none -serial file:linux-console.log -monitor unix:linux-mon.sock,server,nowait \
 -pidfile linux.pid -daemonize"
