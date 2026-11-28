#!/bin/sh
# FreeBSD 15.1 の試験用仮想マシン。ssh は 127.0.0.1:2222、試験の線は 10.99.0.2
cd "$(dirname "$0")"
exec sg kvm -c "qemu-system-x86_64 -enable-kvm -cpu host -smp 8 -m 8G \
 -drive file=target.qcow2,if=virtio -cdrom cidata.iso \
 -netdev user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22 -device virtio-net-pci,netdev=n0 \
 -netdev tap,id=n1,ifname=aodtap0,script=no,downscript=no -device virtio-net-pci,netdev=n1,mac=52:54:00:a0:d0:02 \
 -display none -serial file:target-console.log -monitor unix:target-mon.sock,server,nowait \
 -pidfile target.pid -daemonize"
