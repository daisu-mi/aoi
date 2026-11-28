#!/bin/sh
# What root inside a jail can see and do.  The jail has its own network stack,
# its own device file system with the standard jail rules (ruleset 4), and the
# host's files mounted read-only.  The recorder (honey.ko, log on vtbd1) and
# the fingerprinting module (aod.ko) are loaded on the host.
# Runs as root inside the FreeBSD test machine.
r(){ echo; echo "# $*"; sh -c "$*" 2>&1; echo "[exit $?]"; }
j(){ echo; echo "jail# $*"; jexec jt sh -c "$*" 2>&1; echo "[exit $?]"; }
kldstat -q -m aod || kldload /root/aod/aod.ko
kenv security.mac.honey.logdev=vtbd1 >/dev/null; kenv security.mac.honey.jailonly=1 >/dev/null
kldload /root/honey/honey.ko
mkdir -p /jroot; mount -t nullfs -o ro / /jroot
ifconfig epair9 create >/dev/null
jail -c name=jt path=/jroot mount.devfs devfs_ruleset=4 vnet vnet.interface=epair9b host.hostname=jt persist
jexec jt ifconfig lo0 inet 127.0.0.1/8 up
echo "== setup (host)"
r "jls -j jt jid name path vnet devfs_ruleset"; r "kldstat | grep -e honey -e aod"; r "sysctl kern.securelevel"
r "jexec jt sysctl net.inet.tcp.emu_kind=8; jexec jt sysctl net.inet.tcp.emu_lock=1"

echo; echo "== inside the jail, as root"
j "id -u; sysctl -n security.jail.jailed"
j "ls /dev | wc -l; ls /dev | tr '\n' ' '"
j "ls -l /dev/vtbd1 /dev/mem /dev/kmem"
j "mknod /tmp/fake c 0 0x42"
j "mount -t devfs devfs /mnt"
j "devfs rule -s 4 add path 'vtbd*' unhide; devfs -m /dev rule apply path 'vtbd1' unhide"
j "ps ax | grep -c '\[honey\]'; ps ax | wc -l"
j "dmesg | tail -3"
j "kldstat | grep -e honey -e aod"
j "kldunload honey"; j "kldunload aod"; j "kldload nullfs"
j "sysctl security.mac.honey | cut -c1-70"
j "sysctl security.mac.honey.enabled=0"; j "sysctl security.mac.honey.jailonly=0"
j "sysctl net.inet.tcp.emu_kind net.inet.tcp.emu_lock"
j "sysctl net.inet.tcp.emu_kind=0"; j "sysctl net.inet.tcp.emu_lock=0"
j "sysctl net.inet.ip.ttl; sysctl net.inet.ip.ttl=65; sysctl net.inet.ip.ttl=64"
j "sysctl net.inet.tcp.rfc1323"; j "sysctl net.inet.tcp.rfc1323=0; sysctl net.inet.tcp.rfc1323=1"
j "sysctl kern.disks"
j "sysctl kern.securelevel"

echo; echo "== after the attempts (host)"
r "kldstat | grep -e honey -e aod"; r "sysctl security.mac.honey.enabled security.mac.honey.jailonly security.mac.honey.logged security.mac.honey.logerr"
r "jexec jt sysctl -n net.inet.tcp.emu_kind"
r "sh /root/honey/honeydump.sh /dev/vtbd1 | grep -c kldunload"
jail -r jt; ifconfig epair9a destroy; umount /jroot/dev 2>/dev/null; umount /jroot
kldunload honey; kenv -u security.mac.honey.logdev; kenv -u security.mac.honey.jailonly
r "jls | wc -l; mount | grep -c jroot; kldstat | grep -c honey"
