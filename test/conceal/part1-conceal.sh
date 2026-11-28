#!/bin/sh
# The four concealment checks of the 2002 thesis, against the FreeBSD module
# with no jail.  Runs as root inside the FreeBSD test machine; the log disk is
# vtbd1.  Every command is printed before its output.
r(){ echo; echo "# $*"; sh -c "$*" 2>&1; echo "[exit $?]"; }
work(){ i=0; while [ $i -lt 400 ]; do /bin/cat /etc/hosts > /dev/null; i=$((i+1)); done; }
load(){ kenv security.mac.honey.logdev=vtbd1 >/dev/null; kenv security.mac.honey.rawdirect=$1 >/dev/null
	kldload /root/honey/honey.ko; sleep 1; }
unload(){ kldunload honey; kenv -u security.mac.honey.logdev; kenv -u security.mac.honey.rawdirect; }
cd /root/honey
echo "== setup"; r "uname -rv | cut -c1-60"; r "sysctl kern.securelevel"

echo; echo "== check 3: write statistics of the log disk, direct path (rawdirect=1)"
load 1; r "sysctl security.mac.honey.logdev security.mac.honey.rawdirect"
r "iostat -Ix vtbd1 | tail -2"; r "sysctl -n security.mac.honey.logged"
work; sleep 3
r "sysctl -n security.mac.honey.logged security.mac.honey.dropped security.mac.honey.logerr"; r "iostat -Ix vtbd1 | tail -2"
r "sh /root/honey/honeydump.sh /dev/vtbd1 | wc -l"

echo; echo "== check 2: the recorder holds no open file"
r "pgrep -S -l honey"
r "procstat -f \$(pgrep -S honey)"
r "fstat | grep -c vtbd1"
r "fstat | grep -i honey | grep -v 'honey.ko' | wc -l"

echo; echo "== check 1: recording causes no network traffic"
# The control connection of this test is ssh on vtnet0, so port 22 is left out
# there; vtnet1 is the closed test link and is captured whole.
tcpdump -n -i vtnet0 -w /tmp/c0.pcap not port 22 2>/tmp/c0.err & tcpdump -n -i vtnet1 -w /tmp/c1.pcap 2>/tmp/c1.err &
sleep 2; a=$(sysctl -n security.mac.honey.logged); work; sleep 3; b=$(sysctl -n security.mac.honey.logged)
pkill tcpdump; sleep 1; echo; echo "records written during the capture: $((b-a))"
r "tcpdump -n -r /tmp/c0.pcap 2>/dev/null | wc -l; tcpdump -n -r /tmp/c0.pcap 2>/dev/null | head -20"
r "tcpdump -n -r /tmp/c1.pcap 2>/dev/null | wc -l; tcpdump -n -r /tmp/c1.pcap 2>/dev/null | head -20"

echo; echo "== check 4: the device file does not exist"
r "ls -l /dev/vtbd1"
r "devfs rule -s 10 add path 'vtbd1*' hide; devfs -m /dev rule -s 10 applyset"
r "ls -l /dev/vtbd1"; r "cat /dev/vtbd1 | head -c 8"; r "ls /dev | grep -c vtbd1"
r "ls -l /dev/vtbd0 | awk '{print \$5, \$6}'"
r "mknod /tmp/fake-vtbd1 c 0x5e; ls -l /tmp/fake-vtbd1; head -c 8 /tmp/fake-vtbd1; rm -f /tmp/fake-vtbd1"
a=$(sysctl -n security.mac.honey.logged); work; sleep 3; b=$(sysctl -n security.mac.honey.logged)
echo; echo "records written while the node is hidden: $((b-a)), errors: $(sysctl -n security.mac.honey.logerr)"
r "devfs -m /dev rule apply path 'vtbd1*' unhide; devfs rule -s 10 delset; ls /dev | grep -c '^vtbd1'"
r "sh /root/honey/honeydump.sh /dev/vtbd1 | wc -l"

echo; echo "== what root on the host still sees (no jail)"
r "kldstat | grep honey"; r "ps ax | grep '\[honey\]' | grep -v grep"; r "sysctl security.mac.honey | cut -c1-70"; r "sysctl kern.disks"
unload

echo; echo "== check 3 again, ordinary path (rawdirect=0), for comparison"
load 0; r "sysctl security.mac.honey.rawdirect"
r "iostat -Ix vtbd1 | tail -2"; a=$(sysctl -n security.mac.honey.logged); work; sleep 3; b=$(sysctl -n security.mac.honey.logged)
echo; echo "records written: $((b-a))"; r "iostat -Ix vtbd1 | tail -2"
unload; r "kldstat | grep -c honey"
