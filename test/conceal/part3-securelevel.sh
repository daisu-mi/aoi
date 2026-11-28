#!/bin/sh
# Secure levels 1 and 2 against root on the host (no jail): can root unload the
# recorder, load another module, write kernel memory or write the log disk,
# and does recording go on?  The secure level cannot be lowered again; the
# machine is restarted after this script.
# Runs as root inside the FreeBSD test machine.
r(){ echo; echo "# $*"; sh -c "$*" 2>&1; echo "[exit $?]"; }
work(){ i=0; while [ $i -lt 100 ]; do /bin/cat /etc/hosts > /dev/null; i=$((i+1)); done; sleep 3; }
lines(){ echo; echo "lines on the log disk: $(sh /root/honey/honeydump.sh /dev/vtbd1 | wc -l | tr -d ' ')   logged=$(sysctl -n security.mac.honey.logged) logerr=$(sysctl -n security.mac.honey.logerr)"; }
# the last sector of the log disk is rewritten with its own content
last=$(( $(diskinfo /dev/vtbd1 | awk '{print $4}') - 1 ))
try(){ r "kldunload honey"; r "kldload nullfs"; r "dd if=/dev/null of=/dev/mem"
	r "dd if=/dev/vtbd1 of=/tmp/last.bin bs=512 skip=$last count=1"
	r "dd if=/tmp/last.bin of=/dev/vtbd1 bs=512 seek=$last count=1"; }
kenv security.mac.honey.logdev=vtbd1 >/dev/null; kldload /root/honey/honey.ko; sleep 1
for lv in -1 1 2; do
	echo; echo "== secure level $lv"
	[ $lv != -1 ] && r "sysctl kern.securelevel=$lv"
	r "sysctl kern.securelevel"; lines
	if [ $lv = -1 ]; then r "dd if=/dev/null of=/dev/mem"; r "dd if=/dev/vtbd1 of=/tmp/last.bin bs=512 skip=$last count=1"; r "dd if=/tmp/last.bin of=/dev/vtbd1 bs=512 seek=$last count=1"
	else try; fi
	work; lines
done
echo; echo "== at level 2: read the log disk, lower the level"
r "dd if=/dev/vtbd1 of=/dev/null bs=512 count=8"; r "sysctl kern.securelevel=0"; r "kldstat | grep honey"
