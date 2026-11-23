#!/bin/sh
# Run inside the FreeBSD test machine.  Three workloads inside a jail, five runs each.
# usage: bench.sh label
label=$1
w1='i=0; while [ $i -lt 3000 ]; do /usr/bin/true; i=$((i+1)); done'
w2='find /usr/src/sys/dev -type f | xargs cat > /dev/null'
w3='cd /root/honey && make clean > /dev/null 2>&1 && make > /dev/null 2>&1'
for w in w1 w2 w3; do
	eval cmd=\$$w
	for run in 1 2 3 4 5; do
		before=$(sysctl -n security.mac.honey.logged 2>/dev/null || echo 0)
		t=$( { /usr/bin/time -p jexec b sh -c "$cmd"; } 2>&1 | awk '/^real/{print $2}')
		sleep 2
		after=$(sysctl -n security.mac.honey.logged 2>/dev/null || echo 0)
		echo "$label $w $run $t $((after - before)) $(sysctl -n security.mac.honey.dropped 2>/dev/null || echo 0)"
	done
done
