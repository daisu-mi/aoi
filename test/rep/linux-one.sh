#!/bin/sh
# One repetition of the three Linux scenes.  Runs inside the Linux test
# machine; the container "hp" must be running with the service on port 1524.
# usage: linux-one.sh container-address
C=$1
start(){ sudo rm -f $1 $2; (sudo BPFTRACE_PERF_RB_PAGES=4096 timeout -s INT 120 bpftrace /tmp/honey.bt -o $1 2>$2) & until sudo grep -q "Attached\|ERROR" $2 2>/dev/null; do sleep 0.5; done; sleep 1; }
stop(){ sleep 2; sudo pkill -INT bpftrace; wait; }
fresh(){ sudo service auditd rotate >/dev/null 2>&1; sudo sh -c "rm -f /var/log/audit/audit.log.*; : > /var/log/audit/audit.log"; sudo auditctl -D >/dev/null; }
keep(){ sudo auditctl -D >/dev/null; sudo sh -c "cat /var/log/audit/audit.log.* /var/log/audit/audit.log 2>/dev/null | tr -d '\000' > $1"; }
rm -rf /tmp/rep; mkdir /tmp/rep; cd /tmp/rep

# scenes 1 and 2: a login over ssh, then the vulnerable service
fresh; sudo auditctl -a always,exit -F arch=b64 -S execve -S openat -S kill -k honey
date +%s.%N > t1a; start /tmp/rep/bt1.log /tmp/rep/bt1.err
sh /tmp/session.sh $C > session1.txt 2>&1; echo "ssh exit=$?"; stop; date +%s.%N > t1b
start /tmp/rep/bt2.log /tmp/rep/bt2.err
python3 /tmp/attack.py $C 1524 > session2.txt 2>&1; echo "attack exit=$?"; stop; date +%s.%N > t2b
keep /tmp/rep/audit.log

# scene 3: three clients at once, with accept and process creation audited
fresh; sudo auditctl -a always,exit -F arch=b64 -S accept,accept4 -S clone,clone3,fork,vfork -S execve -k join
sudo ip addr add 10.0.3.2/24 dev lxcbr0; sudo ip addr add 10.0.3.3/24 dev lxcbr0
start /tmp/rep/m.log /tmp/rep/m.err
python3 /tmp/multi.py $C 1524 10.0.3.1 10.0.3.2 10.0.3.3; echo "multi exit=$?"; stop
sudo ip addr del 10.0.3.2/24 dev lxcbr0; sudo ip addr del 10.0.3.3/24 dev lxcbr0
keep /tmp/rep/audit-join.log
sudo chmod 644 /tmp/rep/*; echo "lost: $(sudo cat bt1.err bt2.err m.err | grep -ci 'lost')"
