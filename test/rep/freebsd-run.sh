#!/bin/sh
# Repeat the FreeBSD scenes.  usage: freebsd-run.sh first last
# Runs on the prober; results go to freebsd/NN/{a,b,c}.  Paths, keys and
# addresses are those of our test setup (a closed link, 10.99.0.0/24).
#   a: module + audit + DTrace; a login over ssh, then the vulnerable service
#   b: audit + DTrace, jail created with allow.setaudit; a login over ssh
#   c: module + audit with accept and fork; three clients at once
cd "$(dirname "$0")"; V=${VMDIR:?set VMDIR to the directory that holds the ssh helper scripts and the key}; S=$V/ssh-target.sh; J=10.99.0.20; L='. /root/honey/freebsd-lib.sh'
O="-i $V/id_vm -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o IdentityAgent=none -o IdentitiesOnly=yes"
nap(){ python3 -c "import time;time.sleep($1)"; }
now(){ $S 'date +%s'; }
login(){ (nap 4; for c in 'id' 'uname -sr' 'cat /etc/hosts > /tmp/jail-mark' 'cat /nonexistent-file' 'sleep 30 & kill $!' 'env SECRET=xyz /bin/echo hello' 'passwd foo'; do echo "$c"; nap 1; done; echo 'foobar!'; nap 1; echo 'foobar!'; nap 1; echo exit) | ssh $O -tt root@$J > $1 2>&1; echo "ssh exit=$?"; }
get(){ scp -q $O -P 2222 root@127.0.0.1:$1 $2; }
scp -q $O -P 2222 freebsd-lib.sh ../vuln/vuln.sh ../compare/honey.d root@127.0.0.1:/root/honey/
for a in 17 18 19; do sudo -n ip addr add 10.99.0.$a/29 dev aodtap0 2>/dev/null; done
for i in $(seq $1 $2); do
	d=freebsd/$(printf %02d $i); mkdir -p $d/a $d/b $d/c
	{
	# --- a
	$S "$L; audit_on lo,aa,ex,fr,fw,fc,fd,pc cnt,argv,arge; honey_on; net_up; jail_up ''"
	$S "$L; sshd_up; inetd_up; dtrace_up; pgrep -l dtrace | head -1"
	T0=$(now); login $d/a/session.txt; nap 2; T1=$(now); echo "$T0 $T1" > $d/a/interval-ssh.txt
	$S "$L; dtrace_down"
	T2=$(now); python3 ../vuln/attack.py $J 1524 > $d/a/session2.txt 2>&1; echo "attack exit=$?"; nap 2; T3=$(now); echo "$T2 $T3" > $d/a/interval-vuln.txt
	$S "$L; audit_get /tmp/audit.log; cp /var/log/honey.log /tmp/honey.log; echo dropped=\$(sysctl -n security.mac.honey.dropped)"
	get /tmp/audit.log $d/a/; get /tmp/honey.log $d/a/; get /tmp/dtrace.log $d/a/; get /tmp/dtrace.err.kept $d/a/dtrace.err
	$S "$L; jail_down; honey_off; audit_off"
	# --- b
	$S "$L; audit_on lo,aa,ex,fr,fw,fc,fd,pc cnt,argv,arge; jail_up allow.setaudit"
	$S "$L; sshd_up; dtrace_up"
	T0=$(now); login $d/b/session.txt; nap 2; T1=$(now); echo "$T0 $T1" > $d/b/interval.txt
	$S "$L; dtrace_down; audit_get /tmp/audit.log"
	get /tmp/audit.log $d/b/; get /tmp/dtrace.log $d/b/; get /tmp/dtrace.err.kept $d/b/dtrace.err
	$S "$L; jail_down; audit_off"
	# --- c
	$S "$L; audit_on lo,aa,ex,pc,nt cnt,argv; honey_on; jail_up ''"
	$S "$L; inetd_up"
	T0=$(now); python3 ../vuln/multi.py $J 1524 10.99.0.17 10.99.0.18 10.99.0.19; echo "multi exit=$?"; nap 2; T1=$(now); echo "$T0 $T1" > $d/c/interval.txt
	$S "$L; audit_get /tmp/audit.log; cp /var/log/honey.log /tmp/honey.log; echo dropped=\$(sysctl -n security.mac.honey.dropped)"
	get /tmp/audit.log $d/c/; get /tmp/honey.log $d/c/
	$S "$L; jail_down; honey_off; audit_off; net_down"
	} > $d/run.txt 2>&1
	echo "$d: $(grep -h 'exit=\|dropped=\|tracers' $d/run.txt | tr '\n' ' ')"
done
for a in 17 18 19; do sudo -n ip addr del 10.99.0.$a/29 dev aodtap0; done
