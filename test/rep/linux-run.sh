#!/bin/sh
# Repeat the Linux scenes.  usage: linux-run.sh first last
# Runs on the prober; results go to linux/NN/.  Paths and keys are those of our test setup.
cd "$(dirname "$0")"; V=${VMDIR:?set VMDIR to the directory that holds the ssh helper scripts and the key}; C=10.0.3.229
O="-i $V/id_vm -P 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o IdentityAgent=none -o IdentitiesOnly=yes"
for i in $(seq $1 $2); do
	d=linux/$(printf %02d $i); mkdir -p $d
	timeout 500 $V/ssh-linux.sh "sh /tmp/linux-one.sh $C" 2>&1 | grep -v "WARNING\|delete(\|~~" > $d/run.txt
	scp -q $O "ubuntu@127.0.0.1:/tmp/rep/*" $d/
	( cd $d && python3 ../../../lxc/match.py > match.txt 2>&1; python3 ../../../lxc/summary.py > summary.txt 2>&1
	  python3 ../../../lxc/join.py audit-join.log 10.0.3.1 10.0.3.2 10.0.3.3 > join.txt 2>&1
	  python3 ../../../lxc/tally-marks.py m.log 10.0.3.1 10.0.3.2 10.0.3.3 > marks.txt 2>&1 )
	echo "$d: $(tr '\n' ' ' < $d/run.txt)"
done
