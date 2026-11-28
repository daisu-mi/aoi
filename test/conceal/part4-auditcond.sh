#!/bin/sh
# Runs auditcond on the host, in a jail without allow.setaudit and in a jail
# with it, while the host's audit daemon is running.
# Runs as root inside the FreeBSD test machine.
r(){ echo; echo "# $*"; sh -c "$*" 2>&1; echo "[exit $?]"; }
cd /root/honey; cc -o /root/honey/auditcond auditcond.c -lbsm || exit 1
service auditd onestart >/dev/null 2>&1; sleep 1
r "service auditd onestatus"
echo; echo "== host"; r "/root/honey/auditcond"
echo; echo "== jail, default permissions"
jail -c name=ja path=/ host.hostname=ja persist; r "jexec ja /root/honey/auditcond"; jail -r ja
echo; echo "== jail with allow.setaudit"
jail -c name=jb path=/ host.hostname=jb allow.setaudit persist; r "jls -j jb name allow.setaudit"; r "jexec jb /root/honey/auditcond"; jail -r jb
service auditd onestop >/dev/null 2>&1; r "service auditd onestatus; jls | wc -l"
