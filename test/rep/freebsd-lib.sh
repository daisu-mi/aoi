# Helpers for the repeated FreeBSD scenes.  Sourced inside the FreeBSD test machine.
J=10.99.0.20
net_up(){ ifconfig vtnet1 inet 10.99.0.2 -alias; ifconfig bridge0 create >/dev/null; ifconfig bridge0 addm vtnet1 up; ifconfig bridge0 inet 10.99.0.2/30; }
net_down(){ ifconfig bridge0 destroy; ifconfig vtnet1 inet 10.99.0.2/30 up; }
jail_up(){ ifconfig epair1 create >/dev/null; ifconfig bridge0 addm epair1a; ifconfig epair1a up
	jail -c name=j1 path=/ vnet vnet.interface=epair1b host.hostname=j1 $1 persist
	jexec j1 ifconfig lo0 inet 127.0.0.1/8 up; jexec j1 ifconfig epair1b inet $J/29 up; }
jail_down(){ pkill dtrace; pkill inetd; [ -f /var/run/sshd-j1.pid ] && kill $(cat /var/run/sshd-j1.pid); sleep 1
	jail -r j1; ifconfig epair1a destroy; rm -f /var/run/sshd-j1.pid /var/run/inetd-j1.pid /tmp/jail-mark /tmp/mark-* /tmp/dtrace.log /tmp/dtrace.err; }
audit_on(){ [ -f /etc/security/audit_control.before-rep ] || cp -p /etc/security/audit_control /etc/security/audit_control.before-rep
	sed -i "" -e "s/^flags:.*/flags:$1/" -e "s/^naflags:.*/naflags:$1/" -e "s/^policy:.*/policy:$2/" -e "s/^filesz:.*/filesz:50M/" /etc/security/audit_control
	rm -f /var/audit/2026*; service auditd onestart 2>&1 | tail -1; sleep 1; }
audit_off(){ service auditd onestop >/dev/null 2>&1; cp -p /etc/security/audit_control.before-rep /etc/security/audit_control && rm /etc/security/audit_control.before-rep; rm -f /var/audit/2026*; }
audit_get(){ audit -n >/dev/null 2>&1; sleep 1; (cd /var/audit && cat 2026*[0-9] | praudit -l > $1); }
honey_on(){ kenv security.mac.honey.jailonly=1 >/dev/null; : > /var/log/honey.log; kldload /root/honey/honey.ko; }
honey_off(){ kldunload honey; kenv -u security.mac.honey.jailonly; }
sshd_up(){ jexec j1 /usr/sbin/sshd -o ListenAddress=$J -o PidFile=/var/run/sshd-j1.pid; }
inetd_up(){ echo "ingreslock stream tcp nowait root /bin/sh sh /root/honey/vuln.sh" > /tmp/inetd-test.conf
	jexec j1 /usr/sbin/inetd -a $J -p /var/run/inetd-j1.pid /tmp/inetd-test.conf; sleep 1; }
dtrace_up(){ kldstat -q -m dtraceall || kldload dtraceall; nohup dtrace -s /root/honey/honey.d -o /tmp/dtrace.log > /tmp/dtrace.err 2>&1 & sleep 4; echo "tracers running=$(pgrep dtrace | wc -l | tr -d ' ')"; }
# Not -INT: a background job of a non-interactive shell ignores SIGINT.
dtrace_down(){ pkill dtrace; sleep 2; echo "tracers left=$(pgrep dtrace | wc -l | tr -d ' ') drops=$(grep -c -i drop /tmp/dtrace.err)"; cp /tmp/dtrace.err /tmp/dtrace.err.kept; }
