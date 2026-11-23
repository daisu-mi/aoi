#!/usr/bin/env python3
"""Attribute executions to remote addresses from the Linux audit log alone.

An accept event carries the peer address in its SOCKADDR record.  Every record
names its process and its parent by their ids on the host, so descent can be
followed through parent ids.  What cannot be read off directly is which child
of the listening process belongs to which accept: a clone record gives the
child's id in the caller's PID namespace, not on the host.  Heuristic: the
listener's children, in order of their host ids, are paired with the
listener's successful clones in order of audit serial, and each gets the
address of the listener's latest accept before that clone.
usage: join.py audit.log addr-of-client-1 addr-of-client-2 addr-of-client-3
"""
import re, sys, collections
ev=collections.defaultdict(dict)
for l in open(sys.argv[1],errors='replace'):
    m=re.match(r'type=(\w+) msg=audit\((\d+\.\d+):(\d+)\): (.*)',l)
    if m:
        e=ev[int(m.group(3))]; e.setdefault(m.group(1),[]).append(m.group(4))
parent={}; last={}; clones=collections.defaultdict(list); execs=[]; n_acc=n_addr=0
for ser in sorted(ev):                      # audit serial numbers give the order of events
    e=ev[ser]
    if 'SYSCALL' not in e: continue
    s=e['SYSCALL'][0]; g=lambda k:(re.search(r'\b%s=("[^"]*"|\S+)'%k,s) or [None,''])[1].strip('"')
    sc=g('SYSCALL'); pid=int(g('pid')); ok=g('success')=='yes'
    parent.setdefault(pid,int(g('ppid')))
    if sc in('accept','accept4') and ok:
        n_acc+=1
        m=re.search(r'laddr=(?:::ffff:)?([0-9.]+) lport=(\d+)',' '.join(e.get('SOCKADDR',[])))
        if m: last[pid]=m.group(1); n_addr+=1
    elif sc in('clone','clone3','fork','vfork') and ok and pid in last:
        clones[pid].append(last[pid])       # a listener creates a child for its latest connection
    elif sc=='execve' and ok:
        x=e.get('EXECVE',[''])[0]
        execs.append((pid,' '.join((v.strip('"') if v.startswith('"') else bytes.fromhex(v).decode(errors='replace')) for v in re.findall(r'\ba\d+=("[^"]*"|[0-9A-F]+)',x))))
assigned={}
for lst,addrs in clones.items():
    kids=sorted(p for p,pp in parent.items() if pp==lst)
    for k,a in zip(kids,addrs): assigned[k]=a
def addr(p,depth=0):
    if p in assigned: return assigned[p]
    if p not in parent or depth>64: return '-'
    return addr(parent[p],depth+1)
print('successful accept events: %d, with a peer address record: %d; listeners: %d; their children paired: %d; executions: %d'%(n_acc,n_addr,len(clones),len(assigned),len(execs)))
src={'1':sys.argv[2],'2':sys.argv[3],'3':sys.argv[4]}; ok=bad=none=0; got=0
for p,args in execs:
    a=addr(p); got+=a!='-'
    m=re.search(r'attacker(\d) round|/tmp/mark-(\d)-',args)
    if not m: continue
    n=m.group(1) or m.group(2)
    if a=='-': none+=1
    elif a==src[n]: ok+=1
    else: bad+=1
print('marked executions: right address %d, wrong %d, none %d'%(ok,bad,none))
print('executions given an address: %d of %d (correctness checked only for the marked ones)'%(got,len(execs)))
import os
if os.environ.get('MARKS'):      # one line per marked execution: client, round, address given
    for p,args in execs:
        m=re.search(r'attacker(\d) round(\d+)',args)
        if m: print('mark',m.group(1),m.group(2),addr(p))
