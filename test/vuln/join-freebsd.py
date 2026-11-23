#!/usr/bin/env python3
"""Attribute executions to remote addresses from the FreeBSD audit trail alone
(praudit -l): accept records give the address, fork records the child."""
import re, sys
last={}; peer={}; out=[]; n_acc=n_fork=0
for l in open(sys.argv[1],errors='replace'):
    m=re.match(r'header,\d+,\d+,([^,]*)',l)
    s=re.search(r'subject,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,(\d+),',l)
    if not m or not s or ',zone,j1,' not in l: continue
    ev=m.group(1); pid=int(s.group(1)); ok='return,success' in l
    if ev.startswith('accept') and ok:
        a=re.search(r'socket-inet,\d+,(\d+),([0-9.]+)',l)
        if a: last[pid]=a.group(2); n_acc+=1
    elif re.match(r'(fork|vfork|rfork|pdfork)',ev) and ok:
        c=int(re.search(r'return,success,(\d+)',l).group(1)); n_fork+=1
        if pid in last: peer[c]=last[pid]
        elif pid in peer: peer[c]=peer[pid]
    elif ev.startswith('execve') and ok:
        a=re.search(r'exec arg,(.*?)(?:,exec env,|,path,)',l)
        out.append((peer.get(pid,'-'),a.group(1).replace(',',' ') if a else '?'))
print('accept records with an address: %d, fork records: %d, executions: %d'%(n_acc,n_fork,len(out)))
src={'1':sys.argv[2],'2':sys.argv[3],'3':sys.argv[4]}; ok=bad=none=0
for a,args in out:
    m=re.search(r'attacker(\d) round|/tmp/mark-(\d)-',args)
    if not m: continue
    n=m.group(1) or m.group(2)
    if a=='-': none+=1
    elif a==src[n]: ok+=1
    else: bad+=1
print('marked executions: right address %d, wrong %d, none %d'%(ok,bad,none))
print('executions with an address: %d of %d'%(sum(a!='-' for a,_ in out),len(out)))
