#!/usr/bin/env python3
"""Record-level match of opens and execs in run1, where the module, audit and DTrace
recorded the same session at the same time (same process ids)."""
import re, calendar, time, collections
T0,T1=map(int,open('run1/interval.txt').read().split())
def base(p): return p.rstrip('/').split('/')[-1]
def norm(b):
    if b in ('tty',) or re.fullmatch(r'\d+',b): return 'TTY'          # /dev/tty is reported as the pts it resolves to
    return b
H=collections.Counter(); HX=collections.Counter()
for l in open('run1/honey.log',errors='replace'):
    f=l.rstrip('\n').split(',',6)
    if len(f)<7 or not (T0<=float(f[0])<=T1+1): continue
    if f[2] in('open','open-failed'):
        d=re.sub(r' errno=\d+$','',f[6]); H[(int(f[3]),norm(base(d.split(' ',1)[1])),f[2]=='open')]+=1
    if f[2]=='exec': HX[(int(f[3]),f[6].split(' | ')[1])]+=1
D=collections.Counter(); DX=collections.Counter()
for l in open('run1/dtrace.log',errors='replace'):
    f=l.rstrip('\n').split(',',5)
    if len(f)<6 or not f[0].isdigit() or not (T0<=int(f[0])/1e6<=T1+1): continue
    if f[1] in('open','open-failed'): D[(int(f[2]),norm(base(f[5])),f[1]=='open')]+=1
    if f[1]=='exec': DX[(int(f[2]),f[5])]+=1
A=collections.Counter(); AX=collections.Counter()
for l in open('run1/audit.log',errors='replace'):
    m=re.match(r'header,\d+,\d+,(.*?),\d+,(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (\w+) +(\d+) (\d+):(\d+):(\d+) (\d+), \+ (\d+) msec,(.*)',l)
    if not m: continue
    t=calendar.timegm((int(m.group(7)),time.strptime(m.group(2),'%b').tm_mon,int(m.group(3)),int(m.group(4)),int(m.group(5)),int(m.group(6))))+int(m.group(8))/1000
    if not(T0<=t<=T1+1) or ',zone,j1' not in l: continue
    s=re.search(r'subject,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,(\d+),',l); pid=int(s.group(1))
    if m.group(1).startswith('open'):
        p=re.search(r'path,([^,]*)',m.group(9)); A[(pid,norm(base(p.group(1))) if p else '?','return,success' in l)]+=1
    if m.group(1).startswith('execve'):
        a=re.search(r'exec arg,(.*?)(?:,exec env,|,path,)',m.group(9)); AX[(pid,a.group(1).replace(',',' ') if a else '?')]+=1
for name,X,Y in (('module vs DTrace',H,D),('module vs audit',H,A)):
    both=sum((X&Y).values()); print('opens %s: %d in module, %d in other, %d matched one-to-one on (pid, last name component, outcome)'%(name,sum(X.values()),sum(Y.values()),both))
    print('   only module:',list((X-Y).elements())[:6]); print('   only other :',list((Y-X).elements())[:6])
for name,X,Y in (('module vs DTrace',HX,DX),('module vs audit',HX,AX)):
    print('execs %s: %d / %d, %d matched on (pid, argument list)'%(name,sum(X.values()),sum(Y.values()),sum((X&Y).values())))
    print('   only module:',list((X-Y).elements())[:3]); print('   only other :',list((Y-X).elements())[:3])
