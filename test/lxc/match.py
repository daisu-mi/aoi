#!/usr/bin/env python3
"""Record-level match of opens and execs between bpftrace and auditd (same process ids)."""
import re, collections
ta,tb,tc=[float(open(f).read()) for f in ('t1a','t1b','t2b')]
def base(p): return p.rstrip('/').split('/')[-1]
ev=collections.defaultdict(dict)
for l in open('audit.log',errors='replace'):
    m=re.match(r'type=(\w+) msg=audit\((\d+\.\d+):(\d+)\): (.*)',l)
    if m:
        e=ev[m.group(3)]; e['t']=float(m.group(2)); e.setdefault(m.group(1),[]).append(m.group(4))
def dec(v): return v.strip('"') if v.startswith('"') else (bytes.fromhex(v).decode(errors='replace') if re.fullmatch(r'[0-9A-F]+',v) and len(v)%2==0 else v)
for title,fn,t0,t1 in (('ssh','bt1.log',ta,tb),('service','bt2.log',tb,tc)):
    B=collections.Counter(); BX=collections.Counter(); pids=set()
    for l in open(fn,errors='replace'):
        f=l.rstrip('\n').split(',',6)
        if len(f)<7 or not f[0].isdigit() or f[1].startswith('0.0.0.0'): continue
        pid=int(f[3]); pids.add(pid)
        if f[2] in('open','open-failed'): B[(pid,base(f[6]),f[2]=='open')]+=1
        if f[2]=='exec': BX[(pid,f[6].replace('\\x00',' ').strip())]+=1
    A=collections.Counter(); AX=collections.Counter()
    for e in ev.values():
        if not(t0<=e['t']<=t1) or 'SYSCALL' not in e: continue
        s=e['SYSCALL'][0]; g=lambda k:(re.search(r'\b%s=("[^"]*"|\S+)'%k,s) or [None,''])[1].strip('"')
        pid=int(g('pid'))
        if pid not in pids: continue
        if g('SYSCALL')=='openat':
            names=[dec(re.search(r'name=("[^"]*"|\S+)',p).group(1)) for p in e.get('PATH',[]) if re.search(r'name=("[^"]*"|\S+)',p)]
            # the name given by the caller is the last PATH item that is not the parent directory
            cand=[p for p in e.get('PATH',[]) if 'nametype=PARENT' not in p]
            nm=dec(re.search(r'name=("[^"]*"|\S+)',cand[-1]).group(1)) if cand else (names[-1] if names else '?')
            A[(pid,base(nm),g('success')=='yes')]+=1
        if g('SYSCALL')=='execve' and g('success')=='yes':
            x=e.get('EXECVE',[''])[0]; AX[(pid,' '.join(dec(m.group(1)) for m in re.finditer(r'\ba\d+=("[^"]*"|[0-9A-F]+)',x)))]+=1
    print('%s: opens %d / %d, matched one-to-one on (pid, last name component, outcome): %d'%(title,sum(B.values()),sum(A.values()),sum((B&A).values())))
    print('   only bpftrace:',list((B-A).elements())[:5]); print('   only auditd  :',list((A-B).elements())[:5])
    print('%s: execs %d / %d, matched on (pid, argument list): %d'%(title,sum(BX.values()),sum(AX.values()),sum((BX&AX).values())))
    print('   only bpftrace:',list((BX-AX).elements())[:3]); print('   only auditd  :',list((AX-BX).elements())[:3])
