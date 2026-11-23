#!/usr/bin/env python3
"""Summarise what bpftrace and auditd kept for the two Linux scenarios."""
import re, collections
ta,tb,tc=[float(open(f).read()) for f in ('t1a','t1b','t2b')]
def load(fn):
    R=[]
    for l in open(fn,errors='replace'):
        f=l.rstrip('\n').split(',',6)
        if len(f)==7 and f[0].isdigit():
            R.append(dict(peer=f[1],kind=f[2].replace('vfs_',''),pid=int(f[3]),comm=f[5],d=f[6].replace('\\x00',' ').strip()))
    return R
ev=collections.defaultdict(dict)
for l in open('audit.log',errors='replace'):
    m=re.match(r'type=(\w+) msg=audit\((\d+\.\d+):(\d+)\): (.*)',l)
    if m:
        e=ev[m.group(3)]; e['t']=float(m.group(2)); e.setdefault(m.group(1),[]).append(m.group(4))
def audit(t0,t1,pids):
    A=[]
    for e in ev.values():
        if not(t0<=e['t']<=t1) or 'SYSCALL' not in e: continue
        s=e['SYSCALL'][0]; g=lambda k:(re.search(r'\b%s=("[^"]*"|\S+)'%k,s) or [None,''])[1].strip('"')
        if int(g('pid')) in pids:
            A.append(dict(sc=g('SYSCALL'),ok=g('success')=='yes',auid=g('AUID'),tty=g('tty'),raw=s+' '+' '.join(sum((v for k,v in e.items() if k not in('t','SYSCALL')),[]))))
    return A
for title,fn,t0,t1 in (('1. ssh で入る場面','bt1.log',ta,tb),('2. 穴のあるサーバから入る場面','bt2.log',tb,tc)):
    B=load(fn); S=[r for r in B if not r['peer'].startswith('0.0.0.0')]; pids=set(r['pid'] for r in S)
    k=collections.Counter(r['kind'] for r in S)
    print('\n== '+title)
    print('bpftrace: コンテナ全体 %d 行、接続元つき %d 行 %s'%(len(B),len(S),dict(collections.Counter(r['peer'] for r in S))))
    print('  種類:',dict(k))
    print('  exec:',[r['d'] for r in S if r['kind']=='exec' and re.match(r'(id|uname|cat|sleep|env|/bin/echo|passwd|sh -i)\b',r['d'])])
    print('  signal(子の終了通知 17 番以外):',[r['d'] for r in S if r['kind']=='signal' and not r['d'].startswith('17 ')])
    tin=''.join(bytes(r['d'].split(' ',1)[1],'utf-8').decode('unicode_escape') for r in S if r['kind']=='tty-in' and ' ' in r['d'])
    print('  端末の入力 %d 文字、パスワード foobar! %d 回、端末の出力 %d 行'%(len(tin),tin.count('foobar!'),k['tty-out']))
    print('  jail-mark:',sorted(set((r['kind'],r['comm']) for r in S if 'jail-mark' in r['d'] and not r['kind'].startswith('tty'))),' nonexistent:',sorted(set((r['kind'],r['comm']) for r in S if 'nonexistent' in r['d'] and not r['kind'].startswith('tty'))))
    A=audit(t0,t1,pids); c=collections.Counter((a['sc'],a['ok']) for a in A)
    print('監査: 同じプロセスの記録 %d 件'%len(A))
    print('  exec 成功 %d(bpftrace %d)、open 成功/失敗 %d/%d(bpftrace %d/%d)、kill %d'%(c[('execve',True)],k['exec'],c[('openat',True)],c[('openat',False)],k['open'],k['open-failed'],c[('kill',True)]))
    print('  持ち主(auid)',dict(collections.Counter(a['auid'] for a in A)),' 接続元 10.0.3.1 が出る件数',sum('10.0.3.1' in a['raw'] for a in A))
print('\n監査の記録全体で 10.0.3.1 を含む行:',sum('10.0.3.1' in l for l in open('audit.log',errors='replace')))
