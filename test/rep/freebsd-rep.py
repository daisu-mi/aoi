#!/usr/bin/env python3
"""Numbers of one FreeBSD repetition (a directory made by freebsd-run.sh), as one JSON line.
usage: freebsd-rep.py freebsd/NN"""
import re, sys, json, calendar, time, collections, subprocess, os
d = sys.argv[1]; SRC = '10.99.0.17'; here = os.path.dirname(os.path.abspath(__file__))
def base(p): return p.rstrip('/').split('/')[-1]
def norm(b): return 'TTY' if b == 'tty' or re.fullmatch(r'\d+', b) else b   # /dev/tty is reported as the pts it resolves to
def honey(fn, t0, t1):
    R = []
    for l in open(fn, errors='replace'):
        f = l.rstrip('\n').split(',', 6)
        if len(f) == 7 and t0 <= float(f[0]) <= t1 + 1: R.append(f)
    return R
def dtrace(fn, t0, t1):
    R = []
    for l in open(fn, errors='replace'):
        f = l.rstrip('\n').split(',', 5)
        if len(f) == 6 and f[0].isdigit() and t0 <= int(f[0]) / 1e6 <= t1 + 1: R.append(f)
    return R
def audit(fn, t0, t1):
    R = []
    for l in open(fn, errors='replace'):
        m = re.match(r'header,\d+,\d+,(.*?),\d+,(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (\w+) +(\d+) (\d+):(\d+):(\d+) (\d+), \+ (\d+) msec,(.*)', l)
        if not m or ',zone,j1' not in l: continue
        t = calendar.timegm((int(m.group(7)), time.strptime(m.group(2), '%b').tm_mon, int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)))) + int(m.group(8)) / 1000
        if not (t0 <= t <= t1 + 1): continue
        s = re.search(r'subject,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,(\d+),(\d+),(\d+),([^,]*)', l)
        R.append(dict(ev=m.group(1), rest=m.group(9), pid=int(s.group(1)), addr=s.group(4), ok='return,success' in l))
    return R
def keys_h(H):
    O = collections.Counter(); X = collections.Counter()
    for f in H:
        if f[2] in ('open', 'open-failed'):
            O[(int(f[3]), norm(base(re.sub(r' errno=\d+$', '', f[6]).split(' ', 1)[1])), f[2] == 'open')] += 1
        if f[2] == 'exec': X[(int(f[3]), f[6].split(' | ')[1])] += 1
    return O, X
def keys_d(D):
    O = collections.Counter(); X = collections.Counter()
    for f in D:
        if f[1] in ('open', 'open-failed'): O[(int(f[2]), norm(base(f[5])), f[1] == 'open')] += 1
        if f[1] == 'exec': X[(int(f[2]), f[5])] += 1
    return O, X
def keys_a(A):
    O = collections.Counter(); X = collections.Counter()
    for r in A:
        if r['ev'].startswith('open'):
            p = re.search(r'path,([^,]*)', r['rest']); O[(r['pid'], norm(base(p.group(1))) if p else '?', r['ok'])] += 1
        if r['ev'].startswith('execve'):
            a = re.search(r'exec arg,(.*?)(?:,exec env,|,path,)', r['rest']); X[(r['pid'], a.group(1).replace(',', ' ') if a else '?')] += 1
    return O, X
def n(c): return sum(c.values())
def labelled(H): return sum(bool(re.match(re.escape(SRC) + '[:>]', f[1])) for f in H)
out = {}
# a: login over ssh
t0, t1 = map(int, open(d + '/a/interval-ssh.txt').read().split())
H = honey(d + '/a/honey.log', t0, t1); D = dtrace(d + '/a/dtrace.log', t0, t1); A = audit(d + '/a/audit.log', t0, t1)
HO, HX = keys_h(H); DO, DX = keys_d(D); AO, AX = keys_a(A)
out['ssh'] = dict(exec=[n(HX), n(AX), n(DX)], exec_match_audit=n(HX & AX), exec_match_dtrace=n(HX & DX),
    open=[n(HO), n(AO), n(DO)], open_ok=[sum(v for k, v in c.items() if k[2]) for c in (HO, AO, DO)],
    open_match_audit=n(HO & AO), open_match_dtrace=n(HO & DO),
    module_lines=len(H), module_labelled=labelled(H), audit_records=len(A), audit_intruder=sum(r['addr'] == SRC for r in A),
    audit_subject=dict(collections.Counter(r['addr'] for r in A)))
# a: the vulnerable service
t0, t1 = map(int, open(d + '/a/interval-vuln.txt').read().split())
H = honey(d + '/a/honey.log', t0, t1); A = audit(d + '/a/audit.log', t0, t1)
out['service'] = dict(module_lines=len(H), module_labelled=labelled(H), audit_records=len(A), audit_intruder=sum(r['addr'] == SRC for r in A))
# b: login over ssh, allow.setaudit, no module
t0, t1 = map(int, open(d + '/b/interval.txt').read().split())
D = dtrace(d + '/b/dtrace.log', t0, t1); A = audit(d + '/b/audit.log', t0, t1)
DO, DX = keys_d(D); AO, AX = keys_a(A)
out['setaudit'] = dict(audit_records=len(A), audit_intruder=sum(r['addr'] == SRC for r in A), audit_subject=dict(collections.Counter(r['addr'] for r in A)),
    exec=[n(DX), n(AX)], exec_match=n(DX & AX), open=[n(DO), n(AO)], open_match=n(DO & AO))
# c: three clients
t0, t1 = map(int, open(d + '/c/interval.txt').read().split())
H = honey(d + '/c/honey.log', t0, t1); src = {'1': '10.99.0.17', '2': '10.99.0.18', '3': '10.99.0.19'}; ok = bad = none = 0
for f in H:
    m = re.search(r'attacker(\d) round|/tmp/mark-(\d)-', f[6])
    if not m: continue
    k = m.group(1) or m.group(2)
    if f[1] == '-': none += 1
    elif re.match(re.escape(src[k]) + '[:>]', f[1]): ok += 1
    else: bad += 1
j = subprocess.run([sys.executable, here + '/../vuln/join-freebsd.py', d + '/c/audit.log', '10.99.0.17', '10.99.0.18', '10.99.0.19'], capture_output=True, text=True).stdout
m = re.search(r'right address (\d+), wrong (\d+), none (\d+)', j); m2 = re.search(r'with an address: (\d+) of (\d+)', j)
out['three'] = dict(module_lines=len(H), module_marks=[ok, bad, none], join_marks=[int(x) for x in m.groups()] if m else None, join_assigned=[int(x) for x in m2.groups()] if m2 else None)
print(json.dumps(out))
