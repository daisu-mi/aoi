#!/usr/bin/env python3
"""The scripted "sleep 30 & kill $!" of the login and service scenes: did the
signal find the shell's child before or after it executed sleep?  And, for
the FreeBSD service scene, the opens of the module against those of audit.
Reads the unpacked stored records only; measures nothing.

usage: extra2.py linux | freebsd | freebsd-first-series

For every repetition and scene it prints, per recorder:
  target  the command name the recorder prints for the target of signal 15
  exec    whether the same PID has an execution of "sleep 30" in the scene
  order   'exec-first' or 'signal-first', by the recorder's own time stamps
          ('same-time' if equal), and by the order of lines in its file
  n_exec  executions in the scene (for the login scene: the count of the
          comparison table)
linux:    bt1.log (login) and bt2.log (service), lines with a nonzero
          address, as in test/lxc/match.py.
freebsd:  a/honey.log, a/dtrace.log, a/audit.log in the login interval and
          the service interval; b/dtrace.log, b/audit.log in the interval of
          the repeat without the module.  Intervals and the audit filter
          (",zone,j1", t0 <= t <= t1 + 1) are those of freebsd-rep.py.
          service.open: opens of the module and of audit in the service
          interval and the number matched by the key of freebsd-rep.py
          (PID, last name component normalized, outcome).
"""
import re, sys, json, glob, calendar, time, collections, os
here = os.path.dirname(os.path.abspath(__file__))
def base(p): return p.rstrip('/').split('/')[-1]
def norm(b): return 'TTY' if b == 'tty' or re.fullmatch(r'\d+', b) else b
def order(te, ts, ie, is_):
    return dict(by_time='exec-first' if te < ts else 'signal-first' if te > ts else 'same-time',
                by_line='exec-first' if ie < is_ else 'signal-first')
def judge(sigs, execs):
    """sigs: [(time, line, target pid, target name)], execs: [(time, line, pid)] of sleep 30"""
    R = []
    for ts, is_, pid, name in sigs:
        e = [(t, i) for t, i, p in execs if p == pid]
        r = dict(target=name, exec=bool(e))
        if e: r.update(order(e[0][0], ts, e[0][1], is_))
        R.append(r)
    return R[0] if len(R) == 1 else R
def linux(d):
    out = {}
    for name, fn in (('login', 'bt1.log'), ('service', 'bt2.log')):
        sigs = []; execs = []; n = 0
        for i, l in enumerate(open(d + '/' + fn, errors='replace')):
            f = l.rstrip('\n').split(',', 6)
            if len(f) != 7 or f[1].startswith('0.0.0.0'): continue
            if f[2] == 'exec':
                n += 1
                if f[6].replace('\\x00', ' ').strip() == 'sleep 30': execs.append((int(f[0]), i, int(f[3])))
            if f[2] == 'signal':
                m = re.match(r'15 to (\d+) (\S+)', f[6])
                if m: sigs.append((int(f[0]), i, int(m.group(1)), m.group(2)))
        out[name] = dict(bpftrace=judge(sigs, execs), n_exec=n)
    return out
def atime(m): return calendar.timegm((int(m.group(7)), time.strptime(m.group(2), '%b').tm_mon, int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)))) + int(m.group(8)) / 1000
HDR = r'header,\d+,\d+,(.*?),\d+,(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (\w+) +(\d+) (\d+):(\d+):(\d+) (\d+), \+ (\d+) msec,(.*)'
def f_honey(fn, t0, t1):
    sigs = []; execs = []; n = 0; O = collections.Counter()
    for i, l in enumerate(open(fn, errors='replace')):
        f = l.rstrip('\n').split(',', 6)
        if len(f) != 7 or not (t0 <= float(f[0]) <= t1 + 1): continue
        if f[2] == 'exec':
            n += 1
            if f[6].split(' | ')[1] == 'sleep 30': execs.append((float(f[0]), i, int(f[3])))
        if f[2] == 'signal':
            m = re.match(r'15 to (\d+) (\S+)', f[6])
            if m: sigs.append((float(f[0]), i, int(m.group(1)), m.group(2)))
        if f[2] in ('open', 'open-failed'):
            O[(int(f[3]), norm(base(re.sub(r' errno=\d+$', '', f[6]).split(' ', 1)[1])), f[2] == 'open')] += 1
    return dict(module=judge(sigs, execs), n_exec=n), O
def f_dtrace(fn, t0, t1):
    sigs = []; execs = []; n = 0
    for i, l in enumerate(open(fn, errors='replace')):
        f = l.rstrip('\n').split(',', 5)
        if len(f) != 6 or not f[0].isdigit() or not (t0 <= int(f[0]) / 1e6 <= t1 + 1): continue
        if f[1] == 'exec':
            n += 1
            if f[5] == 'sleep 30': execs.append((int(f[0]), i, int(f[2])))
        if f[1] == 'signal':
            m = re.match(r'15 to (\d+) (\S+)', f[5])
            if m: sigs.append((int(f[0]), i, int(m.group(1)), m.group(2)))
    return dict(dtrace=judge(sigs, execs), n_exec=n)
def f_audit(fn, t0, t1):
    """audit names no command for the target of kill; it gives the target PID
    (token "process") and, for an execution, the PID in the subject."""
    kills = []; execs = []; n = 0; O = collections.Counter()
    for i, l in enumerate(open(fn, errors='replace')):
        m = re.match(HDR, l)
        if not m or ',zone,j1' not in l: continue
        t = atime(m)
        if not (t0 <= t <= t1 + 1): continue
        s = re.search(r'subject,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,(\d+),', l); pid = int(s.group(1))
        ev = m.group(1); rest = m.group(9)
        if ev.startswith('execve'):
            n += 1
            a = re.search(r'exec arg,(.*?)(?:,exec env,|,path,)', rest)
            if a and a.group(1).replace(',', ' ') == 'sleep 30': execs.append((t, i, pid))
        if ev.startswith('kill'):
            p = re.search(r'process(?:_ex)?,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,(\d+),', rest)
            sg = re.search(r'argument,\d+,0x([0-9a-f]+),signal', rest)
            kills.append((t, i, int(p.group(1)) if p else None, sg.group(1) if sg else None))
        if ev.startswith('open'):
            p = re.search(r'path,([^,]*)', rest); O[(pid, norm(base(p.group(1))) if p else '?', 'return,success' in l)] += 1
    R = []
    for t, i, tp, sg in kills:
        e = [(te, ie) for te, ie, p in execs if p == tp]
        r = dict(kill_target_has_exec_of_sleep=bool(e), signal=sg)
        if e: r.update(order(e[0][0], t, e[0][1], i))
        R.append(r)
    return dict(audit=R[0] if len(R) == 1 else R, n_exec=n), O
def freebsd(d):
    out = {}
    for name, fn in (('login', 'interval-ssh.txt'), ('service', 'interval-vuln.txt')):
        t0, t1 = map(int, open(d + '/a/' + fn).read().split())
        h, HO = f_honey(d + '/a/honey.log', t0, t1); a, AO = f_audit(d + '/a/audit.log', t0, t1)
        out[name] = dict(module=h['module'], audit=a['audit'], n_exec=[h['n_exec'], a['n_exec']])
        if name == 'login':
            dt = f_dtrace(d + '/a/dtrace.log', t0, t1); out[name]['dtrace'] = dt['dtrace']; out[name]['n_exec'].append(dt['n_exec'])
        else:
            n = lambda c: sum(c.values())
            out['service.open'] = dict(module=n(HO), audit=n(AO), matched=n(HO & AO),
                module_ok=sum(v for k, v in HO.items() if k[2]), audit_ok=sum(v for k, v in AO.items() if k[2]),
                only_module=sorted(map(str, (HO - AO).elements())), only_audit=sorted(map(str, (AO - HO).elements())))
    if os.path.exists(d + '/b/interval.txt'):
        t0, t1 = map(int, open(d + '/b/interval.txt').read().split())
        dt = f_dtrace(d + '/b/dtrace.log', t0, t1); a, _ = f_audit(d + '/b/audit.log', t0, t1)
        out['repeat'] = dict(dtrace=dt['dtrace'], audit=a['audit'], n_exec=[dt['n_exec'], a['n_exec']])
    return out
kind = sys.argv[1]
for d in sorted(glob.glob(here + '/' + kind + '/[0-9][0-9]')):
    print(kind + '/' + os.path.basename(d), json.dumps(linux(d) if kind == 'linux' else freebsd(d)))
