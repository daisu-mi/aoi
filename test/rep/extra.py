#!/usr/bin/env python3
"""Counts quoted in the report that agg.py does not print.  Reads the unpacked
records only (tar xJf freebsd.tar.xz; tar xJf linux.tar.xz).

Computes, for every repetition:
 freebsd  three-client scene (c/audit.log): audit records that carry the
          jail's name, and how many of them have the administrator's terminal
          address (10.0.2.2) or 0.0.0.0 in their subject, (1) in the whole
          trail exported for the run and (2) in the interval of the scene
          (the same filter as freebsd-rep.py: t0 <= t <= t1 + 1);
          login scene (a/honey.log, interval of the login): opens and
          executions whose matching key occurs more than once;
          login and service scenes (a/honey.log): lines of the module without
          an address, and how many of them come before the first line with an
          address in the interval;
          service scene (a/honey.log and a/audit.log, interval of the scene):
          executions in the module's log, in the audit trail, and matched by
          (process, argument text), with the keys of freebsd-rep.py;
          three-client scene (c/honey.log, interval of the scene): lines of
          the module, how often two consecutive lines with an address carry
          different addresses, and processes that appear with more than one
          address.
          login scene, rows of the comparison table that the other scripts do
          not print (added for the round-11 revision; PW is the password the
          client script types twice at passwd, "foobar!"):
          ssh.module_terminal (a/honey.log, interval of the login): lines of
          the module by event (tty-in, tty-out, read, write, signal) and the
          number of tty-in lines that contain PW;
          ssh.dtrace_with_module (a/dtrace.log, interval of the login) and
          ssh.dtrace_repeat (b/dtrace.log, interval of the repeat without the
          module): records of the DTrace script by event; "password" is how
          often PW occurs in the tty-in character codes joined in file order,
          "password_each_char_twice" how often it occurs with every character
          twice in succession ("ffoooobbaarr!!"), and "tty_in_all_in_equal_
          pairs" whether the tty-in records, taken two by two in file order,
          are pairs of equal character and process; "write_without_name" is
          the number of write records whose name is "?"; "signals" counts
          the signal records by signal number, and "signals_other_than_the_
          scripted_kill" leaves out the one signal 15;
          ssh.audit_password_records: audit records with the jail's name in
          the interval that contain PW, for a/audit.log and b/audit.log.
 linux    login scene (bt1.log, lines to which the tracer gave an address):
          opens and executions whose matching key occurs more than once.
The matching keys are those of freebsd-rep.py and ../lxc/match.py.
usage: extra.py freebsd|linux"""
import re, sys, os, glob, json, calendar, time, collections
here = os.path.dirname(os.path.abspath(__file__)); which = sys.argv[1]
def base(p): return p.rstrip('/').split('/')[-1]
def norm(b): return 'TTY' if b == 'tty' or re.fullmatch(r'\d+', b) else b
def shared(c): return sum(v for v in c.values() if v > 1)
def fb(d):
    out = {}
    t0, t1 = map(int, open(d + '/c/interval.txt').read().split())
    whole = collections.Counter(); inint = collections.Counter()
    for l in open(d + '/c/audit.log', errors='replace'):
        m = re.match(r'header,\d+,\d+,(.*?),\d+,(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (\w+) +(\d+) (\d+):(\d+):(\d+) (\d+), \+ (\d+) msec,(.*)', l)
        if not m or ',zone,j1' not in l: continue
        s = re.search(r'subject,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,(\d+),(\d+),(\d+),([^,]*)', l)
        t = calendar.timegm((int(m.group(7)), time.strptime(m.group(2), '%b').tm_mon, int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)))) + int(m.group(8)) / 1000
        whole[s.group(4)] += 1
        if t0 <= t <= t1 + 1: inint[s.group(4)] += 1
    out['three.audit_jail_records.whole_trail'] = dict(total=sum(whole.values()), subject=dict(whole))
    out['three.audit_jail_records.interval'] = dict(total=sum(inint.values()), subject=dict(inint))
    t0, t1 = map(int, open(d + '/a/interval-ssh.txt').read().split())
    O = collections.Counter(); X = collections.Counter()
    for l in open(d + '/a/honey.log', errors='replace'):
        f = l.rstrip('\n').split(',', 6)
        if len(f) != 7 or not (t0 <= float(f[0]) <= t1 + 1): continue
        if f[2] in ('open', 'open-failed'):
            O[(int(f[3]), norm(base(re.sub(r' errno=\d+$', '', f[6]).split(' ', 1)[1])), f[2] == 'open')] += 1
        if f[2] == 'exec': X[(int(f[3]), f[6].split(' | ')[1])] += 1
    out['ssh.open_shared_key'] = [shared(O), sum(O.values())]; out['ssh.exec_shared_key'] = [shared(X), sum(X.values())]
    for name, fn in (('ssh', 'interval-ssh.txt'), ('service', 'interval-vuln.txt')):
        t0, t1 = map(int, open(d + '/a/' + fn).read().split())
        H = [f for f in (l.rstrip('\n').split(',', 6) for l in open(d + '/a/honey.log', errors='replace')) if len(f) == 7 and t0 <= float(f[0]) <= t1 + 1]
        lab = [i for i, f in enumerate(H) if f[1] != '-']; un = [i for i, f in enumerate(H) if f[1] == '-']
        out[name + '.module_unlabelled'] = dict(lines=len(H), unlabelled=len(un), before_first_labelled=sum(i < min(lab) for i in un) if lab else len(un))
    HX = collections.Counter((int(f[3]), f[6].split(' | ')[1]) for f in H if f[2] == 'exec'); AX = collections.Counter()
    for l in open(d + '/a/audit.log', errors='replace'):
        m = re.match(r'header,\d+,\d+,(.*?),\d+,(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (\w+) +(\d+) (\d+):(\d+):(\d+) (\d+), \+ (\d+) msec,(.*)', l)
        if not m or ',zone,j1' not in l or not m.group(1).startswith('execve'): continue
        t = calendar.timegm((int(m.group(7)), time.strptime(m.group(2), '%b').tm_mon, int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)))) + int(m.group(8)) / 1000
        if not (t0 <= t <= t1 + 1): continue
        s = re.search(r'subject,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,(\d+),', l); a = re.search(r'exec arg,(.*?)(?:,exec env,|,path,)', m.group(9))
        AX[(int(s.group(1)), a.group(1).replace(',', ' ') if a else '?')] += 1
    out['service.exec'] = [sum(HX.values()), sum(AX.values())]; out['service.exec_match'] = sum((HX & AX).values())
    t0, t1 = map(int, open(d + '/c/interval.txt').read().split())
    H = [f for f in (l.rstrip('\n').split(',', 6) for l in open(d + '/c/honey.log', errors='replace')) if len(f) == 7 and t0 <= float(f[0]) <= t1 + 1]
    A = [(re.split('[:>]', f[1])[0], int(f[3])) for f in H if f[1] != '-']; per = collections.defaultdict(set)
    for a, p in A: per[p].add(a)
    out['three.module_interleave'] = dict(lines=len(H), changes_between_labelled_neighbours=sum(A[i][0] != A[i + 1][0] for i in range(len(A) - 1)),
        processes_with_two_addresses=sum(len(v) > 1 for v in per.values()))
    PW = 'foobar!'; DBL = ''.join(c + c for c in PW)
    t0, t1 = map(int, open(d + '/a/interval-ssh.txt').read().split())
    H = [f for f in (l.rstrip('\n').split(',', 6) for l in open(d + '/a/honey.log', errors='replace')) if len(f) == 7 and t0 <= float(f[0]) <= t1 + 1]
    ev = collections.Counter(f[2] for f in H)
    out['ssh.module_terminal'] = {'tty-in': ev['tty-in'], 'tty-out': ev['tty-out'], 'read': ev['read'], 'write': ev['write'], 'signal': ev['signal'],
        'tty-in_lines_with_password': sum(PW in f[6] for f in H if f[2] == 'tty-in')}
    for name, sub, iv in (('ssh.dtrace_with_module', 'a', 'interval-ssh.txt'), ('ssh.dtrace_repeat', 'b', 'interval.txt')):
        t0, t1 = map(int, open('%s/%s/%s' % (d, sub, iv)).read().split())
        D = [f for f in (l.rstrip('\n').split(',', 5) for l in open('%s/%s/dtrace.log' % (d, sub), errors='replace')) if len(f) == 6 and f[0].isdigit() and t0 <= int(f[0]) / 1e6 <= t1 + 1]
        ev = collections.Counter(f[1] for f in D); tin = [(f[2], int(f[5])) for f in D if f[1] == 'tty-in']; text = ''.join(chr(c) for _, c in tin)
        sig = collections.Counter(f[5].split(' ')[0] for f in D if f[1] == 'signal')
        out[name] = {'tty-in': ev['tty-in'], 'password': text.count(PW), 'password_each_char_twice': text.count(DBL),
            'tty_in_all_in_equal_pairs': len(tin) % 2 == 0 and all(tin[i] == tin[i + 1] for i in range(0, len(tin) - 1, 2)),
            'tty-out': ev['tty-out'], 'read': ev['read'], 'write': ev['write'], 'write_without_name': sum(f[5] == '?' for f in D if f[1] == 'write'),
            'read_without_name': sum(f[5] == '?' for f in D if f[1] == 'read'),
            'signals': dict(sorted(sig.items())), 'signals_other_than_the_scripted_kill': sum(v for k, v in sig.items() if k != '15')}
    ap = {}
    for sub, iv in (('a', 'interval-ssh.txt'), ('b', 'interval.txt')):
        t0, t1 = map(int, open('%s/%s/%s' % (d, sub, iv)).read().split()); n = 0
        for l in open('%s/%s/audit.log' % (d, sub), errors='replace'):
            m = re.match(r'header,\d+,\d+,(.*?),\d+,(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (\w+) +(\d+) (\d+):(\d+):(\d+) (\d+), \+ (\d+) msec,(.*)', l)
            if not m or ',zone,j1' not in l: continue
            t = calendar.timegm((int(m.group(7)), time.strptime(m.group(2), '%b').tm_mon, int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)))) + int(m.group(8)) / 1000
            if t0 <= t <= t1 + 1 and PW in l: n += 1
        ap[sub] = n
    out['ssh.audit_password_records'] = ap
    return out
def lx(d):
    O = collections.Counter(); X = collections.Counter()
    for l in open(d + '/bt1.log', errors='replace'):
        f = l.rstrip('\n').split(',', 6)
        if len(f) < 7 or not f[0].isdigit() or f[1].startswith('0.0.0.0'): continue
        if f[2] in ('open', 'open-failed'): O[(int(f[3]), base(f[6]), f[2] == 'open')] += 1
        if f[2] == 'exec': X[(int(f[3]), f[6].replace('\\x00', ' ').strip())] += 1
    return {'ssh.open_shared_key': [shared(O), sum(O.values())], 'ssh.exec_shared_key': [shared(X), sum(X.values())]}
for d in sorted(glob.glob('%s/%s/[0-9][0-9]' % (here, which))):
    print(which + '/' + os.path.basename(d), json.dumps(fb(d) if which == 'freebsd' else lx(d)))
