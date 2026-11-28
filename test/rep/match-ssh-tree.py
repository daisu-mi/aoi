#!/usr/bin/env python3
"""Login scene on Linux, the ten stored runs: the record-by-record match of
../lxc/match.py with the processes selected from the audit log alone.
Read-only: reads audit.log, bt1.log, t1a and t1b of each run and changes
nothing.  Written after the runs, on 2026-11-27, for the revision of the
report; it is an analysis of the stored records, not part of the harness.

../lxc/match.py compares the processes for which the tracer printed a line
with a nonzero address.  Here the processes are those of the process tree
rebuilt from the audit log, by the two root rules of tree-ssh-root.py:
  "first"  a root is a process whose audit records in the interval name the
           executable /usr/sbin/sshd and whose parent has no such record;
  "exec"   the root is the process with an audited successful execve in the
           interval whose argument list is exactly /usr/sbin/sshd -D -R.
A process belongs to the tree when the chain of parent identifiers in its
audit records of the interval leads to a root.

For each rule the script prints, with the matching keys of ../lxc/match.py
(execution: PID and argument text, successful executions only on the audit
side; open: PID, last component of the name, outcome; each record used once):
  exec        [tracer, auditd]  executions of tree processes in each stream
  exec_match  how many match
  open        [tracer, auditd]  opens of tree processes in each stream
  open_match  how many match
  only_tracer, only_auditd      the opens left over on each side
All lines of the tracer from tree processes are used, with or without an
address.  For comparison, "labelled" gives the same four numbers for the
selection of ../lxc/match.py (the PIDs the tracer labelled).

The audit rule of the scene records execve, openat and kill, so the tree
holds only processes that made one of these calls.
usage: match-ssh-tree.py DIR [DIR ...]      (DIR is linux/NN)"""
import re, sys, json, collections

def base(p): return p.rstrip('/').split('/')[-1]
def dec(v): return v.strip('"') if v.startswith('"') else (bytes.fromhex(v).decode(errors='replace') if re.fullmatch(r'[0-9A-F]+', v) and len(v) % 2 == 0 else v)

def run(d):
    ta, tb = (float(open('%s/%s' % (d, f)).read()) for f in ('t1a', 't1b'))
    ev = collections.defaultdict(dict)
    for l in open(d + '/audit.log', errors='replace'):
        m = re.match(r'type=(\w+) msg=audit\((\d+\.\d+):(\d+)\): (.*)', l)
        if m:
            e = ev[m.group(3)]; e['t'] = float(m.group(2)); e.setdefault(m.group(1), []).append(m.group(4))
    # the trees, as in tree-ssh-root.py
    parent, sshd, execroot = {}, set(), []
    for e in ev.values():
        if not (ta <= e['t'] <= tb) or 'SYSCALL' not in e: continue
        s = e['SYSCALL'][0]
        pid = int(re.search(r'\bpid=(\d+)', s).group(1)); ppid = int(re.search(r'\bppid=(\d+)', s).group(1))
        parent.setdefault(pid, ppid)
        if 'exe="/usr/sbin/sshd"' in s: sshd.add(pid)
        if re.search(r'\bsyscall=59\b', s) and 'success=yes' in s and e.get('EXECVE'):
            args = [a.strip('"') for a in re.findall(r'\ba\d+=("[^"]*"|\S+)', e['EXECVE'][0])]
            if args == ['/usr/sbin/sshd', '-D', '-R']: execroot.append(pid)
    def tree(roots):
        def inside(p):
            seen = set()
            while p in parent and p not in seen:
                if p in roots: return True
                seen.add(p); p = parent[p]
            return p in roots
        return set(p for p in parent if inside(p))
    # the two streams, with the keys of ../lxc/match.py
    T = []
    for l in open(d + '/bt1.log', errors='replace'):
        f = l.rstrip('\n').split(',', 6)
        if len(f) < 7 or not f[0].isdigit(): continue
        T.append((int(f[3]), not f[1].startswith('0.0.0.0'), f[2], f[6]))
    A = []
    for e in ev.values():
        if not (ta <= e['t'] <= tb) or 'SYSCALL' not in e: continue
        s = e['SYSCALL'][0]; g = lambda k: (re.search(r'\b%s=("[^"]*"|\S+)' % k, s) or [None, ''])[1].strip('"')
        pid = int(g('pid'))
        if g('SYSCALL') == 'openat':
            names = [dec(re.search(r'name=("[^"]*"|\S+)', p).group(1)) for p in e.get('PATH', []) if re.search(r'name=("[^"]*"|\S+)', p)]
            cand = [p for p in e.get('PATH', []) if 'nametype=PARENT' not in p]
            nm = dec(re.search(r'name=("[^"]*"|\S+)', cand[-1]).group(1)) if cand else (names[-1] if names else '?')
            A.append((pid, 'open', (pid, base(nm), g('success') == 'yes')))
        if g('SYSCALL') == 'execve' and g('success') == 'yes':
            x = e.get('EXECVE', [''])[0]
            A.append((pid, 'exec', (pid, ' '.join(dec(m.group(1)) for m in re.finditer(r'\ba\d+=("[^"]*"|[0-9A-F]+)', x)))))
    def match(pids):
        B = collections.Counter(); BX = collections.Counter(); AO = collections.Counter(); AX = collections.Counter()
        for pid, lab, evn, det in T:
            if pid not in pids: continue
            if evn in ('open', 'open-failed'): B[(pid, base(det), evn == 'open')] += 1
            if evn == 'exec': BX[(pid, det.replace('\\x00', ' ').strip())] += 1
        for pid, kind, key in A:
            if pid not in pids: continue
            (AO if kind == 'open' else AX)[key] += 1
        n = lambda c: sum(c.values())
        return dict(exec=[n(BX), n(AX)], exec_match=n(BX & AX), open=[n(B), n(AO)], open_match=n(B & AO),
            only_tracer=[list(k) for k in (B - AO).elements()], only_auditd=[list(k) for k in (AO - B).elements()],
            exec_only_tracer=n(BX - AX), exec_only_auditd=n(AX - BX))
    first = set(p for p in sshd if parent[p] not in sshd)
    return dict(first=dict(roots=len(first), **match(tree(first))), exec=dict(roots=len(execroot), **match(tree(set(execroot)))),
        labelled=match(set(pid for pid, lab, evn, det in T if lab)))

for d in sys.argv[1:]:
    print(d, json.dumps(run(d), sort_keys=True))
