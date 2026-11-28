#!/usr/bin/env python3
"""Login scene on Linux, the single earlier run kept in this directory
(audit.log, bt1.log, t1a, t1b): how many lines of the tracer belong to the
process tree of the SSH connection when the tree is rebuilt from the audit
log alone, and how many of those carry the client's address.

Computes: lines of the tracer in bt1.log; lines from processes in the tree;
of those, lines with an address; lines with an address from processes outside
the tree.  Reads existing records only.

The root is a process whose audit records in the interval name the executable
/usr/sbin/sshd and whose parent has no such record (the server process started
for the connection).  A process belongs to the tree when the chain of parent
identifiers in its audit records leads to the root.  The audit rule of the
scene records execve, openat and kill, so a process that made none of these
is not seen.
usage: tree-ssh.py [directory]   (default: the directory of this script)"""
import re, sys, os, json
d = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
ta, tb = (float(open('%s/%s' % (d, f)).read()) for f in ('t1a', 't1b'))
ev = {}
for l in open(d + '/audit.log', errors='replace'):
    m = re.match(r'type=(\w+) msg=audit\((\d+\.\d+):(\d+)\): (.*)', l)
    if m and ta <= float(m.group(2)) <= tb:
        ev.setdefault(m.group(3), {}).setdefault(m.group(1), []).append(m.group(4))
parent, sshd = {}, set()
for e in ev.values():
    if 'SYSCALL' not in e: continue
    s = e['SYSCALL'][0]
    pid, ppid = int(re.search(r'\bpid=(\d+)', s).group(1)), int(re.search(r'\bppid=(\d+)', s).group(1))
    parent.setdefault(pid, ppid)
    if 'exe="/usr/sbin/sshd"' in s: sshd.add(pid)
roots = sorted(p for p in sshd if parent[p] not in sshd)
def inside(p):
    seen = set()
    while p in parent and p not in seen:
        if p in roots: return True
        seen.add(p); p = parent[p]
    return p in roots
tree = set(p for p in parent if inside(p))
lines = lab = both = lab_out = tree_nolab = 0; nolab = []
for l in open(d + '/bt1.log', errors='replace'):
    f = l.rstrip('\n').split(',', 6)
    if len(f) != 7 or not f[0].isdigit(): continue
    lines += 1
    L, T = not f[1].startswith('0.0.0.0'), int(f[3]) in tree
    lab += L; both += L and T; lab_out += L and not T; tree_nolab += T and not L
    if T and not L: nolab.append(','.join(f[2:]))
print(json.dumps(dict(roots=roots, tree_processes=len(tree), tracer_lines=lines, labelled=lab,
    in_tree=both + tree_nolab, labelled_in_tree=both, labelled_outside_tree=lab_out, tree_without_label=tree_nolab)))
for x in nolab: print('in the tree without an address:', x)
