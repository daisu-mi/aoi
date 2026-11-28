#!/usr/bin/env python3
"""Service scene on Linux: is the set of lines the tracer labelled the same
as the process tree of the service, rebuilt from the audit log alone?

The root is the process that executed /root/vuln.sh in the interval of the
scene; a process belongs to the tree when the chain of parent identifiers in
its audit records leads to the root.  The audit rule of the scene records
execve, openat and kill, so a process that made none of these is not seen.
usage: tree.py linux/NN"""
import re, sys, json
d = sys.argv[1]
tb, tc = (float(open('%s/%s' % (d, f)).read()) for f in ('t1b', 't2b'))
ev = {}
for l in open(d + '/audit.log', errors='replace'):
    m = re.match(r'type=(\w+) msg=audit\((\d+\.\d+):(\d+)\): (.*)', l)
    if m and tb <= float(m.group(2)) <= tc:
        ev.setdefault(m.group(3), {}).setdefault(m.group(1), []).append(m.group(4))
parent, roots = {}, []
for e in ev.values():
    if 'SYSCALL' not in e: continue
    s = e['SYSCALL'][0]
    pid, ppid = int(re.search(r'\bpid=(\d+)', s).group(1)), int(re.search(r'\bppid=(\d+)', s).group(1))
    parent.setdefault(pid, ppid)
    if 'SYSCALL=execve' in s and any('/root/vuln.sh' in x for x in e.get('EXECVE', [])):
        roots.append(pid)
def inside(p):
    seen = set()
    while p in parent and p not in seen:
        if p in roots: return True
        seen.add(p); p = parent[p]
    return p in roots
tree = set(p for p in parent if inside(p))
lines = lab = both = lab_out = tree_nolab = 0
for l in open(d + '/bt2.log', errors='replace'):
    f = l.rstrip('\n').split(',', 6)
    if len(f) != 7 or not f[0].isdigit(): continue
    lines += 1
    L, T = not f[1].startswith('0.0.0.0'), int(f[3]) in tree
    lab += L; both += L and T; lab_out += L and not T; tree_nolab += T and not L
print(json.dumps(dict(roots=len(roots), tree_processes=len(tree), tracer_lines=lines, labelled=lab,
    in_tree=both + tree_nolab, labelled_in_tree=both, labelled_outside_tree=lab_out, tree_without_label=tree_nolab)))
