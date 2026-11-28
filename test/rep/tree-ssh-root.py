#!/usr/bin/env python3
"""Login scene on Linux, the ten stored runs: the check of ../lxc/tree-ssh.py
with two rules for the root of the process tree, side by side.

Reads existing records only (audit.log, bt1.log, t1a, t1b of each run) and
changes nothing.  For each run it prints one JSON line.

Rule "first" is the rule of ../lxc/tree-ssh.py: a root is a process whose
audit records in the interval name the executable /usr/sbin/sshd and whose
parent has no such record.

Rule "exec" is narrower: a root is a process with an audited successful
execve in the interval whose argument list is exactly
/usr/sbin/sshd -D -R.  The script also prints how many processes have such a
record in the run ("exec_roots"), and every other argument list with which
/usr/sbin/sshd was executed in the interval ("other_sshd_execs").

For each rule: the processes in the tree (a process belongs to the tree when
the chain of parent identifiers in its audit records leads to a root), the
lines of the tracer from tree processes, how many of those carry an address,
how many do not, and the lines with an address from processes outside the
tree.  "outside" lists those lines by event and command, and
"without_label_by_pid" counts the lines without an address by process.

The audit rule of the scene records execve, openat and kill, so a process
that made none of these is not seen by either rule.
usage: tree-ssh-root.py DIR [DIR ...]      (DIR is linux/NN)"""
import re, sys, json, collections

def run(d):
    ta, tb = (float(open('%s/%s' % (d, f)).read()) for f in ('t1a', 't1b'))
    ev = {}
    for l in open(d + '/audit.log', errors='replace'):
        m = re.match(r'type=(\w+) msg=audit\((\d+\.\d+):(\d+)\): (.*)', l)
        if m and ta <= float(m.group(2)) <= tb:
            ev.setdefault(m.group(3), {}).setdefault(m.group(1), []).append(m.group(4))
    parent, sshd, execroot, other = {}, set(), [], []
    for e in ev.values():
        if 'SYSCALL' not in e: continue
        s = e['SYSCALL'][0]
        pid = int(re.search(r'\bpid=(\d+)', s).group(1)); ppid = int(re.search(r'\bppid=(\d+)', s).group(1))
        parent.setdefault(pid, ppid)
        if 'exe="/usr/sbin/sshd"' in s: sshd.add(pid)
        if re.search(r'\bsyscall=59\b', s) and 'success=yes' in s and e.get('EXECVE'):
            args = re.findall(r'\ba\d+=("[^"]*"|\S+)', e['EXECVE'][0])
            args = [a.strip('"') for a in args]
            if args and args[0] == '/usr/sbin/sshd':
                if args == ['/usr/sbin/sshd', '-D', '-R']: execroot.append(pid)
                else: other.append({'pid': pid, 'ppid': ppid, 'args': ' '.join(args)})
    first = sorted(p for p in sshd if parent[p] not in sshd)
    def count(roots):
        def inside(p):
            seen = set()
            while p in parent and p not in seen:
                if p in roots: return True
                seen.add(p); p = parent[p]
            return p in roots
        tree = set(p for p in parent if inside(p))
        lines = lab = both = tree_nolab = 0
        outside = collections.Counter(); nolab = collections.Counter()
        for l in open(d + '/bt1.log', errors='replace'):
            f = l.rstrip('\n').split(',', 6)
            if len(f) != 7 or not f[0].isdigit(): continue
            lines += 1
            L, T = not f[1].startswith('0.0.0.0'), int(f[3]) in tree
            lab += L; both += L and T; tree_nolab += T and not L
            if L and not T: outside['%s %s' % (f[2], f[5])] += 1
            if T and not L: nolab[f[3]] += 1
        return dict(roots=sorted(roots), tree_processes=len(tree), tracer_lines=lines, labelled=lab,
            in_tree=both + tree_nolab, labelled_in_tree=both, labelled_outside_tree=sum(outside.values()),
            tree_without_label=tree_nolab, outside=dict(outside), without_label_by_pid=dict(nolab))
    return dict(first=count(first), exec_roots=len(execroot),
        exec_root_parent=[parent[p] for p in execroot], other_sshd_execs=other, exec=count(sorted(execroot)))

for d in sys.argv[1:]:
    print(d, json.dumps(run(d), sort_keys=True))
