#!/usr/bin/env python3
"""The three-client scene, mark by mark: for every run, whether each of the 24
planted executions (client 1-3, round 0-7) was found by the offline join and
which address it was given.  usage: marks.py freebsd|linux"""
import sys, glob, os, subprocess, collections
which = sys.argv[1]; here = os.path.dirname(os.path.abspath(__file__))
src = {'freebsd': ['10.99.0.17', '10.99.0.18', '10.99.0.19'], 'linux': ['10.0.3.1', '10.0.3.2', '10.0.3.3']}[which]
script, log = {'freebsd': ('../vuln/join-freebsd.py', 'c/audit.log'), 'linux': ('../lxc/join.py', 'audit-join.log')}[which]
print('%s: planted executions by run (expected 24: clients 1-3, rounds 0-7)' % which)
print('run  found  right  wrong  none  missing  duplicate')
for d in sorted(glob.glob('%s/%s/[0-9][0-9]' % (here, which))):
    o = subprocess.run([sys.executable, os.path.join(here, script), os.path.join(d, log)] + src, capture_output=True, text=True, env=dict(os.environ, MARKS='1')).stdout
    seen = collections.Counter(); right = wrong = none = 0
    for l in o.splitlines():
        f = l.split()
        if len(f) == 4 and f[0] == 'mark':
            k, r, a = int(f[1]), int(f[2]), f[3]; seen[(k, r)] += 1
            if a == '-': none += 1
            elif a == src[k - 1]: right += 1
            else: wrong += 1
    want = [(k, r) for k in (1, 2, 3) for r in range(8)]
    print('%s   %5d  %5d  %5d  %4d  %7d  %9d' % (os.path.basename(d), sum(seen.values()), right, wrong, none, sum(1 for w in want if w not in seen), sum(v - 1 for v in seen.values() if v > 1)))
