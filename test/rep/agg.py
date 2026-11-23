#!/usr/bin/env python3
"""Put the repetitions side by side: for every number, the value if all runs agree,
otherwise minimum, median and maximum.  usage: agg.py freebsd|linux"""
import sys, json, glob, subprocess, statistics, os
which = sys.argv[1]; here = os.path.dirname(os.path.abspath(__file__))
runs = sorted(glob.glob('%s/%s/[0-9][0-9]' % (here, which))); rows = []
for r in runs:
    o = subprocess.run([sys.executable, '%s/%s-rep.py' % (here, which), r], capture_output=True, text=True)
    if o.returncode: print('FAILED', r, o.stderr.strip().splitlines()[-1:]); continue
    rows.append(json.loads(o.stdout))
def flat(x, p=''):
    if isinstance(x, dict):
        for k, v in x.items(): yield from flat(v, p + k + '.')
    elif isinstance(x, list):
        for i, v in enumerate(x): yield from flat(v, p + str(i) + '.')
    else: yield p[:-1], x
print('%s: %d repetitions' % (which, len(rows)))
keys = [k for k, _ in flat(rows[0])]
for k in keys:
    vals = [dict(flat(r)).get(k) for r in rows]
    if all(v == vals[0] for v in vals): print('  %-34s %s (all runs)' % (k, vals[0]))
    elif all(isinstance(v, (int, float)) for v in vals): print('  %-34s min %s, median %s, max %s   %s' % (k, min(vals), statistics.median(vals), max(vals), vals))
    else: print('  %-34s %s' % (k, vals))
