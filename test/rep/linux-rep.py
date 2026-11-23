#!/usr/bin/env python3
"""Numbers of one Linux repetition (a directory made by linux-run.sh), as one JSON line.
Reads the outputs of ../lxc/match.py, summary.py, join.py and tally-marks.py kept there.
usage: linux-rep.py linux/NN"""
import re, sys, json
d = sys.argv[1]; R = lambda f: open(d + '/' + f, errors='replace').read()
out = {}
m = R('match.txt'); s = R('summary.txt')
blocks = re.split(r'\n== ', s)[1:]
for name, blk in zip(('ssh', 'service'), blocks):
    o = re.search(name + r': opens (\d+) / (\d+), matched[^:]*: (\d+)', m); x = re.search(name + r': execs (\d+) / (\d+), matched[^:]*: (\d+)', m)
    b = re.search(r'bpftrace: コンテナ全体 (\d+) 行、接続元つき (\d+) 行', blk); a = re.search(r'監査: 同じプロセスの記録 (\d+) 件', blk)
    au = re.search(r"持ち主\(auid\) (\{.*?\})\s+接続元 10.0.3.1 が出る件数 (\d+)", blk)
    out[name] = dict(open=[int(o.group(1)), int(o.group(2))], open_match=int(o.group(3)), exec=[int(x.group(1)), int(x.group(2))], exec_match=int(x.group(3)),
        tracer_lines=int(b.group(1)), tracer_labelled=int(b.group(2)), audit_records=int(a.group(1)), audit_owner=au.group(1), audit_intruder=int(au.group(2)))
j = R('join.txt'); k = R('marks.txt')
a = re.search(r'successful accept events: (\d+), with a peer address record: (\d+)', j)
out['three'] = dict(tracer_marks=[int(x) for x in re.search(r'right (\d+), wrong (\d+), none (\d+)', k).groups()],
    join_marks=[int(x) for x in re.search(r'right address (\d+), wrong (\d+), none (\d+)', j).groups()],
    join_assigned=[int(x) for x in re.search(r'given an address: (\d+) of (\d+)', j).groups()], accepts=[int(a.group(1)), int(a.group(2))])
out['lost'] = int(re.search(r'lost: (\d+)', R('run.txt')).group(1))
print(json.dumps(out, ensure_ascii=False))
