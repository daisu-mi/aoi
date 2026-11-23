#!/usr/bin/env python3
"""Count marked lines of the three-client run in a bpftrace log by the address they carry.
usage: tally-marks.py log addr1 addr2 addr3"""
import re, sys
src={'1':sys.argv[2],'2':sys.argv[3],'3':sys.argv[4]}; ok=bad=none=0
for l in open(sys.argv[1],errors='replace'):
    f=l.rstrip('\n').split(',',6)
    if len(f)<7 or not f[0].isdigit(): continue
    m=re.search(r'attacker(\d) round|/tmp/mark-(\d)-',f[6].replace('\\x00',' '))
    if not m: continue
    a=f[1].split(':')[0]; n=m.group(1) or m.group(2)
    if a=='0.0.0.0': none+=1
    elif a==src[n]: ok+=1
    else: bad+=1
print('marked lines: right %d, wrong %d, none %d'%(ok,bad,none))
