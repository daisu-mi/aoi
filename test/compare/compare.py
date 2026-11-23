#!/usr/bin/env python3
"""Compare what honey.ko, audit and DTrace recorded for the same session."""
import re, calendar, time, collections
T0, T1 = map(int, open('run1/interval.txt').read().split())
U0, U1 = map(int, open('run2/interval.txt').read().split())

# ---- honey
H = []
for l in open('run1/honey.log', errors='replace'):
    f = l.rstrip('\n').split(',', 6)
    if len(f) < 7: continue
    t = float(f[0])
    if T0 <= t <= T1 + 1:
        H.append(dict(t=t, peer=f[1], kind=f[2], pid=int(f[3]), comm=f[5], d=f[6]))
# ---- dtrace
D = []
for l in open('run2/dtrace.log', errors='replace'):
    f = l.rstrip('\n').split(',', 5)
    if len(f) < 6 or not f[0].isdigit(): continue
    t = int(f[0]) / 1e6
    if U0 <= t <= U1 + 1:
        D.append(dict(t=t, kind=f[1], pid=int(f[2]), comm=f[4], d=f[5]))
# ---- audit (praudit -l, one record per line; times are UTC)
A = []
for l in open('run2/audit.log', errors='replace'):
    m = re.match(r'header,\d+,\d+,(.*?),\d+,(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (\w+) +(\d+) (\d+):(\d+):(\d+) (\d+), \+ (\d+) msec,(.*)', l)
    if not m: continue
    mon = time.strptime(m.group(2), '%b').tm_mon
    t = calendar.timegm((int(m.group(7)), mon, int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)))) + int(m.group(8)) / 1000
    if not (U0 <= t <= U1 + 1) or ',zone,j1' not in l: continue
    s = re.search(r'subject,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,(\d+),(\d+),(\d+),([^,]*)', l)
    A.append(dict(t=t, comm='', ev=m.group(1), rest=m.group(9), pid=int(s.group(1)) if s else 0,
                  addr=s.group(4) if s else '', ok='return,success' in l))

pidname = {}
for r in D: pidname[r['pid']] = r['comm']
for r in A: r['comm'] = pidname.get(r['pid'], '?')
def base(p): return p.rstrip('/').split('/')[-1]
def show(title, rows):
    print('\n== ' + title)
    for r in rows: print('  ' + r)

# exec
hx = sorted((0, r['d'].split(' | ')[1] if ' | ' in r['d'] else r['d']) for r in H if r['kind'] == 'exec')
dx = sorted((0, r['d']) for r in D if r['kind'] == 'exec')
ax = []
for r in A:
    if r['ev'].startswith('execve'):
        m = re.search(r'exec arg,(.*?)(?:,exec env,|,path,)', r['rest'])
        ax.append((0, m.group(1).replace(',', ' ') if m else '?'))
ax.sort()
show('exec の件数', ['honey %d、監査 %d、DTrace %d' % (len(hx), len(ax), len(dx)),
     '引数の並びが全件一致: honey と監査 %s、honey と DTrace %s' % ([a for _,a in hx] == [a for _,a in ax], [a for _,a in hx] == [a for _,a in dx])])
for name, x in (('honey', hx), ('監査', ax), ('DTrace', dx)):
    print('  %s: %s' % (name, [a for _, a in x if 'echo' in a or 'passwd' in a]))
henv = sum('SECRET=xyz' in r['d'] for r in H if r['kind'] == 'exec')
aenv = sum('SECRET=xyz' in r['rest'] for r in A if r['ev'].startswith('execve'))
print('  環境変数 SECRET=xyz が残った件数: honey %d、監査 %d、DTrace %d' % (henv, aenv, sum('SECRET' in r['d'] for r in D)))

# open
def hopen(r):
    d = re.sub(r' errno=\d+$', '', r['d'])
    b = base(d.split(' ', 1)[1] if ' ' in d else d)
    return (r['comm'], 'tmp*' if re.search(r'\.[A-Za-z0-9]{6,10}$', b) else b, r['kind'] == 'open')
ho = collections.Counter(hopen(r) for r in H if r['kind'] in ('open', 'open-failed'))
tmpn = lambda b: 'tmp*' if re.search(r'\.[A-Za-z0-9]{6,10}$', b) else b
do = collections.Counter((r['comm'], tmpn(base(r['d'])), r['kind'] == 'open') for r in D if r['kind'] in ('open', 'open-failed'))
ao = collections.Counter()
for r in A:
    if r['ev'].startswith('open'):
        m = re.search(r'path,([^,]*)', r['rest'])
        ao[(r['comm'], tmpn(base(m.group(1))) if m else '?', r['ok'])] += 1
def tot(c, ok): return sum(v for k, v in c.items() if k[2] == ok)
show('open の件数(成功 / 失敗)', ['honey %d / %d' % (tot(ho, True), tot(ho, False)), '監査 %d / %d' % (tot(ao, True), tot(ao, False)), 'DTrace %d / %d' % (tot(do, True), tot(do, False)),
     'honey にあって DTrace にない: %d、DTrace にあって honey にない: %d' % (sum((ho - do).values()), sum((do - ho).values())),
     'honey にあって監査にない: %d、監査にあって honey にない: %d' % (sum((ho - ao).values()), sum((ao - ho).values()))])
print('  honey にあって監査にない例:', [k for k in (ho - ao)][:6])
print('  監査にあって honey にない例:', [k for k in (ao - ho)][:6])
print('  DTrace と honey の差の例:', [k for k in (ho - do)][:4], [k for k in (do - ho)][:4])

# signal
hs = sorted(r['d'] for r in H if r['kind'] == 'signal')
ds = sorted(r['d'] for r in D if r['kind'] == 'signal')
as_ = [r for r in A if r['ev'].startswith('kill')]
show('signal', ['honey %d 件: %s' % (len(hs), hs), '監査 kill(2) %d 件' % len(as_),
     'DTrace %d 件(うちカーネルが出した子プロセス終了の通知 20 番が %d 件)' % (len(ds), sum(d.startswith('20 ') for d in ds)),
     'DTrace の 20 番以外: %s' % [d for d in ds if not d.startswith('20 ')]])

# terminal
hin = ''.join(r['d'].split(' ', 1)[1] for r in H if r['kind'] == 'tty-in')
din = ''.join(chr(int(r['d'])) for r in D if r['kind'] == 'tty-in' and r['d'].isdigit())
hout = sum(len(r['d'].split(' ', 1)[1].encode().decode('unicode_escape', 'replace')) for r in H if r['kind'] == 'tty-out' and ' ' in r['d'])
dout = [r['d'].split(' ', 1)[1] for r in D if r['kind'] == 'tty-out' and ' ' in r['d']]
show('端末', ['入力: honey %d 行、DTrace %d 文字、監査 0' % (sum(r['kind'] == 'tty-in' for r in H), len(din)),
     'パスワード foobar! が入力の記録にある回数: honey %d、DTrace %d、監査 %d' % (hin.count('foobar!'), din.count('foobar!'), sum('foobar!' in r['rest'] for r in A)),
     'DTrace の入力をつなげたもの: %r' % din[-150:],
     '出力: honey %d 件 約 %d バイト、DTrace %d 件' % (sum(r['kind'] == 'tty-out' for r in H), hout, len(dout)),
     '出力に「New Password」がある: honey %s、DTrace %s' % (any('New Password' in r['d'] for r in H if r['kind'] == 'tty-out'), any('New Password' in d for d in dout)),
     '出力に入力の写し(root@j1 のあとの id など)がある: honey %s、DTrace %s' % (any('uname' in r['d'] for r in H if r['kind'] == 'tty-out'), 'uname' in ''.join(d.replace('\\0', '') for d in dout))])

# read / write
for k in ('read', 'write'):
    hr = set((r['comm'], tmpn(base(r['d']))) for r in H if r['kind'] == k)
    dr = set((r['comm'], tmpn(r['d'])) for r in D if r['kind'] == k)
    show(k, ['行数: honey %d、DTrace %d、監査 0' % (sum(r['kind'] == k for r in H), sum(r['kind'] == k for r in D)),
         'プロセスとファイルの組: honey %d、DTrace %d、共通 %d' % (len(hr), len(dr), len(hr & dr)),
         'honey だけ: %s' % sorted(hr - dr)[:5], 'DTrace だけ: %s' % sorted(dr - hr)[:5],
         '名前が ? の行: honey %d、DTrace %d' % (sum(r['kind'] == k and r['d'] == '?' for r in H), sum(r['kind'] == k and r['d'] == '?' for r in D))])

# who
show('接続元', ['honey: %s' % dict(collections.Counter(r['peer'] for r in H)),
     '監査の subject: %s' % dict(collections.Counter(r['addr'] for r in A)), 'DTrace: 記録なし'])
show('全体の行数', ['honey %d、監査 %d、DTrace %d' % (len(H), len(A), len(D)),
     '監査の内訳の上位: %s' % collections.Counter(r['ev'] for r in A).most_common(8)])
