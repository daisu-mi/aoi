#!/usr/bin/env python3
"""Where the client's address is in the stored audit records.  Read-only:
reads the unpacked records (tar xJf freebsd.tar.xz; tar xJf linux.tar.xz, here
or in another directory given as ROOT) and changes nothing.  Written after the
runs, on 2026-11-27, for the revision of the report; it is an analysis of the
stored records, not part of the harness.

What it computes, for every repetition, one JSON line:

 freebsd  For the login scene (a/audit.log, interval of the login), the
          service scene (a/audit.log, interval of the service), the repeat of
          the login with allow.setaudit and without the module (b/audit.log)
          and the three-client scene (c/audit.log, interval of the scene, and
          the whole exported trail):
            records       audit records with the jail's name (",zone,j1") in
                          the interval; the same selection as freebsd-rep.py
                          (t0 <= t <= t1 + 1)
            subject       how many of them have each address in the terminal
                          address of their subject token
            subject_is_client
                          (a) records whose subject address is a client's
            client_anywhere
                          (b) records in which a client's address occurs
                          anywhere, as a whole dotted address
            where         for (b), in which part of the record the address
                          occurs: "env:NAME" is the environment string NAME=...
                          of an audited execve (between "exec env" and
                          "path"), "arg" its argument list, "socket-inet" a
                          socket address token, "subject" the subject token,
                          "other" anything else.  A record is counted once
                          under each part in which the address occurs.
            events        for (b), the audit event names of those records
            exec_ssh_vars (added for the round-11 revision)
                          for the execve(2) records of the selection: "execve"
                          is their number; "SSH_CLIENT" and "SSH_CONNECTION"
                          give, per address that is the first word of the
                          variable's value in the audited environment, how
                          many execution records carry it; "neither" is the
                          number of execution records with neither variable
                          (all of them where the policy does not record
                          environments, as in the three-client scene)
          "setup_before_login" is the same count for the records with the
          jail's name in a/audit.log before the interval of the login (the
          executions by which the harness set up the jail and started its
          services).
          The client is 10.99.0.17 in the login, service and repeat scenes;
          the three clients are 10.99.0.17, .18 and .19.  10.0.2.2 is the
          address of the administrator's session from which the harness
          started the jail's services.

 linux    For the login scene (audit.log, t1a <= t <= t1b), the service scene
          (audit.log, t1b <= t <= t2b) and the three-client scene (the whole
          audit-join.log):
            events        audit events (records grouped by serial)
            client_anywhere
                          events with a record in which a client's address
                          occurs in any of three forms: as dotted text, as
                          the hexadecimal encoding of that text (the form in
                          which the audit daemon writes some argument and
                          title strings), or as the four address bytes in the
                          hexadecimal "saddr=" field of a SOCKADDR record
                          (an IPv4 or IPv4-mapped IPv6 socket address)
            where         for those, "TYPE:form" counted once per event
            syscalls      for those, the SYSCALL names of the events
            auid          the AUID values of the events of the interval (the
                          login identity; interpreted field of the daemon's
                          ENRICHED format)
          The client is 10.0.3.1 in the login and service scenes; the three
          clients are 10.0.3.1, .2 and .3.

usage: peer-in-audit.py freebsd|linux [ROOT]
       (ROOT holds freebsd/NN or linux/NN; default: the directory of this file)"""
import re, sys, os, glob, json, calendar, time, collections, binascii
here = os.path.dirname(os.path.abspath(__file__)); which = sys.argv[1]
root = sys.argv[2] if len(sys.argv) > 2 else here

def has(addr, text):
    return re.search(r'(?<![\d.])' + re.escape(addr) + r'(?![\d])', text) is not None

HDR = re.compile(r'header,\d+,\d+,(.*?),\d+,(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (\w+) +(\d+) (\d+):(\d+):(\d+) (\d+), \+ (\d+) msec,(.*)')
SUBJ = re.compile(r',subject,[^,]*,[^,]*,[^,]*,[^,]*,[^,]*,(\d+),(\d+),(\d+),([^,]*)')

def fb_scene(fn, clients, t0=None, t1=None, before=None):
    xv = dict(execve=0, neither=0, SSH_CLIENT=collections.Counter(), SSH_CONNECTION=collections.Counter())
    n = 0; subj = collections.Counter(); a = b = 0; where = collections.Counter(); events = collections.Counter()
    for l in open(fn, errors='replace'):
        m = HDR.match(l)
        if not m or ',zone,j1' not in l: continue
        if t0 is not None or before is not None:
            t = calendar.timegm((int(m.group(7)), time.strptime(m.group(2), '%b').tm_mon, int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)))) + int(m.group(8)) / 1000
            if t0 is not None and not (t0 <= t <= t1 + 1): continue
            if before is not None and not (t < before): continue
        n += 1
        if m.group(1) == 'execve(2)':
            xv['execve'] += 1; got = False
            for name in ('SSH_CLIENT', 'SSH_CONNECTION'):
                v = re.search(r',' + name + r'=([^, ]*)', l)
                if v: xv[name][v.group(1)] += 1; got = True
            if not got: xv['neither'] += 1
        s = SUBJ.search(l); sa = s.group(4) if s else '?'
        subj[sa] += 1
        if sa in clients: a += 1
        if not any(has(c, l) for c in clients): continue
        b += 1; events[m.group(1)] += 1; parts = set()
        rest = l
        if sa in clients: parts.add('subject')
        if s: rest = rest[:s.start()] + rest[s.end():]
        e = re.search(r',exec env,(.*?),path,', rest)
        if e:
            for item in e.group(1).split(','):
                if any(has(c, item) for c in clients): parts.add('env:' + item.split('=')[0])
            rest = rest[:e.start()] + ',path,' + rest[e.end():]
        g = re.search(r',exec arg,(.*?)(?:,exec env,|,path,)', l)
        if g and any(has(c, g.group(1)) for c in clients):
            parts.add('arg'); rest = rest.replace(g.group(1), '', 1)
        for k in re.finditer(r',socket-inet6?,[^,]*,[^,]*,([^,]*)', rest):
            if any(has(c, k.group(1)) for c in clients): parts.add('socket-inet')
        rest = re.sub(r',socket-inet6?,[^,]*,[^,]*,[^,]*', '', rest)
        if any(has(c, rest) for c in clients): parts.add('other')
        for p in parts: where[p] += 1
    return dict(records=n, subject=dict(subj), subject_is_client=a, client_anywhere=b, where=dict(sorted(where.items())), events=dict(sorted(events.items())),
        exec_ssh_vars=dict(execve=xv['execve'], neither=xv['neither'], SSH_CLIENT=dict(sorted(xv['SSH_CLIENT'].items())), SSH_CONNECTION=dict(sorted(xv['SSH_CONNECTION'].items()))))

def fb(d):
    out = {}; one = ['10.99.0.17']; three = ['10.99.0.17', '10.99.0.18', '10.99.0.19']
    t0, t1 = map(int, open(d + '/a/interval-ssh.txt').read().split()); out['login'] = fb_scene(d + '/a/audit.log', one, t0, t1)
    out['setup_before_login'] = fb_scene(d + '/a/audit.log', one, before=t0)
    t0, t1 = map(int, open(d + '/a/interval-vuln.txt').read().split()); out['service'] = fb_scene(d + '/a/audit.log', one, t0, t1)
    t0, t1 = map(int, open(d + '/b/interval.txt').read().split()); out['repeat_setaudit'] = fb_scene(d + '/b/audit.log', one, t0, t1)
    t0, t1 = map(int, open(d + '/c/interval.txt').read().split()); out['three_interval'] = fb_scene(d + '/c/audit.log', three, t0, t1)
    out['three_whole_trail'] = fb_scene(d + '/c/audit.log', three)
    return out

def forms(addr, typ, text):
    f = set()
    if has(addr, text): f.add('text')
    hx = binascii.hexlify(addr.encode()).decode().upper()
    if re.search(hx + r'(?!3[0-9])', text): f.add('hex-text')
    if typ == 'SOCKADDR':
        m = re.search(r'\bsaddr=([0-9A-F]+)', text)
        raw = ''.join('%02X' % int(x) for x in addr.split('.'))
        if m:
            s = m.group(1)
            if s[:4] == '0200' and s[8:16] == raw: f.add('saddr-bytes')        # AF_INET: family, port, address
            if s[:4] == '0A00' and s[40:48] == raw: f.add('saddr-bytes')       # AF_INET6: last four bytes of the address
    return f

def lx_scene(fn, clients, t0=None, t1=None):
    ev = collections.OrderedDict()
    for l in open(fn, errors='replace'):
        m = re.match(r'type=(\w+) msg=audit\((\d+\.\d+):(\d+)\): (.*)', l)
        if not m: continue
        if t0 is not None and not (t0 <= float(m.group(2)) <= t1): continue
        ev.setdefault(m.group(3), []).append((m.group(1), m.group(4)))
    b = 0; where = collections.Counter(); sysc = collections.Counter(); auid = collections.Counter()
    for recs in ev.values():
        parts = set()
        for typ, text in recs:
            for c in clients:
                for f in forms(c, typ, text): parts.add('%s:%s' % (typ, f))
            if typ == 'SYSCALL':
                u = re.search(r'\bAUID="([^"]*)"', text)
                if u: auid[u.group(1)] += 1
        if parts:
            b += 1
            for p in parts: where[p] += 1
            for typ, text in recs:
                if typ == 'SYSCALL':
                    s = re.search(r'\bSYSCALL=(\w+)', text); sysc[s.group(1) if s else '?'] += 1
    return dict(events=len(ev), client_anywhere=b, where=dict(sorted(where.items())), syscalls=dict(sorted(sysc.items())), auid=dict(auid))

def lx(d):
    ta, tb, tc = (float(open('%s/%s' % (d, f)).read()) for f in ('t1a', 't1b', 't2b'))
    return dict(login=lx_scene(d + '/audit.log', ['10.0.3.1'], ta, tb), service=lx_scene(d + '/audit.log', ['10.0.3.1'], tb, tc),
        three_whole_log=lx_scene(d + '/audit-join.log', ['10.0.3.1', '10.0.3.2', '10.0.3.3']))

for d in sorted(glob.glob('%s/%s/[0-9][0-9]' % (root, which))):
    print(which + '/' + os.path.basename(d), json.dumps(fb(d) if which == 'freebsd' else lx(d), sort_keys=True))
