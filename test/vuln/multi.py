#!/usr/bin/env python3
"""Test only: several attackers at once, each from its own source address."""
import socket, sys, time, threading
target, port, sources = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
def attacker(n, src):
    s = socket.create_connection((target, port), timeout=10, source_address=(src, 0))
    def send(line, wait=0.3):
        s.sendall(line.encode() + b'\n'); time.sleep(wait)
    time.sleep(0.5)
    send('x; sh -i')
    for i in range(8):
        send('/bin/echo attacker%d round%d' % (n, i))
        send('cat /etc/hosts > /tmp/mark-%d-%d' % (n, i))
        send('sleep 20 & kill $!')
    send('exit')
    s.close()
ts = [threading.Thread(target=attacker, args=(i + 1, src)) for i, src in enumerate(sources)]
for t in ts: t.start()
for t in ts: t.join()
