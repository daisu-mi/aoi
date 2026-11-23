#!/bin/sh
# Test only: the same interactive session as on FreeBSD, typed into ssh.
K="-i $HOME/.ssh/id_hp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
(sleep 3; for c in 'id' 'uname -sr' 'cat /etc/hosts > /tmp/jail-mark' 'cat /nonexistent-file' 'sleep 30 & kill $!' 'env SECRET=xyz /bin/echo hello' 'passwd foo'; do echo "$c"; sleep 1; done; echo 'foobar!'; sleep 1; echo 'foobar!'; sleep 1; echo exit) | ssh $K -tt root@"$1"
