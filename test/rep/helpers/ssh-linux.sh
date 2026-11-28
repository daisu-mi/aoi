#!/bin/sh
exec ssh -i "$(dirname "$0")/id_vm" -p 2223 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o IdentityAgent=none -o IdentitiesOnly=yes ubuntu@127.0.0.1 "$@"
