#!/bin/sh
# Test only: a greeting service with a deliberate hole.  The name is handed
# to the shell unquoted, so anything after ";" runs as a command.
printf 'name? '
read name
eval "echo Hello, $name"
