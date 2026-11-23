#!/bin/sh
# Print the honey log kept on a raw disk.  usage: honeydump.sh /dev/md0
dev=${1:?usage: $0 device}
magic=$(dd if="$dev" bs=512 count=1 2>/dev/null | head -c 8)
[ "$magic" = HONEYLOG ] || { echo "$dev: no honey log" >&2; exit 1; }
ss=$(dd if="$dev" bs=512 count=1 2>/dev/null | od -An -t u4 -j 12 -N 4 | tr -d ' ')
used=$(dd if="$dev" bs=512 count=1 2>/dev/null | od -An -t u8 -j 16 -N 8 | tr -d ' ')
[ "$used" -gt 0 ] && dd if="$dev" bs="$ss" skip=1 2>/dev/null | head -c "$used"
