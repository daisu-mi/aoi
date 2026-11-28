#!/bin/sh
# Computes the size of the 2001 patch and of the 2026 recorder sources, for
# the size table of the report.  Reads the files only.
#   patch: files touched, lines added, lines added that are not blank, lines removed
#   sources: lines (wc -l) and lines that are not blank
# usage: sh count-lines.sh     (run from any directory)
cd "$(dirname "$0")/.." || exit 1
P=legacy/honey-linux-2.2.16.patch
echo "$P: files $(grep -c '^+++ ' $P), added $(grep '^+' $P | grep -vc '^+++ '), added not blank $(grep '^+' $P | grep -v '^+++ ' | grep -vc '^+[[:space:]]*$'), removed $(grep '^-' $P | grep -vc '^--- ')"
for f in freebsd/honey.c test/compare/honey.d test/lxc/honey.bt; do
	echo "$f: lines $(wc -l < $f | tr -d ' '), not blank $(grep -c '[^[:space:]]' $f)"
done
