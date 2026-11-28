# Concealment, containment and the audit condition (FreeBSD)

Four scripts, each run once as root inside the FreeBSD 15.1 test machine, and
the transcript of each run. Every command is printed before its output.

| Script | Transcript | What it shows |
|---|---|---|
| `part1-conceal.sh` | `part1-conceal.txt` | the four concealment checks of the 2002 thesis, with no jail: no network traffic, no open file, write statistics, hidden device node |
| `part2-jail.sh` | `part2-jail.txt` | what root inside a jail can see and do |
| `part3-securelevel.sh` | `part3-securelevel.txt` | secure levels 1 and 2 against root on the host |
| `part4-auditcond.sh`, `auditcond.c` | `part4-auditcond.txt` | what a jailed process is told when it asks whether auditing is on |

The log disk is `vtbd1`, a 16 MB virtual disk. `part3` raises the secure
level, which cannot be lowered again; the machine was restarted after it.
The control connection of the tests is ssh on `vtnet0`, so the packet capture
of `part1` leaves port 22 out on that interface.
