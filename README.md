# aoi — Anti OS Intrusion

aoi records what an intruder does on a host. It does not block intrusion; it
is the recorder of a honeypot.

It is a loadable kernel module for FreeBSD 15.1, and a reconstruction of a
Linux 2.2.16 kernel patch written in 2001. The original patched the kernel
source. This one leaves the kernel untouched. Inside the code the module
keeps its 2001 name, `honey`.

This repository accompanies a report that compares the module with standard
tools (audit, DTrace, bpftrace). It is published so that the measurements can
be checked, not as a tool to deploy.

The module records what processes do after an intrusion:

- program execution, with the argument list
- file opens, including the ones that fail
- reads and writes of regular files
- signals sent from one process to another
- everything that goes in and out of pseudo terminals, including text that is
  never echoed
- the address and port of the remote peer, on the records of every process
  that descends from an accepted connection

It is the companion of [aod](https://github.com/daisu-mi/aod) (Anti OS
Detection), which makes a host answer an OS scanner as a different system.

## Status

This is a research prototype. Do not use its log as evidence.

- Unloading the module while a wrapped system call is in progress is not safe.
- A write to the raw disk that fails late is flagged, but the lost records are
  not counted.
- The peer label is right for servers that start one process for each
  connection. Servers that keep a pool of processes or threads were not tested.
- IPv6 peers are formatted but were not tested.

## Build and load

On FreeBSD 15.1 with the kernel source in `/usr/src`:

```
cd freebsd
make
kldload ./honey.ko
```

The log goes to `/var/log/honey.log`. Each line is

```
time,peer,event,pid,uid,command,detail
```

Settings are under `security.mac.honey`:

| Name | Meaning |
|---|---|
| `enabled` | Record events. On by default. |
| `jailonly` | Record only what happens inside jails. |
| `logfile` | Log file. Set before loading. |
| `logdev` | A raw disk to log to in place of the file, for example `md0`. Set before loading. |
| `rawdirect` | Hand log writes straight to the disk driver. Set before loading. |
| `alertdev` | A terminal that shows activity as it happens, for example `ttyv1`. Set before loading. |
| `logged`, `dropped`, `queued`, `logerr` | Counters. |

Settings marked "set before loading" are read once, from the kernel
environment (`kenv`). `freebsd/honeydump.sh` prints a log kept on a raw disk.

## The same recording without the module

Two short scripts record the same events with standard tools only:

- `test/compare/honey.d`: DTrace, for processes inside FreeBSD jails
- `test/lxc/honey.bt`: bpftrace, for processes inside Linux containers

## Measurements

`test/` holds the scripts and the raw records of every run.

| Directory | Content |
|---|---|
| `test/compare` | One scripted SSH session on FreeBSD, recorded by the module, by audit and by DTrace |
| `test/vuln` | A deliberately vulnerable service on FreeBSD, with one and with three attackers |
| `test/lxc` | The same scenes in a Linux container, recorded by bpftrace and by auditd |
| `test/perf` | Cost of recording |

All addresses in the records belong to an isolated test network. The password
that appears in them belongs to a throwaway test account.

## The 2001 version

`legacy/` holds the original as a patch to the Linux 2.2.16 kernel, with a
link to the paper that described it.

## License

BSD 2-Clause; see `LICENSE`. The patch in `legacy/` modifies Linux kernel
files and is under the GNU General Public License, version 2.
