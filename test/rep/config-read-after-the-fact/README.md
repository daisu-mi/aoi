# Configuration read after the fact

The two files in this directory were read from the two test machines on
2026-11-27 (the date each file prints), that is, after the repeated runs of
`../freebsd.tar.xz` and `../linux.tar.xz` were made. They are not a record of
the state of the machines during the runs. The FreeBSD machine was rebooted
between the experiments and this reading. Nothing here was saved at run time.

| File | What it holds |
|---|---|
| `freebsd/audit-config.txt` | FreeBSD test machine: line counts of the four files under `/etc/security/`, the lines of `audit_control`, the line of `audit_user`, `uname -a`, the date |
| `linux/audit-and-container-config.txt` | Linux test machine: the date, `uname -a`, `/etc/audit/auditd.conf`, the listing and content of `/etc/audit/rules.d`, `/etc/audit/audit.rules`, the config file of the LXC container `hp` (`/var/lib/lxc/hp/config`), and the versions of bpftrace, LXC and the packages `auditd`, `bpftrace`, `lxc` |

## What the harness set at run time, and what is only known from this reading

Set at run time by the scripts kept in `..` (so known for the runs):

- FreeBSD (`freebsd-lib.sh`, `audit_on`; called from `freebsd-run.sh`): the
  lines `flags:`, `naflags:`, `policy:` and `filesz:` of
  `/etc/security/audit_control` are rewritten before each scene
  (`flags` and `naflags` to `lo,aa,ex,fr,fw,fc,fd,pc` with policy
  `cnt,argv,arge` for scenes a and b, and to `lo,aa,ex,pc,nt` with policy
  `cnt,argv` for scene c; `filesz:50M`), the audit daemon is started, and
  after the scene the file is put back from a copy made before the first
  change (`audit_off`). The values of those four lines in
  `freebsd/audit-config.txt` are therefore not the values of the runs.
- Linux (`linux-one.sh`, `fresh`): the audit log is rotated and emptied, all
  rules are deleted (`auditctl -D`), and one rule is added per part
  (`-a always,exit -F arch=b64 -S execve -S openat -S kill -k honey` for the
  login and service scenes; `-a always,exit -F arch=b64 -S accept,accept4 -S
  clone,clone3,fork,vfork -S execve -k join` for the three-client scene).
  bpftrace is started with `BPFTRACE_PERF_RB_PAGES=4096`.

Known only from this later reading (not recorded at run time):

- FreeBSD: the other lines of `audit_control` (`dir`, `dist`, `minfree`,
  `expire-after`), `audit_user`, and that `audit_class` and `audit_event`
  have 20 and 719 lines. The harness does not touch these.
- Linux: `auditd.conf` (among its lines `log_format = ENRICHED`), the rules
  file (`-D`, `-b 8192`, `-f 1`, `--backlog_wait_time 60000`), the container's
  config file with its header line naming the template and its parameters
  (`lxc-download`, `-d ubuntu -r noble -a amd64`), and the tool versions.

Not in this directory and not stored elsewhere in the repository: the files
included by the container's config (`/usr/share/lxc/config/common.conf`,
`userns.conf`, `/etc/lxc/default.conf`), the command that started the
vulnerable service in the container, the helper scripts behind `VMDIR`, and
the sizes of the virtual machines.
