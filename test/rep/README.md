# Repeated runs

Every scene of the report was run ten times. This directory holds the scripts
and the raw records.

| File | What it does |
|---|---|
| `freebsd-run.sh`, `freebsd-lib.sh` | run the FreeBSD scenes; results go to `freebsd/NN/` |
| `linux-run.sh`, `linux-one.sh` | run the Linux scenes; results go to `linux/NN/` |
| `freebsd-rep.py`, `linux-rep.py` | the numbers of one repetition, as one JSON line |
| `agg.py freebsd` or `agg.py linux` | all repetitions side by side |
| `marks.py freebsd` or `marks.py linux` | the three-client scene mark by mark: found, right, wrong, missing, duplicate |
| `tree.py linux/NN` | service scene on Linux: the process tree rebuilt from the audit log, against the lines the tracer labelled; all ten are in `results-linux-tree.txt` |
| `extra.py freebsd` or `extra.py linux` | counts that `agg.py` does not print: records that share a matching key, audit subjects of the three-client scene in the whole trail and in the interval, lines of the module without an address, interleaving, executions of the service scene on FreeBSD; and, added on 2026-11-27 for the rows of the comparison table that no other script printed for FreeBSD, the login scene's terminal input and output, reads and writes, sightings of the password, write records without a name and signals, for the module (`ssh.module_terminal`), for DTrace with the module (`ssh.dtrace_with_module`) and in the repeat without it (`ssh.dtrace_repeat`), and the audit records that contain the password (`ssh.audit_password_records`); all runs are in `results-extra.txt` |
| `../lxc/tree-ssh.py` | the same tree check as `tree.py`, for the login scene of the one earlier run kept in `../lxc/` |
| `../lxc/tree-ssh.py linux/NN` | the same check run on the login scene of each of the ten runs; the output for all ten is in `results-linux-tree-ssh.txt` |
| `tree-ssh-root.py linux/NN ...` | the login-scene check with two rules for the root of the tree side by side: the rule of `tree-ssh.py`, and the process that executed `/usr/sbin/sshd -D -R`; all ten are in `results-linux-tree-ssh-root.txt` |
| `results-freebsd-first-series.txt` | output of `freebsd-rep.py freebsd-first-series/NN` for the ten runs of the first FreeBSD series (see below) |
| `config-read-after-the-fact/` | audit and container configuration of the two test machines, read on 2026-11-27, after the runs; see its README |
| `peer-in-audit.py freebsd` or `peer-in-audit.py linux` | where the client's address is in the stored audit records: per run and scene, the records whose audit subject carries it, and the records that contain it anywhere, with the field or variable; and, added on 2026-11-27, for the execution records of each scene the address in `SSH_CLIENT` and in `SSH_CONNECTION` and how many records carry each (`exec_ssh_vars`; `setup_before_login` is the same for the executions that set up the jail before the login); written after the runs; all runs are in `results-peer-in-audit.txt` |
| `helpers/` | the four helper scripts behind `VMDIR` that start and reach the two test machines, copied on 2026-11-27 from the author's machine; no key; see its README |
| `match-ssh-tree.py linux/NN ...` | login scene on Linux: the record-by-record match of `../lxc/match.py` with the processes taken from the audit-derived tree (both root rules of `tree-ssh-root.py`) in place of the processes the tracer labelled; written after the runs; all ten are in `results-linux-match-ssh-tree.txt` |
| `extra2.py linux`, `extra2.py freebsd` or `extra2.py freebsd-first-series` | added on 2026-11-27 from the stored records: for the scripted `sleep 30 & kill $!` of the login and service scenes, whether the process the signal was sent to has an execution of `sleep 30` and which of the two each recorder has first; and, for the FreeBSD service scene, the opens of the module against those of audit by the key of `freebsd-rep.py`; output for all runs in `results-extra2.txt` |

The raw records are packed: `linux.tar.xz`, `freebsd.tar.xz` and
`freebsd-first-series.tar.xz`. Unpack them here (`tar xJf linux.tar.xz`, and
so on) before running `agg.py`. `results-linux.txt` and `results-freebsd.txt`
are the output of `agg.py` on the unpacked records: every number of every
run.

## From the records to the tables

```
tar xJf linux.tar.xz; tar xJf freebsd.tar.xz
python3 agg.py freebsd      # results-freebsd.txt
python3 agg.py linux        # results-linux.txt
python3 marks.py freebsd; python3 marks.py linux    # results-marks.txt
```

The comparison table of the report takes its execution and open counts from
`ssh.exec`, `ssh.open` and `ssh.open_ok`, and its address counts from
`ssh.module_labelled`, `ssh.module_lines`, `ssh.audit_records` and
`ssh.audit_intruder` (FreeBSD) and from `ssh.tracer_labelled` and
`ssh.audit_records` (Linux). The service table takes the `service.*` fields,
and the three-client paragraphs the `three.*` fields and `results-marks.txt`.
The Nmap rounds are in the repository of the fingerprinting module.

## Setup: what is recorded and what is not

- FreeBSD: the jail, the network, the audit flags, the recorder settings, the
  SSH server, `inetd` and DTrace are set up by `freebsd-lib.sh` and
  `freebsd-run.sh` in each repetition; the commands are in those two files.
- Linux: `linux-one.sh` sets the audit rules and starts bpftrace. It expects a
  running container `hp` with the service on port 1524 and copies of
  `../lxc/honey.bt`, `session.sh`, `attack.py` and `multi.py` in `/tmp` of the
  test machine. The commands that created the container and started the
  service were not saved. The only record of the creation is the header of
  the container's config file, read after the runs
  (`config-read-after-the-fact/linux/audit-and-container-config.txt`):
  "Template used to create this container:
  /usr/share/lxc/templates/lxc-download", "Parameters passed to the template:
  -d ubuntu -r noble -a amd64". The service's script is `../lxc/vuln.sh`; the
  command line that served it on port 1524 was not saved. One trace of it is
  in the records: the audit events of the service's `socat` processes (3 in
  `audit.log` and 18 in `audit-join.log` of each of the ten runs) carry the
  process title, in the hexadecimal `proctitle=` field, `socat
  TCP-LISTEN:1524,fork,reuseaddr EXEC:sh /root/vuln.sh`.
- The helper scripts behind `VMDIR` (`ssh-linux.sh`, `ssh-target.sh`,
  `run-linux.sh`, `run-target.sh`) are stored in `helpers/` as they were on
  the author's machine on 2026-11-27, the day they were copied. The key file
  they name (`id_vm`) is not stored. What they do is described below, in the
  section "Written afterwards".

The scripts are a record of the method, not a portable test suite. They assume
two virtual machines reached through helper scripts (`VMDIR`), a closed test
link, and the addresses of our setup.

## The scenes

FreeBSD, in each repetition:

- `a`: the module, audit and DTrace at once; a login over SSH, then an
  intrusion through a deliberately vulnerable service
- `b`: audit and DTrace without the module, the jail created with
  `allow.setaudit`; a login over SSH
- `c`: the module and audit with `accept` and process creation; three clients
  at once

Linux, in each repetition: a login over SSH and the vulnerable service with
bpftrace and auditd; then three clients at once with `accept` and process
creation audited.

## Two FreeBSD series

The FreeBSD scenes were run twice, ten repetitions each.

In the first series (`freebsd-first-series.tar.xz`) the DTrace process of each
run was not stopped: the stop command sent SIGINT, which a background job of a
non-interactive shell ignores. The earlier processes kept tracing during later
runs and wrote to a file that had already been removed. The records compared
are those of the process started for that run.

`freebsd-lib.sh` now sends SIGTERM and reports, in each run, how many tracers
are running and how many are left afterwards. The second series
(`freebsd.tar.xz`) was made with it; `run.txt` in each repetition shows one
tracer running, none left, and no drops. The report uses the second series.
The matches and attributions of the first were the same: `freebsd-rep.py` run
on each of its ten repetitions (`results-freebsd-first-series.txt`) gives full
agreement between the tools within every run and 24 of 24 marked executions
with the right address; four runs (05, 06, 08, 09) have 13 executions and two
of them (05, 08) have 264 opens in the login scene, against 12 and 259 in the
second series, and in one further run the repeat without the module ran 13
executions.

## Written afterwards, not a record of the runs

Everything in this section was written on 2026-11-27, after the runs, from
the files named. It is a description for a reader who wants to build a
comparable setup. It is not a log of what was typed when the runs were made,
and where the stored files do not say something, this section says so.

### The helper scripts behind `VMDIR`

The harness (`freebsd-run.sh`, `linux-run.sh`) calls two helper scripts and
uses one key file from the directory `VMDIR`. On the author's machine that
directory is outside this repository. The four files described here were last
modified on 2026-11-21, before the runs (2026-11-23); copies of them, made on
2026-11-27, are in `helpers/`. Keys and key material are not reproduced.

| File | What it does |
|---|---|
| `ssh-target.sh` | runs its arguments as a command on the FreeBSD test machine: `ssh` as `root` to `127.0.0.1`, port 2222, with the private key file `id_vm` that lies beside the script; host key checking off, known-hosts file `/dev/null`, no agent, log level `ERROR` |
| `ssh-linux.sh` | the same for the Linux test machine: user `ubuntu`, port 2223, the same key file |
| `run-target.sh` | starts the FreeBSD test machine: `qemu-system-x86_64` with KVM, `-cpu host -smp 8 -m 8G`, one virtio disk image, a cloud-init seed image as CD-ROM, a user-mode network device that forwards `127.0.0.1:2222` to port 22 of the guest, a second virtio network device on a tap interface (`aodtap0`, the closed test link; the guest's address there is 10.99.0.2), no display, serial console to a file |
| `run-linux.sh` | starts the Linux test machine in the same way: `-smp 2 -m 2G`, forwarding `127.0.0.1:2223`, tap interface `aodtap1` (the guest's address there is 10.99.0.6) |

The harness also copies files with `scp`, using the same key and ports; those
command lines are in `freebsd-run.sh` and `linux-run.sh`.

### A container of the kind used (Linux)

The commands that created the container were not saved. The stored facts
are: the header of the container's config file, read after the runs
(`config-read-after-the-fact/linux/audit-and-container-config.txt`), which
names the template `lxc-download` and the parameters `-d ubuntu -r noble -a
amd64`; the same file, which gives the name `hp`, the root file system
`dir:/var/lib/lxc/hp/rootfs` and the identifier maps `u 0 100000 65536` and
`g 0 100000 65536`; LXC 6.0.6 in the version listing of that file; the
address of the container, 10.0.3.229, in `linux-run.sh`; the bridge `lxcbr0`
with 10.0.3.1 in `linux-one.sh`; and the process title of the service (see
above). A command sequence that would produce a container of this kind:

```
sudo lxc-create -n hp -t download -- -d ubuntu -r noble -a amd64
sudo lxc-start -n hp
# copy ../lxc/vuln.sh to /root/vuln.sh inside the container, install socat there, then:
sudo lxc-attach -n hp -- socat TCP-LISTEN:1524,fork,reuseaddr EXEC:"sh /root/vuln.sh"
```

Not known from the stored files: whether these were the commands; where the
identifier maps came from (the config includes `/etc/lxc/default.conf`, which
is not stored); how the packages inside the container were installed; and
how the container got its address. The scene scripts also need, inside the
container, an SSH server that accepts `root` with the key `~/.ssh/id_hp` of
the test machine's user (`../lxc/session.sh`) and a user `foo` whose
password the login scene changes; how these were set up was not saved.

### Nmap option lines

The scans are in the repository of the fingerprinting module (aod). The
command lines of the ten-scan series and of the IPv6 series were not stored
with their outputs. That repository's notes give them as follows:

- ten-scan series: "Nmap 7.98, `-O`, from a prober on the same closed link"
  (`freebsd/jail/README.md`, section "Measurement");
- IPv6 series: "`nmap -6 -O`, five per setting, with the IPv4 scans taken in
  the same session" (`test/README.md`);
- the five legacy settings: `nmap -O -n -Pn -p 22,23 --osscan-guess
  10.99.0.2`, stored as a script (`test/results/personalities-2001/scan.sh`);
  the script kept for single scans of the host (`test/scripts/scan.sh`) uses
  the same options.

Every stored output shows which ports were found open and closed (22 and 23;
135 and 23 for the Windows reference), and names Nmap 7.98 in its first line.

### Where the facts of the test environment come from

Moved here from the text of the article on 2026-11-27. The article states the
facts; this list says which stored file each comes from.

- *The two test machines.* FreeBSD 15.1-RELEASE-p7 is printed by `uname` in
  `../conceal/part1-conceal.txt`. The sizes of the virtual machines (8 virtual
  CPUs and 8 GB; 2 virtual CPUs and 2 GB) are the values in the two scripts
  that start the machines (`helpers/run-target.sh`, `helpers/run-linux.sh`),
  which were last modified on 2026-11-21, two days before the repeated runs.
  No transcript of the runs prints the sizes.
- *The system inside the container* is named in the stored session
  transcript of each Linux run (`linux/NN/session1.txt`), whose first line is
  "Welcome to Ubuntu 24.04.5 LTS".
- *The versions of bpftrace (0.25.0) and LXC (6.0.6)* are printed in a listing
  read from the Linux machine on 2026-11-27, after the experiments
  (`config-read-after-the-fact/linux/audit-and-container-config.txt`); the
  container's configuration file as read on that day names the parameters of
  the template it was created from (`-d ubuntu -r noble -a amd64`).
- *What was read afterwards.* The container's configuration file and the
  configuration of the audit daemons were not saved when the scenes were run.
  They were read from the two machines on 2026-11-27 (the FreeBSD machine had
  been rebooted in between) and are kept in `config-read-after-the-fact/`;
  they are not a record of the runs. Known only from that reading are the
  other lines of the FreeBSD audit control file, the configuration of the
  Linux audit daemon (its log format is `ENRICHED`), the Linux audit rules
  file, and the container's configuration file. On FreeBSD the harness put
  the earlier audit control file back after each scene.
- *The Nmap command lines.* Those of the ten-scan series and of the IPv6
  series are not stored with their results; the notes of the aod repository
  give `nmap -O` and `nmap -6 -O` (quoted under "Nmap option lines" above).
  The script kept for single scans of the host uses the command line of the
  legacy-settings series.
- *The fingerprint database.* No stored scan output names the database file
  that Nmap loaded. The article takes it to be the file installed with
  Nmap 7.98 on the prober (package `nmap-common` 7.98+dfsg-1), whose SHA-256
  was taken on 2026-11-27, after the scans, and is kept in aod
  `test/osdb/nmap-os-db.sha256.txt`.
- *The module revisions at each scan series* were not recorded with the
  outputs. The history of the aod repository shows the ten-scan series
  committed on 2026-11-23 and the IPv6 hooks on 2026-11-24.
- *The jails.* The jail of the repeated scenes is created by `freebsd-lib.sh`
  (`jail_up`); the jail of the containment check by
  `../conceal/part2-jail.sh`; the two jails of the audit-condition test by
  `../conceal/part4-auditcond.sh`. The jail of the timing runs is named in
  `../perf/bench.sh` (`jexec b`), but the command that created it was not
  kept; for the two jails of the IPv6 scan series no creation command is
  stored.

### What the records do not hold

- the configuration of the Linux container and of the audit daemons as they
  were at the time of the runs (only the reading of 2026-11-27 exists);
- the commands that created the container and started its service, and the
  files that the container's configuration includes;
- the key file the helper scripts name;
- the commands of the two Linux timing workloads and of the FreeBSD loop of
  20 passes (`../perf/w2x20.txt`);
- the command lines of the ten-scan and IPv6 scan series, the module revisions
  at each scan series, and the Nmap database file itself;
- what the system log and the login accounting held about the connections of
  the repeated runs.
