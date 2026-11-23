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
The matches and attributions of the first were the same.
