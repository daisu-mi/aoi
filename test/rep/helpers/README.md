# Helper scripts behind `VMDIR`

These four files are the author's local helper scripts as they were on
2026-11-27, the day they were copied here from the author's machine
(`ssh-target.sh`, `ssh-linux.sh`, `run-target.sh`, `run-linux.sh`; last
modified there on 2026-11-21). The harness (`../freebsd-run.sh`,
`../linux-run.sh`) expects them in the directory named by `VMDIR`, together
with a private key file `id_vm`. The key file is not stored here: the scripts
refer to it by name only, and a replication needs its own key, disk images
(`target.qcow2`, `linux.qcow2`) and cloud-init seed images. The comments in
the two `run-` scripts are in Japanese; what each script does is described in
English in `../README.md`, section "Written afterwards".
