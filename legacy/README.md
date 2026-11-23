# The 2001 version

`honey-linux-2.2.16.patch` is the recorder as it was in September 2001: a
patch to the Linux 2.2.16 kernel. It is the implementation described in

- 宮本 大輔, 久保 聡之, 大江 将史, 門林 雄基, "侵入監視のための Honeypot の実装と評価",
  コンピュータセキュリティシンポジウム (CSS2001), 2001 (in Japanese).
  <https://www.iplove.net/pdf/miyamoto-css2001.pdf>

It is kept as a historical record. It is not maintained and is not meant to be
run today.

## What it records

Every change is marked in the source with the comment `/* honey so sweet ... */`.

| Event | Where |
|---|---|
| open | `fs/open.c` |
| exec | `fs/exec.c` |
| read | `mm/filemap.c` |
| write | `fs/ext2/file.c` |
| signals | `kernel/signal.c` |
| pseudo terminal input and output | `drivers/char/tty_io.c` |
| address of the remote peer | `net/ipv4/`, `net/ipv6/`, stored in the task structure (`include/linux/sched.h`) |
| messages to a console terminal | `kernel/printk.c`, `drivers/char/console.c` |

The log files are placed under `/usr/share/locale/` with the names of locale
files (`include/linux/fs.h`).

## How the patch was made

The patch was produced in 2026 from an archive of the kernel tree dated
August 2001. That tree differs from the stock `linux-2.2.16.tar.gz` of
kernel.org in 18 files, and the patch is the difference in those files.
Applying it to the stock source gives the files of the archive byte for byte:

```
tar xzf linux-2.2.16.tar.gz
cd linux
patch -p1 < ../honey-linux-2.2.16.patch
```

The one change outside the recorder is `EXTRAVERSION = -5k` in the top
`Makefile`, the version string of the distribution the kernel was built for
(Kondara MNU/Linux). A debugging `printk` left in `fs/fcntl.c` is kept as it
was.

The version described in the 2002 master's thesis recorded the same events.
Its main difference was the destination of the log: a hidden disk device in
place of these files. Its source has not been found, and the hidden disk
device was the work of a co-author. The FreeBSD module in this repository
follows that later design: it can write its log to a raw disk.

## License

The patch modifies files of the Linux kernel and is under the GNU General
Public License, version 2, as the kernel is.
