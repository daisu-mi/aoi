/*
 * honey: host-based honeypot recorder for FreeBSD, as a loadable module.
 *
 * A reconstruction of the 2001 "honey" Linux 2.2.16 kernel patch.  The
 * original patched the kernel source; this one leaves the kernel untouched.
 *
 * Stage 1: record open and exec.
 * Stage 2: put the address of the remote peer on every record.
 * Stage 3: optionally keep the log on a raw disk device instead of a file.
 * Stage 4: record signals sent by processes.
 * Stage 5: record everything that goes in and out of pseudo terminals.
 * Stage 6: show the administrator what is going on, on a console terminal.
 * Stage 7: record reads and writes of regular files.
 *
 *   exec  MAC framework hook (mpo_vnode_check_exec).  The argument list is
 *         already in the kernel at that point.
 *   open  wrappers around the open and openat system calls.  A MAC hook
 *         sees only the vnode, and the kernel cannot always turn a vnode
 *         back into a name: every open with O_CREAT purges the name cache
 *         entry of the file.  The wrapper has the path as the caller gave
 *         it, and it also sees opens that fail.
 *
 *   read, write  MAC framework hooks (mpo_vnode_check_read and _write), for
 *         regular files.  A run of reads (or writes) of one file by one
 *         process is recorded once.
 *   signal  MAC framework hook (mpo_proc_check_signal): one process asks to
 *         signal another.  Signals the kernel raises itself do not pass
 *         here.
 *   tty   A tty hook (the mechanism snp(4) uses) on every pseudo terminal,
 *         attached when its slave side is opened.  Input is what the
 *         master side feeds in, i.e. what the remote user typed, including
 *         text that is never echoed such as passwords.  Output is what the
 *         master side takes out, i.e. what the remote user sees.  An
 *         encrypted connection does not matter: the terminal carries the
 *         clear text.  This was the main point of the 2001 paper.
 *   peer  A socket that came out of a listening socket is remembered (by
 *         the address of its MAC label; see honey_socket_newconn).  When a process reads from such a socket, the
 *         peer address of the connection becomes the address of that
 *         process, and its children inherit it at fork.  The 2001 code
 *         stored the source address of each received packet in whatever
 *         process happened to be running; this is the same idea with the
 *         right process.
 *
 * Neither place writes the log.  They queue a small record; a kernel
 * process turns it into a text line and appends it to the log.
 *
 * When the tunable security.mac.honey.alertdev names a terminal (ttyv1,
 * ttyu0, ...), the worker also shows activity there as it happens: the
 * output of pseudo terminals as the remote user sees it, and one line for
 * each exec and signal.  This is the "warning" function of the 2001 design.
 *
 * The log is a file (security.mac.honey.logfile) or, when the tunable
 * security.mac.honey.logdev names a disk, that disk itself.  The disk is
 * written through GEOM with no file system on it, so the log is not a file
 * anywhere and nothing is mounted.  Layout: sector 0 is a header (struct
 * honey_rawhdr), the text follows from sector 1.  When the disk is full the
 * newest records are dropped, so the start of an intrusion is kept.
 *
 * When that disk is a whole disk (GEOM class DISK), the worker hands its
 * I/O requests straight to the disk driver instead of sending them through
 * GEOM (tunable security.mac.honey.rawdirect, on by default).  The kernel
 * counts disk I/O in the layer just above the driver, so these writes never
 * reach the counters that iostat and gstat show.  The 2001 hidden disk
 * device subtracted what it wrote from the write statistics; here nothing
 * is added in the first place.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/capsicum.h>
#include <sys/imgact.h>
#include <sys/ucred.h>
#include <sys/jail.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/eventhandler.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/conf.h>
#include <sys/tty.h>
#include <sys/ttyhook.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#include <sys/bio.h>
#include <sys/buf.h>

#include <geom/geom.h>
#include <geom/geom_disk.h>

#include <security/mac/mac_policy.h>

#define	HONEY_TEXT	768	/* bytes of free text kept per record */
#define	HONEY_LINE	2048	/* longest log line */
#define	HONEY_QMAX	8192	/* records waiting; beyond this we drop */

enum honey_kind { HONEY_OPEN, HONEY_EXEC, HONEY_SIGNAL, HONEY_TTYIN,
    HONEY_TTYOUT, HONEY_READ, HONEY_WRITE };

/*
 * The two ends of the connection a process is serving: u is the remote
 * peer, l is our own address it came in on.  af is 0 when there is none.
 */
union honey_ip {
	struct in_addr	a4;
	struct in6_addr	a6;
};
struct honey_addr {
	sa_family_t	af;
	union honey_ip	u;
	union honey_ip	l;
	in_port_t	uport;	/* network byte order, as in the inpcb */
	in_port_t	lport;
};

struct honey_rec {
	STAILQ_ENTRY(honey_rec) link;
	struct timeval	tv;
	enum honey_kind	kind;
	pid_t		pid;
	uid_t		uid;
	char		comm[MAXCOMLEN + 1];
	struct honey_addr peer;
	struct vnode	*vp;	/* the file; referenced, may be NULL */
	struct vnode	*dvp;	/* where a relative path starts; same */
	int		flags;	/* open: flags.  signal: signal number */
	int		error;	/* open: result.  signal: target pid */
	int		len;	/* tty: bytes of raw data in text[] */
	char		tty[16];
	char		text[HONEY_TEXT];
};

static MALLOC_DEFINE(M_HONEY, "honey", "honeypot recorder");

static struct mtx honey_mtx;
MTX_SYSINIT(honey_mtx, &honey_mtx, "honey queue", MTX_DEF);

static STAILQ_HEAD(, honey_rec) honey_q = STAILQ_HEAD_INITIALIZER(honey_q);
static int honey_qlen;
static int honey_stopping;
static struct proc *honey_proc;

static int honey_enabled = 1;
static char honey_logfile[MAXPATHLEN] = "/var/log/honey.log";
static char honey_logdev[64] = "";
static int honey_rawdirect = 1;
static char honey_alertdev[64] = "";
static u_long honey_logged;
static u_long honey_dropped;
static int honey_jailonly;
static int honey_logerr;

SYSCTL_DECL(_security_mac);
static SYSCTL_NODE(_security_mac, OID_AUTO, honey, CTLFLAG_RW | CTLFLAG_MPSAFE,
    0, "honeypot recorder");
SYSCTL_INT(_security_mac_honey, OID_AUTO, enabled, CTLFLAG_RW,
    &honey_enabled, 0, "record events");
SYSCTL_INT(_security_mac_honey, OID_AUTO, jailonly, CTLFLAG_RWTUN,
    &honey_jailonly, 0, "record only what happens inside jails");
SYSCTL_STRING(_security_mac_honey, OID_AUTO, logfile, CTLFLAG_RDTUN,
    honey_logfile, sizeof(honey_logfile), "log file");
SYSCTL_STRING(_security_mac_honey, OID_AUTO, logdev, CTLFLAG_RDTUN,
    honey_logdev, sizeof(honey_logdev),
    "raw disk to log to instead of the file, e.g. md0");
SYSCTL_INT(_security_mac_honey, OID_AUTO, rawdirect, CTLFLAG_RDTUN,
    &honey_rawdirect, 0,
    "hand log writes straight to the disk driver, below the I/O statistics");
SYSCTL_STRING(_security_mac_honey, OID_AUTO, alertdev, CTLFLAG_RDTUN,
    honey_alertdev, sizeof(honey_alertdev),
    "terminal to show activity on, e.g. ttyv1");
SYSCTL_INT(_security_mac_honey, OID_AUTO, queued, CTLFLAG_RD,
    &honey_qlen, 0, "records waiting to be written");
SYSCTL_ULONG(_security_mac_honey, OID_AUTO, logged, CTLFLAG_RD,
    &honey_logged, 0, "records written");
SYSCTL_ULONG(_security_mac_honey, OID_AUTO, dropped, CTLFLAG_RD,
    &honey_dropped, 0, "records dropped");
SYSCTL_INT(_security_mac_honey, OID_AUTO, logerr, CTLFLAG_RD,
    &honey_logerr, 0, "last error from the log file");

/*
 * Peer address of each process.
 */
struct honey_peer {
	LIST_ENTRY(honey_peer) link;
	pid_t		pid;
	struct honey_addr addr;
};

#define	HONEY_PHASH	256
static LIST_HEAD(, honey_peer) honey_ptab[HONEY_PHASH];
static struct mtx honey_pmtx;
MTX_SYSINIT(honey_pmtx, &honey_pmtx, "honey peers", MTX_DEF);
static int honey_pclosed;	/* table torn down; take no new entries */
static eventhandler_tag honey_fork_tag, honey_exit_tag;

/*
 * Sockets that came out of a listening socket, identified by the address
 * of their MAC label.  The obvious way, a private slot inside the label,
 * does not work for a module that gets unloaded: the framework never gives
 * a slot back, and there are only four.
 */
struct honey_in {
	LIST_ENTRY(honey_in) link;
	struct label	*label;
};

#define	HONEY_IHASH	1024
#define	HONEY_IHASHOF(l)	(((uintptr_t)(l) >> 6) % HONEY_IHASH)
static LIST_HEAD(, honey_in) honey_itab[HONEY_IHASH];

static struct honey_in *
honey_in_find(struct label *label)
{
	struct honey_in *hi;

	mtx_assert(&honey_pmtx, MA_OWNED);
	LIST_FOREACH(hi, &honey_itab[HONEY_IHASHOF(label)], link)
		if (hi->label == label)
			return (hi);
	return (NULL);
}

static struct honey_peer *
honey_peer_find(pid_t pid)
{
	struct honey_peer *hp;

	mtx_assert(&honey_pmtx, MA_OWNED);
	LIST_FOREACH(hp, &honey_ptab[pid % HONEY_PHASH], link)
		if (hp->pid == pid)
			return (hp);
	return (NULL);
}

static void
honey_peer_set(pid_t pid, const struct honey_addr *addr)
{
	struct honey_peer *hp;

	mtx_lock(&honey_pmtx);
	if ((hp = honey_peer_find(pid)) == NULL && !honey_pclosed) {
		hp = malloc(sizeof(*hp), M_HONEY, M_NOWAIT);
		if (hp != NULL) {
			hp->pid = pid;
			LIST_INSERT_HEAD(&honey_ptab[pid % HONEY_PHASH], hp,
			    link);
		}
	}
	if (hp != NULL)
		hp->addr = *addr;
	mtx_unlock(&honey_pmtx);
}

static void
honey_peer_get(pid_t pid, struct honey_addr *addr)
{
	struct honey_peer *hp;

	mtx_lock(&honey_pmtx);
	if ((hp = honey_peer_find(pid)) != NULL)
		*addr = hp->addr;
	else
		addr->af = 0;
	mtx_unlock(&honey_pmtx);
}

/*
 * A process that waits for connections is a server.  Whatever address it
 * inherited from the session that started it says nothing about the
 * connections it will hand to its children.
 */
static int
honey_socket_check_accept(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct honey_peer *hp;

	mtx_lock(&honey_pmtx);
	if ((hp = honey_peer_find(curthread->td_proc->p_pid)) != NULL)
		LIST_REMOVE(hp, link);
	mtx_unlock(&honey_pmtx);
	free(hp, M_HONEY);
	return (0);
}

static void
honey_peer_fork(void *arg, struct proc *p1, struct proc *p2, int flags)
{
	struct honey_addr addr;

	honey_peer_get(p1->p_pid, &addr);
	if (addr.af != 0)
		honey_peer_set(p2->p_pid, &addr);
}

static void
honey_peer_exit(void *arg, struct proc *p)
{
	struct honey_peer *hp;

	mtx_lock(&honey_pmtx);
	if ((hp = honey_peer_find(p->p_pid)) != NULL)
		LIST_REMOVE(hp, link);
	mtx_unlock(&honey_pmtx);
	free(hp, M_HONEY);
}

static void
honey_peer_flush(void)
{
	struct honey_peer *hp;
	struct honey_in *hi;
	int i;

	mtx_lock(&honey_pmtx);
	honey_pclosed = 1;
	for (i = 0; i < HONEY_PHASH; i++)
		while ((hp = LIST_FIRST(&honey_ptab[i])) != NULL) {
			LIST_REMOVE(hp, link);
			free(hp, M_HONEY);
		}
	for (i = 0; i < HONEY_IHASH; i++)
		while ((hi = LIST_FIRST(&honey_itab[i])) != NULL) {
			LIST_REMOVE(hi, link);
			free(hi, M_HONEY);
		}
	mtx_unlock(&honey_pmtx);
}

/*
 * Sockets get a label only if some policy has this method.  We put nothing
 * in the label; we need it to exist so that its address identifies the
 * socket in the three methods below.
 */
static int
honey_socket_init_label(struct label *label, int flag)
{
	return (0);
}

static void
honey_socket_destroy_label(struct label *label)
{
	struct honey_in *hi;

	mtx_lock(&honey_pmtx);
	if ((hi = honey_in_find(label)) != NULL)
		LIST_REMOVE(hi, link);
	mtx_unlock(&honey_pmtx);
	free(hi, M_HONEY);
}

/* A connection has arrived on a listening socket. */
static void
honey_socket_newconn(struct socket *oldso, struct label *oldsolabel,
    struct socket *newso, struct label *newsolabel)
{
	struct honey_in *hi;

	if (newsolabel == NULL)
		return;
	if ((hi = malloc(sizeof(*hi), M_HONEY, M_NOWAIT)) == NULL)
		return;
	hi->label = newsolabel;
	mtx_lock(&honey_pmtx);
	if (honey_pclosed || honey_in_find(newsolabel) != NULL) {
		mtx_unlock(&honey_pmtx);
		free(hi, M_HONEY);
		return;
	}
	LIST_INSERT_HEAD(&honey_itab[HONEY_IHASHOF(newsolabel)], hi, link);
	mtx_unlock(&honey_pmtx);
}

/* A process is about to read from a socket. */
static int
honey_socket_check_receive(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	struct honey_addr addr;
	struct inpcb *inp;
	int af, inbound;

	if (solabel == NULL)
		return (0);
	mtx_lock(&honey_pmtx);
	inbound = honey_in_find(solabel) != NULL;
	mtx_unlock(&honey_pmtx);
	if (!inbound)
		return (0);
	af = so->so_proto->pr_domain->dom_family;
	if ((af != AF_INET && af != AF_INET6) || (inp = sotoinpcb(so)) == NULL)
		return (0);
	if (inp->inp_vflag & INP_IPV6) {
		addr.af = AF_INET6;
		addr.u.a6 = inp->in6p_faddr;
		addr.l.a6 = inp->in6p_laddr;
		if (IN6_IS_ADDR_UNSPECIFIED(&addr.u.a6))
			return (0);
	} else {
		addr.af = AF_INET;
		addr.u.a4 = inp->inp_faddr;
		addr.l.a4 = inp->inp_laddr;
		if (addr.u.a4.s_addr == INADDR_ANY)
			return (0);
	}
	addr.uport = inp->inp_fport;
	addr.lport = inp->inp_lport;
	honey_peer_set(curthread->td_proc->p_pid, &addr);
	return (0);
}

/*
 * Recording side.  honey_rec_new() and honey_rec_queue() must not sleep:
 * the exec hook runs with the vnode locked.
 */
static struct honey_rec *
honey_rec_new(enum honey_kind kind, struct ucred *cred)
{
	struct honey_rec *r;
	struct proc *p = curthread->td_proc;
	int i;

	/* Our own log writer and other kernel processes are not events. */
	if (!honey_enabled || (p->p_flag & P_SYSTEM) != 0)
		return (NULL);
	/* With jailonly, the host outside the jails is left alone. */
	if (honey_jailonly && !jailed(cred))
		return (NULL);
	r = malloc(sizeof(*r), M_HONEY, M_NOWAIT);
	if (r == NULL) {
		atomic_add_long(&honey_dropped, 1);
		return (NULL);
	}
	microtime(&r->tv);
	r->kind = kind;
	r->pid = p->p_pid;
	r->uid = cred->cr_uid;
	strlcpy(r->comm, p->p_comm, sizeof(r->comm));
	/* the command name is a field of its own: keep the separator out of it */
	for (i = 0; r->comm[i] != '\0'; i++)
		if (r->comm[i] == ',')
			r->comm[i] = '_';
	honey_peer_get(p->p_pid, &r->peer);
	r->vp = r->dvp = NULL;
	r->flags = r->error = r->len = 0;
	r->text[0] = r->tty[0] = '\0';
	return (r);
}

static void
honey_rec_free(struct honey_rec *r)
{
	/*
	 * In the exec hook the caller still holds its own reference, so
	 * this vrele() never drops the last one and never sleeps there.
	 */
	if (r->vp != NULL)
		vrele(r->vp);
	if (r->dvp != NULL)
		vrele(r->dvp);
	free(r, M_HONEY);
}

static void
honey_rec_queue(struct honey_rec *r)
{
	mtx_lock(&honey_mtx);
	if (honey_stopping || honey_qlen >= HONEY_QMAX) {
		mtx_unlock(&honey_mtx);
		atomic_add_long(&honey_dropped, 1);
		honey_rec_free(r);
		return;
	}
	STAILQ_INSERT_TAIL(&honey_q, r, link);
	honey_qlen++;
	wakeup_one(&honey_q);
	mtx_unlock(&honey_mtx);
}

/*
 * read and write
 */
static struct {
	pid_t		pid;
	struct vnode	*vp;		/* for comparison only */
} honey_rwlast[2];			/* protected by honey_mtx */

static void
honey_record_rw(enum honey_kind kind, struct ucred *cred, struct vnode *vp)
{
	struct honey_rec *r;
	pid_t pid = curthread->td_proc->p_pid;
	int i = kind == HONEY_WRITE, same;

	if (vp->v_type != VREG || !honey_enabled ||
	    (curthread->td_proc->p_flag & P_SYSTEM) != 0 ||
	    (honey_jailonly && !jailed(cred)))
		return;
	mtx_lock(&honey_mtx);
	same = honey_rwlast[i].pid == pid && honey_rwlast[i].vp == vp;
	honey_rwlast[i].pid = pid;
	honey_rwlast[i].vp = vp;
	mtx_unlock(&honey_mtx);
	if (same || (r = honey_rec_new(kind, cred)) == NULL)
		return;
	vref(vp);
	r->vp = vp;
	honey_rec_queue(r);
}

static int
honey_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	honey_record_rw(HONEY_READ, active_cred, vp);
	return (0);
}

static int
honey_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vplabel)
{
	honey_record_rw(HONEY_WRITE, active_cred, vp);
	return (0);
}

/*
 * exec
 */

/* Copy count NUL-terminated strings, separated by spaces.  Returns n. */
static size_t
honey_copy_strings(char *dst, size_t n, const char *s, int count,
    const char *endp)
{
	int i;

	for (i = 0; i < count && s < endp; i++) {
		if (i > 0 && n < HONEY_TEXT - 1)
			dst[n++] = ' ';
		for (; s < endp && *s != '\0'; s++)
			if (n < HONEY_TEXT - 1)
				dst[n++] = (*s == '\n' || *s == '\r') ? ' ' : *s;
		s++;
	}
	return (n);
}

static int
honey_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, struct image_params *imgp, struct label *execlabel)
{
	struct honey_rec *r;
	struct image_args *a;
	size_t n;

	/*
	 * The ELF loader checks the run-time linker (ld-elf.so.1) through
	 * this hook too, with no argument list.  That is not an exec.
	 */
	a = imgp->args;
	if (a == NULL)
		return (0);
	if ((r = honey_rec_new(HONEY_EXEC, cred)) == NULL)
		return (0);
	n = 0;
	if (a->begin_argv != NULL) {
		n = honey_copy_strings(r->text, n, a->begin_argv, a->argc,
		    a->endp);
		/* The environment follows, as in the 2002 version. */
		if (a->envc > 0 && n < sizeof(r->text) - 4) {
			memcpy(r->text + n, " | ", 3);
			n = honey_copy_strings(r->text, n + 3,
			    exec_args_get_begin_envv(a), a->envc, a->endp);
		}
	}
	r->text[n] = '\0';
	vref(vp);
	r->vp = vp;
	honey_rec_queue(r);
	return (0);
}

/*
 * signal.  Called with the target process locked.
 */
static int
honey_proc_check_signal(struct ucred *cred, struct proc *proc, int signum)
{
	struct honey_rec *r;

	if ((r = honey_rec_new(HONEY_SIGNAL, cred)) != NULL) {
		r->flags = signum;
		r->error = proc->p_pid;
		strlcpy(r->text, proc->p_comm, sizeof(r->text));
		honey_rec_queue(r);
	}
	return (0);
}

/*
 * Pseudo terminals.  All hook functions run with the tty locked.
 */
#define	HONEY_TTYCHUNK	180	/* raw bytes per record; 4x fits in text[] */

struct honey_tty {
	LIST_ENTRY(honey_tty) link;
	struct tty	*tp;
	int		inlen;
	char		in[HONEY_TTYCHUNK];	/* input not yet recorded */
};

static LIST_HEAD(, honey_tty) honey_ttys = LIST_HEAD_INITIALIZER(honey_ttys);
static struct mtx honey_tmtx;		/* taken after the tty lock */
MTX_SYSINIT(honey_tmtx, &honey_tmtx, "honey ttys", MTX_DEF);
static int honey_tclosed;

static void
honey_tty_record(struct tty *tp, enum honey_kind kind, const char *buf,
    size_t len)
{
	struct honey_rec *r;
	size_t n;

	for (; len > 0; buf += n, len -= n) {
		n = MIN(len, HONEY_TTYCHUNK);
		if ((r = honey_rec_new(kind, curthread->td_ucred)) == NULL)
			return;
		strlcpy(r->tty, tty_devname(tp), sizeof(r->tty));
		memcpy(r->text, buf, n);
		r->len = n;
		honey_rec_queue(r);
	}
}

static void
honey_tty_flush(struct tty *tp, struct honey_tty *sc)
{
	if (sc->inlen > 0) {
		honey_tty_record(tp, HONEY_TTYIN, sc->in, sc->inlen);
		sc->inlen = 0;
	}
}

static th_rint_t honey_tty_rint;
static th_rint_done_t honey_tty_rint_done;
static th_getc_capture_t honey_tty_getc_capture;
static th_close_t honey_tty_close;

static struct ttyhook honey_tty_hook = {
	.th_rint = honey_tty_rint,
	.th_rint_done = honey_tty_rint_done,
	.th_getc_capture = honey_tty_getc_capture,
	.th_close = honey_tty_close,
};
/* The same without th_rint; see honey_tty_rint(). */
static struct ttyhook honey_tty_inner = {
	.th_rint_done = honey_tty_rint_done,
	.th_getc_capture = honey_tty_getc_capture,
	.th_close = honey_tty_close,
};

/*
 * One input character.  A th_rint method replaces the line discipline: the
 * kernel hands the character to the hook and does nothing more with it.  We
 * only want to look, so we take a copy and pass the character on to the
 * normal ttydisc_rint(), with our th_rint out of the way for that call.
 * The tty stays locked throughout, so nobody sees the swap.
 */
static int
honey_tty_rint(struct tty *tp, char c, int flags)
{
	struct honey_tty *sc = ttyhook_softc(tp);
	int error;

	if (flags == 0) {
		if (sc->inlen == sizeof(sc->in))
			honey_tty_flush(tp, sc);
		sc->in[sc->inlen++] = c;
	}
	tp->t_hook = &honey_tty_inner;
	error = ttydisc_rint(tp, c, flags);
	if (tp->t_hook == &honey_tty_inner)
		tp->t_hook = &honey_tty_hook;
	return (error);
}

/* The master side has finished one write. */
static void
honey_tty_rint_done(struct tty *tp)
{
	honey_tty_flush(tp, ttyhook_softc(tp));
}

/* The master side has taken output. */
static void
honey_tty_getc_capture(struct tty *tp, const void *buf, size_t len)
{
	honey_tty_record(tp, HONEY_TTYOUT, buf, len);
}

/*
 * Last close of the terminal.  ttyhook_unregister() is not for here: it
 * releases the tty, and our caller still uses it.
 */
static void
honey_tty_close(struct tty *tp)
{
	struct honey_tty *sc = ttyhook_softc(tp);

	honey_tty_flush(tp, sc);
	tp->t_flags &= ~TF_HOOK;
	tp->t_hook = NULL;
	ttydisc_optimize(tp);
	mtx_lock(&honey_tmtx);
	LIST_REMOVE(sc, link);
	mtx_unlock(&honey_tmtx);
	free(sc, M_HONEY);
}

/* A character device was opened.  If it is a pseudo terminal, hook it. */
static void
honey_tty_attach(struct vnode *vp)
{
	struct honey_tty *sc;
	struct cdevsw *cdp;
	struct cdev *dev;
	struct tty *tp;
	const char *name;
	int ref;

	if (vp->v_type != VCHR ||
	    (cdp = devvn_refthread(vp, &dev, &ref)) == NULL)
		return;
	name = devtoname(dev);
	if ((cdp->d_flags & D_TTY) != 0 && strncmp(name, "pts/", 4) == 0 &&
	    strchr(name, '.') == NULL &&
	    (sc = malloc(sizeof(*sc), M_HONEY, M_NOWAIT | M_ZERO)) != NULL) {
		tp = dev->si_drv1;
		tty_lock(tp);
		mtx_lock(&honey_tmtx);
		if (!tty_gone(tp) && (tp->t_flags & TF_HOOK) == 0 &&
		    !honey_tclosed) {
			sc->tp = tp;
			tp->t_flags |= TF_HOOK;
			tp->t_hook = &honey_tty_hook;
			tp->t_hooksoftc = sc;
			ttydisc_optimize(tp);
			LIST_INSERT_HEAD(&honey_ttys, sc, link);
			sc = NULL;
		}
		mtx_unlock(&honey_tmtx);
		tty_unlock(tp);
		free(sc, M_HONEY);
	}
	dev_relthread(dev, ref);
}

/* Unhook every terminal; for unload. */
static void
honey_tty_detach_all(void)
{
	struct honey_tty *sc;
	struct tty *tp;

	mtx_lock(&honey_tmtx);
	honey_tclosed = 1;
	while ((sc = LIST_FIRST(&honey_ttys)) != NULL) {
		tp = sc->tp;
		/*
		 * The lock order is tty first.  If the tty is busy, let go
		 * and look again: it may be in honey_tty_close() waiting
		 * for our mutex, and will then be off the list.
		 */
		if (!mtx_trylock(tp->t_mtx)) {
			mtx_unlock(&honey_tmtx);
			pause("hnytty", 1);
			mtx_lock(&honey_tmtx);
			continue;
		}
		LIST_REMOVE(sc, link);
		mtx_unlock(&honey_tmtx);
		ttyhook_unregister(tp);		/* unlocks the tty */
		free(sc, M_HONEY);
		mtx_lock(&honey_tmtx);
	}
	mtx_unlock(&honey_tmtx);
}

/*
 * open
 */
static sy_call_t *honey_orig_open;
static sy_call_t *honey_orig_openat;
static volatile u_int honey_inflight;	/* threads inside our wrappers */

static void
honey_record_open(struct thread *td, int dirfd, const char *upath, int flags,
    int error)
{
	struct honey_rec *r;
	struct pwd *pwd;
	char *p;

	if (error == ERESTART || error == EJUSTRETURN)
		return;
	if ((r = honey_rec_new(HONEY_OPEN, td->td_ucred)) == NULL)
		return;
	r->flags = flags;
	r->error = error;
	if (copyinstr(upath, r->text, sizeof(r->text), NULL) != 0)
		strlcpy(r->text, "?", sizeof(r->text));
	for (p = r->text; *p != '\0'; p++)
		if (*p == '\n' || *p == '\r')
			*p = ' ';
	/* The file itself, when the open worked. */
	if (error == 0 &&
	    fgetvp(td, td->td_retval[0], &cap_no_rights, &r->vp) != 0)
		r->vp = NULL;
	if (r->vp != NULL)
		honey_tty_attach(r->vp);
	/* The directory a relative path starts from. */
	if (r->text[0] != '/') {
		if (dirfd == AT_FDCWD) {
			pwd = pwd_hold(td);
			r->dvp = pwd->pwd_cdir;
			vref(r->dvp);
			pwd_drop(pwd);
		} else if (fgetvp(td, dirfd, &cap_no_rights, &r->dvp) != 0)
			r->dvp = NULL;
	}
	honey_rec_queue(r);
}

static int
honey_sys_open(struct thread *td, void *v)
{
	struct open_args *uap = v;
	int error;

	atomic_add_int(&honey_inflight, 1);
	error = honey_orig_open(td, v);
	honey_record_open(td, AT_FDCWD, uap->path, uap->flags, error);
	atomic_subtract_int(&honey_inflight, 1);
	return (error);
}

static int
honey_sys_openat(struct thread *td, void *v)
{
	struct openat_args *uap = v;
	int error;

	atomic_add_int(&honey_inflight, 1);
	error = honey_orig_openat(td, v);
	honey_record_open(td, uap->fd, uap->path, uap->flag, error);
	atomic_subtract_int(&honey_inflight, 1);
	return (error);
}

static void
honey_syscalls_hook(void)
{
	honey_orig_open = sysent[SYS_open].sy_call;
	honey_orig_openat = sysent[SYS_openat].sy_call;
	sysent[SYS_open].sy_call = honey_sys_open;
	sysent[SYS_openat].sy_call = honey_sys_openat;
}

/*
 * Put the system calls back and wait until no thread is left inside a
 * wrapper.  An open can block for a long time (a FIFO, a tty), so give up
 * after a while and stay loaded rather than pull the code from under it.
 */
static int
honey_syscalls_unhook(void)
{
	int i;

	sysent[SYS_open].sy_call = honey_orig_open;
	sysent[SYS_openat].sy_call = honey_orig_openat;
	for (i = 0; i < 50 && honey_inflight != 0; i++)
		pause("hnyuhk", hz / 10);
	if (honey_inflight != 0) {
		sysent[SYS_open].sy_call = honey_sys_open;
		sysent[SYS_openat].sy_call = honey_sys_openat;
		return (EBUSY);
	}
	/* Let a thread that just left the counter finish its return. */
	pause("hnyuhk", hz / 10);
	return (0);
}

/*
 * The worker: everything below runs in its own kernel process and may sleep.
 */
static struct vnode *
honey_log_open(void)
{
	struct nameidata nd;
	int error, flags;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, honey_logfile);
	flags = FWRITE | O_CREAT | O_APPEND;
	error = vn_open(&nd, &flags, 0600, NULL);
	if (error != 0) {
		honey_logerr = error;
		return (NULL);
	}
	NDFREE_PNBUF(&nd);
	VOP_UNLOCK(nd.ni_vp);
	return (nd.ni_vp);
}

static const char *
honey_open_mode(int flags, char *buf)
{
	int n = 0;

	switch (flags & O_ACCMODE) {
	case O_RDONLY:
		buf[n++] = 'r';
		break;
	case O_WRONLY:
		buf[n++] = 'w';
		break;
	case O_RDWR:
		buf[n++] = 'r';
		buf[n++] = 'w';
		break;
	default:
		buf[n++] = '-';
	}
	if (flags & O_APPEND)
		buf[n++] = 'a';
	if (flags & O_CREAT)
		buf[n++] = 'c';
	if (flags & O_TRUNC)
		buf[n++] = 't';
	buf[n] = '\0';
	return (buf);
}

/* Append raw terminal data to a line, keeping the line a single line. */
static int
honey_escape(char *line, int len, const char *buf, int n)
{
	static const char hex[] = "0123456789abcdef";
	u_char c;
	int i;

	for (i = 0; i < n && len < HONEY_LINE - 6; i++) {
		c = buf[i];
		if (c == '\\') {
			line[len++] = '\\';
			line[len++] = '\\';
		} else if (c >= 0x20 && c != 0x7f)
			line[len++] = c;	/* printable, and UTF-8 bytes */
		else {
			line[len++] = '\\';
			if (c == '\n')
				line[len++] = 'n';
			else if (c == '\r')
				line[len++] = 'r';
			else if (c == '\t')
				line[len++] = 't';
			else {
				line[len++] = 'x';
				line[len++] = hex[c >> 4];
				line[len++] = hex[c & 15];
			}
		}
	}
	return (len);
}

static void
honey_ntop(sa_family_t af, union honey_ip *ip, char *buf, size_t size)
{
	if (af == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&ip->a6))
		inet_ntop(AF_INET, &ip->a6.s6_addr[12], buf, size);
	else {
		/*
		 * Inside the kernel a link-local address carries the
		 * interface number in its second word.  Take it out.
		 */
		if (af == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&ip->a6))
			ip->a6.s6_addr[2] = ip->a6.s6_addr[3] = 0;
		inet_ntop(af, ip, buf, size);
	}
}

/*
 * Look a path up once, so that the name cache has it again and later
 * records about the same file (read, write) can be turned into a name.
 */
static void
honey_cache_warm(char *path)
{
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, path);
	if (namei(&nd) == 0) {
		NDFREE_PNBUF(&nd);
		vrele(nd.ni_vp);
	}
}

/* Turn a record into one line of text.  Returns its length. */
static char honey_scratch[HONEY_LINE];

static int
honey_format(struct honey_rec *r, char *line)
{
	char *path, *freebuf, *dir, *dfreebuf, mode[8];
	char peer[2 * INET6_ADDRSTRLEN + 24], *full;
	const char *o, *c;
	int len, start;

	/*
	 * remote:port>local:port, or -.  The port tells two connections from
	 * the same address apart.  IPv6 addresses go in brackets.
	 */
	strlcpy(peer, "-", sizeof(peer));
	if (r->peer.af != 0) {
		o = r->peer.af == AF_INET6 ? "[" : "";
		c = r->peer.af == AF_INET6 ? "]" : "";
		len = snprintf(peer, sizeof(peer), "%s", o);
		honey_ntop(r->peer.af, &r->peer.u, peer + len,
		    INET6_ADDRSTRLEN);
		len = strlen(peer);
		len += snprintf(peer + len, sizeof(peer) - len, "%s:%u>%s", c,
		    ntohs(r->peer.uport), o);
		honey_ntop(r->peer.af, &r->peer.l, peer + len,
		    INET6_ADDRSTRLEN);
		len = strlen(peer);
		snprintf(peer + len, sizeof(peer) - len, "%s:%u", c,
		    ntohs(r->peer.lport));
	}

	/* time,address,event,pid,uid,command,detail */
	len = snprintf(line, HONEY_LINE, "%jd.%06ld,%s,",
	    (intmax_t)r->tv.tv_sec, r->tv.tv_usec, peer);

	freebuf = dfreebuf = NULL;
	path = NULL;
	if (r->vp != NULL && vn_fullpath(r->vp, &path, &freebuf) != 0)
		path = NULL;

	switch (r->kind) {
	case HONEY_OPEN:
		len += snprintf(line + len, HONEY_LINE - len, "%s,%d,%u,%s,%s ",
		    r->error == 0 ? "open" : "open-failed", r->pid, r->uid,
		    r->comm, honey_open_mode(r->flags, mode));
		start = len;
		if (path != NULL || r->text[0] == '/')
			/* The kernel's own name for the file, or as given. */
			len += snprintf(line + len, HONEY_LINE - len, "%s",
			    path != NULL ? path : r->text);
		else {
			dir = "?";
			if (r->dvp != NULL &&
			    vn_fullpath(r->dvp, &dir, &dfreebuf) != 0)
				dir = "?";
			len += snprintf(line + len, HONEY_LINE - len, "%s%s%s",
			    dir, dir[1] == '\0' ? "" : "/", r->text);
		}
		if (r->error == 0 && path == NULL && r->vp != NULL &&
		    r->vp->v_type == VREG && len < HONEY_LINE) {
			full = line + start;	/* NUL-terminated by snprintf */
			honey_cache_warm(full);
		}
		if (r->error != 0)
			len += snprintf(line + len, HONEY_LINE - len,
			    " errno=%d", r->error);
		break;
	case HONEY_TTYIN:
	case HONEY_TTYOUT:
		len += snprintf(line + len, HONEY_LINE - len, "%s,%d,%u,%s,%s ",
		    r->kind == HONEY_TTYIN ? "tty-in" : "tty-out", r->pid,
		    r->uid, r->comm, r->tty);
		len = honey_escape(line, len, r->text, r->len);
		break;
	case HONEY_READ:
	case HONEY_WRITE:
		len += snprintf(line + len, HONEY_LINE - len, "%s,%d,%u,%s,%s",
		    r->kind == HONEY_READ ? "read" : "write", r->pid, r->uid,
		    r->comm, path != NULL ? path : "?");
		break;
	case HONEY_SIGNAL:
		len += snprintf(line + len, HONEY_LINE - len,
		    "signal,%d,%u,%s,%d to %d %s", r->pid, r->uid, r->comm,
		    r->flags, r->error, r->text);
		break;
	case HONEY_EXEC:
		len += snprintf(line + len, HONEY_LINE - len,
		    "exec,%d,%u,%s,%s | %s", r->pid, r->uid, r->comm,
		    path != NULL ? path : "?", r->text);
		break;
	}
	if (freebuf != NULL)
		free(freebuf, M_TEMP);
	if (dfreebuf != NULL)
		free(dfreebuf, M_TEMP);
	if (len > HONEY_LINE - 2)
		len = HONEY_LINE - 2;
	/*
	 * File names and arguments come from the intruder.  A newline in one
	 * of them must not start what looks like a new record.  Terminal
	 * data was escaped above.  Only the log writer runs this, so one
	 * buffer is enough.
	 */
	if (r->kind != HONEY_TTYIN && r->kind != HONEY_TTYOUT) {
		memcpy(honey_scratch, line, len);
		len = honey_escape(line, 0, honey_scratch, len);
		if (len > HONEY_LINE - 2)
			len = HONEY_LINE - 2;
	}
	line[len++] = '\n';
	return (len);
}

/*
 * Where the log goes: a file, or a raw disk.
 */
#define	HONEY_MAGIC	"HONEYLOG"

struct honey_rawhdr {
	char		magic[8];
	uint32_t	version;
	uint32_t	sectorsize;
	uint64_t	used;		/* bytes of text after the header */
};

struct honey_out {
	struct vnode	*vp;		/* file */
	struct g_consumer *cp;		/* raw disk */
	struct disk	*dp;		/* its driver, when we go direct */
	u_int		ss;		/* sector size */
	off_t		cap;		/* room for text */
	off_t		used;		/* text written so far */
	char		*sec;		/* the sector being filled */
	int		dirty;
};

static struct g_class honey_gclass = {
	.name = "HONEY",
	.version = G_VERSION,
};
static volatile int honey_raw_gone;	/* the disk went away under us */

static void
honey_g_orphan(struct g_consumer *cp)
{
	g_topology_assert();
	honey_raw_gone = 1;
	g_wither_geom_close(cp->geom, ENXIO);
}

/*
 * One request straight to the disk driver.  This is what g_disk_start()
 * does for a read or write, minus the devstat calls around it.
 */
static int
honey_disk_io(struct disk *dp, int cmd, off_t offset, void *data, size_t len)
{
	struct bio *bp;
	int error;

	bp = g_alloc_bio();
	bp->bio_cmd = cmd;
	bp->bio_offset = offset;
	bp->bio_length = bp->bio_bcount = len;
	bp->bio_data = data;
	bp->bio_pblkno = offset / dp->d_sectorsize;
	bp->bio_disk = dp;
	bp->bio_done = NULL;		/* biodone() then wakes biowait() */
	dp->d_strategy(bp);
	error = biowait(bp, "hnyio");
	g_destroy_bio(bp);
	return (error);
}

static int
honey_raw_write(struct honey_out *o, off_t offset, void *data, size_t len)
{
	if (o->dp != NULL)
		return (honey_disk_io(o->dp, BIO_WRITE, offset, data, len));
	return (g_write_data(o->cp, offset, data, len));
}

static int
honey_raw_read(struct honey_out *o, off_t offset, void *data, size_t len)
{
	void *buf;
	int error;

	if (o->dp != NULL)
		return (honey_disk_io(o->dp, BIO_READ, offset, data, len));
	if ((buf = g_read_data(o->cp, offset, len, &error)) == NULL)
		return (error);
	memcpy(data, buf, len);
	g_free(buf);
	return (0);
}

static void
honey_raw_flush(struct honey_out *o)
{
	struct honey_rawhdr *h;
	int error = 0;

	if (!o->dirty || honey_raw_gone)
		return;
	if (o->used % o->ss != 0)
		error = honey_raw_write(o, o->ss + rounddown(o->used, o->ss),
		    o->sec, o->ss);
	if (error == 0) {
		h = malloc(o->ss, M_HONEY, M_WAITOK | M_ZERO);
		memcpy(h->magic, HONEY_MAGIC, sizeof(h->magic));
		h->version = 1;
		h->sectorsize = o->ss;
		h->used = o->used;
		error = honey_raw_write(o, 0, h, o->ss);
		free(h, M_HONEY);
	}
	if (error != 0)
		honey_logerr = error;
	else
		o->dirty = 0;
}

static void
honey_raw_open(struct honey_out *o)
{
	struct g_provider *pp;
	struct g_geom *gp;
	struct g_consumer *cp;
	struct honey_rawhdr *h;
	struct disk *dp;
	char *buf;
	int error;

	g_topology_lock();
	if ((pp = g_provider_by_name(honey_logdev)) == NULL) {
		g_topology_unlock();
		honey_logerr = ENOENT;
		return;
	}
	gp = g_new_geomf(&honey_gclass, "honey");
	gp->orphan = honey_g_orphan;
	cp = g_new_consumer(gp);
	if ((error = g_attach(cp, pp)) == 0 &&
	    (error = g_access(cp, 1, 1, 0)) != 0)
		g_detach(cp);
	if (error != 0) {
		g_destroy_consumer(cp);
		g_destroy_geom(gp);
		g_topology_unlock();
		honey_logerr = error;
		return;
	}
	o->ss = pp->sectorsize;
	o->cap = pp->mediasize - o->ss;
	/*
	 * A whole disk: find its driver.  The softc of a DISK geom is
	 * private to geom_disk.c; in FreeBSD 15.1 its first member is the
	 * struct disk pointer.  The d_geom test checks that this is so.
	 */
	o->dp = NULL;
	if (honey_rawdirect && strcmp(pp->geom->class->name, "DISK") == 0 &&
	    pp->geom->softc != NULL) {
		dp = *(struct disk **)pp->geom->softc;
		if (dp != NULL && dp->d_geom == pp->geom &&
		    dp->d_sectorsize == pp->sectorsize)
			o->dp = dp;
	}
	g_topology_unlock();

	o->sec = malloc(o->ss, M_HONEY, M_WAITOK | M_ZERO);
	buf = malloc(o->ss, M_HONEY, M_WAITOK);
	o->used = 0;
	o->cp = cp;
	/* Carry on after an earlier log on this disk, if there is one. */
	if (honey_raw_read(o, 0, buf, o->ss) == 0) {
		h = (struct honey_rawhdr *)buf;
		if (memcmp(h->magic, HONEY_MAGIC, sizeof(h->magic)) == 0 &&
		    h->version == 1 && h->sectorsize == o->ss &&
		    h->used <= o->cap)
			o->used = h->used;
	}
	if (o->used % o->ss != 0 && honey_raw_read(o,
	    o->ss + rounddown(o->used, o->ss), buf, o->ss) == 0)
		memcpy(o->sec, buf, o->used % o->ss);
	free(buf, M_HONEY);
	if (o->used == 0) {
		o->dirty = 1;
		honey_raw_flush(o);
	}
}

static int
honey_raw_put(struct honey_out *o, const char *line, int len)
{
	int error, n, off;

	if (honey_raw_gone)
		return (ENXIO);
	if (o->used + len > o->cap)
		return (ENOSPC);
	while (len > 0) {
		off = o->used % o->ss;
		n = MIN(len, o->ss - off);
		memcpy(o->sec + off, line, n);
		o->used += n;
		line += n;
		len -= n;
		o->dirty = 1;
		if (o->used % o->ss == 0) {
			error = honey_raw_write(o, o->used, o->sec, o->ss);
			bzero(o->sec, o->ss);
			if (error != 0)
				return (error);
		}
	}
	return (0);
}

static void
honey_out_open(struct honey_out *o)
{
	if (honey_logdev[0] != '\0')
		honey_raw_open(o);
	else
		o->vp = honey_log_open();
}

static void
honey_out_close(struct honey_out *o, struct thread *td)
{
	struct g_geom *gp;

	if (o->vp != NULL)
		vn_close(o->vp, FWRITE, td->td_ucred, td);
	if (o->cp != NULL) {
		honey_raw_flush(o);
		g_topology_lock();
		if (!honey_raw_gone) {
			gp = o->cp->geom;
			g_access(o->cp, -1, -1, 0);
			g_detach(o->cp);
			g_destroy_consumer(o->cp);
			g_destroy_geom(gp);
		}
		g_topology_unlock();
		free(o->sec, M_HONEY);
	}
}

static void
honey_out_put(struct honey_out *o, char *line, int len, struct thread *td)
{
	int error;

	if (o->cp != NULL)
		error = honey_raw_put(o, line, len);
	else if (o->vp != NULL)
		/* IO_NOMACCHECK: our own write is not an event. */
		error = vn_rdwr(UIO_WRITE, o->vp, line, len, 0, UIO_SYSSPACE,
		    IO_APPEND | IO_UNIT | IO_NOMACCHECK, td->td_ucred, NOCRED,
		    NULL, td);
	else
		error = ENXIO;
	if (error != 0) {
		honey_logerr = error;
		atomic_add_long(&honey_dropped, 1);
	} else
		atomic_add_long(&honey_logged, 1);
}

/*
 * The alert terminal.
 */
struct honey_alert {
	struct vnode	*vp;
	struct tty	*tp;
};

static void
honey_alert_open(struct honey_alert *a)
{
	struct nameidata nd;
	struct cdevsw *cdp;
	struct cdev *dev;
	char path[80];
	int flags, ref;

	snprintf(path, sizeof(path), "/dev/%s", honey_alertdev);
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, path);
	flags = FWRITE | O_NONBLOCK | O_NOCTTY;
	if (vn_open(&nd, &flags, 0, NULL) != 0)
		return;
	NDFREE_PNBUF(&nd);
	VOP_UNLOCK(nd.ni_vp);
	a->vp = nd.ni_vp;
	/* We keep it open, so the tty stays for as long as we use it. */
	if (a->vp->v_type == VCHR &&
	    (cdp = devvn_refthread(a->vp, &dev, &ref)) != NULL) {
		if ((cdp->d_flags & D_TTY) != 0)
			a->tp = dev->si_drv1;
		dev_relthread(dev, ref);
	}
}

static void
honey_alert_put(struct honey_alert *a, const char *buf, int len)
{
	if (a->tp == NULL || len <= 0)
		return;
	tty_lock(a->tp);
	if (!tty_gone(a->tp))
		tty_putstrn(a->tp, buf, len);
	tty_unlock(a->tp);
}

/* line is the log line of r, already formatted. */
static void
honey_alert_show(struct honey_alert *a, struct honey_rec *r, char *line,
    int len)
{
	char *p;

	switch (r->kind) {
	case HONEY_TTYOUT:
		honey_alert_put(a, r->text, r->len);
		break;
	case HONEY_EXEC:
	case HONEY_SIGNAL:
		/* The log line without its time stamp. */
		if ((p = memchr(line, ',', len)) != NULL) {
			p++;
			honey_alert_put(a, "\r\n", 2);
			honey_alert_put(a, p, len - (p - line) - 1);
			honey_alert_put(a, "\r\n", 2);
		}
		break;
	default:
		break;
	}
}

static void
honey_alert_close(struct honey_alert *a, struct thread *td)
{
	if (a->vp != NULL)
		vn_close(a->vp, FWRITE, td->td_ucred, td);
}

static void
honey_worker(void *arg)
{
	STAILQ_HEAD(, honey_rec) batch;
	struct thread *td = curthread;
	struct honey_rec *r;
	struct honey_out out;
	struct honey_alert alert;
	char *line;
	int len;

	line = malloc(HONEY_LINE, M_HONEY, M_WAITOK);
	bzero(&out, sizeof(out));
	bzero(&alert, sizeof(alert));
	honey_out_open(&out);

	mtx_lock(&honey_mtx);
	for (;;) {
		while (STAILQ_EMPTY(&honey_q) && !honey_stopping)
			msleep(&honey_q, &honey_mtx, 0, "honey", 0);
		if (STAILQ_EMPTY(&honey_q))
			break;			/* stopping and drained */
		STAILQ_INIT(&batch);
		STAILQ_CONCAT(&batch, &honey_q);
		honey_qlen = 0;
		mtx_unlock(&honey_mtx);

		if (out.vp == NULL && out.cp == NULL)
			honey_out_open(&out);
		if (honey_alertdev[0] != '\0' && alert.vp == NULL)
			honey_alert_open(&alert);
		while ((r = STAILQ_FIRST(&batch)) != NULL) {
			STAILQ_REMOVE_HEAD(&batch, link);
			len = honey_format(r, line);
			honey_out_put(&out, line, len, td);
			if (alert.tp != NULL)
				honey_alert_show(&alert, r, line, len);
			honey_rec_free(r);
		}
		if (out.cp != NULL)
			honey_raw_flush(&out);
		mtx_lock(&honey_mtx);
	}
	mtx_unlock(&honey_mtx);

	honey_out_close(&out, td);
	honey_alert_close(&alert, td);
	free(line, M_HONEY);
	/* kproc_exit() wakes up whoever sleeps on our proc: honey_stop(). */
	kproc_exit(0);
}

static int
honey_start(void)
{
	int error;

	if ((error = g_modevent(NULL, MOD_LOAD, &honey_gclass)) != 0)
		return (error);
	error = kproc_create(honey_worker, NULL, &honey_proc, 0, 0, "honey");
	if (error != 0) {
		g_modevent(NULL, MOD_UNLOAD, &honey_gclass);
		return (error);
	}
	honey_fork_tag = EVENTHANDLER_REGISTER(process_fork, honey_peer_fork,
	    NULL, EVENTHANDLER_PRI_ANY);
	honey_exit_tag = EVENTHANDLER_REGISTER(process_exit, honey_peer_exit,
	    NULL, EVENTHANDLER_PRI_ANY);
	honey_syscalls_hook();
	return (0);
}

static int
honey_stop(void)
{
	int error;

	if ((error = honey_syscalls_unhook()) != 0)
		return (error);
	honey_tty_detach_all();
	EVENTHANDLER_DEREGISTER(process_fork, honey_fork_tag);
	EVENTHANDLER_DEREGISTER(process_exit, honey_exit_tag);
	honey_peer_flush();
	mtx_lock(&honey_mtx);
	honey_stopping = 1;
	wakeup(&honey_q);
	/*
	 * The worker cannot see honey_stopping until msleep() has released
	 * the mutex, so its exit wakeup cannot be lost.
	 */
	msleep(honey_proc, &honey_mtx, 0, "hnystp", 0);
	mtx_unlock(&honey_mtx);
	/* The worker has closed the disk, so the class has nothing left. */
	g_modevent(NULL, MOD_UNLOAD, &honey_gclass);
	return (0);
}

static int
honey_modevent(module_t mod, int type, void *data)
{
	switch (type) {
	case MOD_LOAD:
		return (honey_start());
	case MOD_UNLOAD:
		return (honey_stop());
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t honey_worker_mod = { "honey_worker", honey_modevent, NULL };
DECLARE_MODULE(honey_worker, honey_worker_mod, SI_SUB_MAC, SI_ORDER_ANY);

static struct mac_policy_ops honey_ops = {
	.mpo_vnode_check_exec = honey_vnode_check_exec,
	.mpo_vnode_check_read = honey_vnode_check_read,
	.mpo_vnode_check_write = honey_vnode_check_write,
	.mpo_proc_check_signal = honey_proc_check_signal,
	.mpo_socket_init_label = honey_socket_init_label,
	.mpo_socket_destroy_label = honey_socket_destroy_label,
	.mpo_socket_newconn = honey_socket_newconn,
	.mpo_socket_check_accept = honey_socket_check_accept,
	.mpo_socket_check_receive = honey_socket_check_receive,
};

MAC_POLICY_SET(&honey_ops, honey, "Honeypot activity recorder",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
