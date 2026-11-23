#!/usr/sbin/dtrace -s
/* The same events honey.ko records, for processes inside jails, with DTrace only. */
#pragma D option quiet
#pragma D option switchrate=20hz
#pragma D option strsize=512
#pragma D option bufsize=32m
#pragma D option dynvarsize=16m

proc:::exec-success
/jid != 0/
{
	printf("%d,exec,%d,%d,%s,%s\n", walltimestamp / 1000, pid, uid,
	    execname, curpsinfo->pr_psargs);
}

syscall::open:entry
/jid != 0/
{
	self->path = arg0; self->flags = arg1; self->on = 1;
}

syscall::openat:entry
/jid != 0/
{
	self->path = arg1; self->flags = arg2; self->on = 1;
}

syscall::open:return, syscall::openat:return
/self->on/
{
	printf("%d,%s,%d,%d,%s,%s\n", walltimestamp / 1000,
	    errno != 0 ? "open-failed" : "open", pid, uid, execname,
	    copyinstr(self->path));
	self->on = 0; self->path = 0; self->flags = 0;
}

proc:::signal-send
/jid != 0/
{
	printf("%d,signal,%d,%d,%s,%d to %d %s\n", walltimestamp / 1000, pid,
	    uid, execname, args[2], args[1]->p_pid, args[1]->p_comm);
}

/* one line per character typed; put together afterwards */
fbt::ttydisc_rint:entry
/jid != 0/
{
	printf("%d,tty-in,%d,%d,%s,%d\n", walltimestamp / 1000, pid, uid,
	    execname, arg1 & 0xff);
}

/* what a jailed process writes to a terminal: remember the buffer, print it
 * once the write reaches the terminal layer */
syscall::write:entry
/jid != 0/
{
	self->wbuf = arg1; self->wlen = arg2;
}

fbt::ttydisc_write:entry
/self->wbuf/
{
	printf("%d,tty-out,%d,%d,%s,%s %S\n", walltimestamp / 1000, pid, uid,
	    execname, stringof(args[0]->t_dev->si_name),
	    copyinstr(self->wbuf, self->wlen < 400 ? self->wlen : 400));
}

syscall::write:return
/self->wbuf/
{
	self->wbuf = 0; self->wlen = 0;
}

/* regular files; only the last part of the name is at hand here */
fbt::vn_read:entry, fbt::vn_write:entry
/jid != 0 && args[0]->f_vnode != NULL &&
    ((int)args[0]->f_vnode->v_type & 0xff) == 1/	/* VREG; the field is one byte */
{
	this->nc = args[0]->f_vnode->v_cache_dst.tqh_first;
	printf("%d,%s,%d,%d,%s,%s\n", walltimestamp / 1000,
	    probefunc == "vn_read" ? "read" : "write", pid, uid, execname,
	    this->nc != NULL ? stringof(this->nc->nc_name) : "?");
}
