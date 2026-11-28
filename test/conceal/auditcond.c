/*
 * Why the SSH server in a jail does not set its audit identity: what a
 * process is told when it asks whether auditing is on, and whether it may
 * read and set its own audit identity.
 * cc -o auditcond auditcond.c -lbsm
 */
#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
	auditinfo_addr_t ai;
	int cond = -1, r;

	errno = 0;
	r = auditon(A_GETCOND, &cond, sizeof(cond));
	printf("auditon(A_GETCOND) = %d, condition %d, %s\n", r, cond,
	    r == 0 ? "ok" : strerror(errno));
	printf("cannot_audit(0) = %d\n", cannot_audit(0));
	errno = 0;
	r = getaudit_addr(&ai, sizeof(ai));
	printf("getaudit_addr = %d, %s\n", r, r == 0 ? "ok" : strerror(errno));
	if (r == 0) {
		errno = 0;
		r = setaudit_addr(&ai, sizeof(ai));	/* same values back */
		printf("setaudit_addr = %d, %s\n", r,
		    r == 0 ? "ok" : strerror(errno));
	}
	return (0);
}
