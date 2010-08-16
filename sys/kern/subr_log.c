/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)subr_log.c	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/kern/subr_log.c,v 1.39.2.2 2001/06/02 08:11:25 phk Exp $
 * $DragonFly: src/sys/kern/subr_log.c,v 1.10 2006/07/28 02:17:40 dillon Exp $
 */

/*
 * Error log buffer for kernel printf's.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/filio.h>
#include <sys/ttycom.h>
#include <sys/msgbuf.h>
#include <sys/signalvar.h>
#include <sys/kernel.h>
#include <sys/event.h>
#include <sys/filedesc.h>
#include <sys/sysctl.h>
#include <sys/thread2.h>

#define LOG_ASYNC	0x04
#define LOG_RDWAIT	0x08

static	d_open_t	logopen;
static	d_close_t	logclose;
static	d_read_t	logread;
static	d_ioctl_t	logioctl;
static	d_kqfilter_t	logkqfilter;

static	void logtimeout(void *arg);
static	void logfiltdetach(struct knote *kn);
static	int  logfiltread(struct knote *kn, long hint);

#define CDEV_MAJOR 7
static struct dev_ops log_ops = {
	{ "log", CDEV_MAJOR, D_KQFILTER },
	.d_open =	logopen,
	.d_close =	logclose,
	.d_read =	logread,
	.d_ioctl =	logioctl,
	.d_kqfilter =	logkqfilter
};

static struct logsoftc {
	int	sc_state;		/* see above for possibilities */
	struct	kqinfo	sc_kqp;		/* processes waiting on I/O */
	struct  sigio *sc_sigio;	/* information for async I/O */
	struct	callout sc_callout;	/* callout to wakeup syslog  */
} logsoftc;

int	log_open;			/* also used in log() */

/* Times per second to check for a pending syslog wakeup. */
static int	log_wakeups_per_second = 5;
SYSCTL_INT(_kern, OID_AUTO, log_wakeups_per_second, CTLFLAG_RW,
    &log_wakeups_per_second, 0, "");

/*ARGSUSED*/
static	int
logopen(struct dev_open_args *ap)
{
	struct proc *p = curproc;

	KKASSERT(p != NULL);
	if (log_open)
		return (EBUSY);
	log_open = 1;
	callout_init(&logsoftc.sc_callout);
	fsetown(p->p_pid, &logsoftc.sc_sigio);	/* signal process only */
	callout_reset(&logsoftc.sc_callout, hz / log_wakeups_per_second,
	    logtimeout, NULL);
	return (0);
}

/*ARGSUSED*/
static	int
logclose(struct dev_close_args *ap)
{
	log_open = 0;
	callout_stop(&logsoftc.sc_callout);
	logsoftc.sc_state = 0;
	funsetown(logsoftc.sc_sigio);
	return (0);
}

/*ARGSUSED*/
static	int
logread(struct dev_read_args *ap)
{
	struct uio *uio = ap->a_uio;
	struct msgbuf *mbp = msgbufp;
	long l;
	int error = 0;

	crit_enter();
	while (mbp->msg_bufr == mbp->msg_bufx) {
		if (ap->a_ioflag & IO_NDELAY) {
			crit_exit();
			return (EWOULDBLOCK);
		}
		logsoftc.sc_state |= LOG_RDWAIT;
		if ((error = tsleep((caddr_t)mbp, PCATCH, "klog", 0))) {
			crit_exit();
			return (error);
		}
	}
	crit_exit();
	logsoftc.sc_state &= ~LOG_RDWAIT;

	while (uio->uio_resid > 0) {
		l = (long)mbp->msg_bufx - (long)mbp->msg_bufr;
		if (l < 0)
			l = mbp->msg_size - mbp->msg_bufr;
		l = (long)szmin(l, uio->uio_resid);
		if (l == 0)
			break;
		error = uiomove((caddr_t)msgbufp->msg_ptr + mbp->msg_bufr,
				(size_t)l, uio);
		if (error)
			break;
		mbp->msg_bufr += l;
		if (mbp->msg_bufr >= mbp->msg_size)
			mbp->msg_bufr = 0;
	}
	return (error);
}

static struct filterops logread_filtops =
	{ FILTEROP_ISFD, NULL, logfiltdetach, logfiltread };

static int
logkqfilter(struct dev_kqfilter_args *ap)
{
	struct knote *kn = ap->a_kn;
	struct klist *klist = &logsoftc.sc_kqp.ki_note;

	ap->a_result = 0;
	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &logread_filtops;
		break;
	default:
		ap->a_result = EOPNOTSUPP;
		return (0);
	}

	knote_insert(klist, kn);

	return (0);
}

static void
logfiltdetach(struct knote *kn)
{
	struct klist *klist = &logsoftc.sc_kqp.ki_note;

	knote_remove(klist, kn);
}

static int
logfiltread(struct knote *kn, long hint)
{
	int ret = 0;

	crit_enter();
	if (msgbufp->msg_bufr != msgbufp->msg_bufx)
		ret = 1;
	crit_exit();

	return (ret);
}

static void
logtimeout(void *arg)
{

	if (!log_open)
		return;
	if (msgbuftrigger == 0) {
		callout_reset(&logsoftc.sc_callout,
		    hz / log_wakeups_per_second, logtimeout, NULL);
		return;
	}
	msgbuftrigger = 0;
	KNOTE(&logsoftc.sc_kqp.ki_note, 0);
	if ((logsoftc.sc_state & LOG_ASYNC) && logsoftc.sc_sigio != NULL)
		pgsigio(logsoftc.sc_sigio, SIGIO, 0);
	if (logsoftc.sc_state & LOG_RDWAIT) {
		wakeup((caddr_t)msgbufp);
		logsoftc.sc_state &= ~LOG_RDWAIT;
	}
	callout_reset(&logsoftc.sc_callout, hz / log_wakeups_per_second,
	    logtimeout, NULL);
}

/*ARGSUSED*/
static	int
logioctl(struct dev_ioctl_args *ap)
{
	long l;

	switch (ap->a_cmd) {
	case FIONREAD:
		/* return number of characters immediately available */
		crit_enter();
		l = msgbufp->msg_bufx - msgbufp->msg_bufr;
		crit_exit();
		if (l < 0)
			l += msgbufp->msg_size;
		*(int *)ap->a_data = l;
		break;

	case FIOASYNC:
		if (*(int *)ap->a_data)
			logsoftc.sc_state |= LOG_ASYNC;
		else
			logsoftc.sc_state &= ~LOG_ASYNC;
		break;

	case FIOSETOWN:
		return (fsetown(*(int *)ap->a_data, &logsoftc.sc_sigio));

	case FIOGETOWN:
		*(int *)ap->a_data = fgetown(logsoftc.sc_sigio);
		break;

	/* This is deprecated, FIOSETOWN should be used instead. */
	case TIOCSPGRP:
		return (fsetown(-(*(int *)ap->a_data), &logsoftc.sc_sigio));

	/* This is deprecated, FIOGETOWN should be used instead */
	case TIOCGPGRP:
		*(int *)ap->a_data = -fgetown(logsoftc.sc_sigio);
		break;

	default:
		return (ENOTTY);
	}
	return (0);
}

static void
log_drvinit(void *unused)
{
	make_dev(&log_ops, 0, UID_ROOT, GID_WHEEL, 0600, "klog");
}

SYSINIT(logdev,SI_SUB_DRIVERS,SI_ORDER_MIDDLE+CDEV_MAJOR,log_drvinit,NULL)
