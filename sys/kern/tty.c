/*-
 * (MPSAFE)
 *
 * Copyright (c) 1982, 1986, 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)tty.c	8.8 (Berkeley) 1/21/94
 * $FreeBSD: src/sys/kern/tty.c,v 1.129.2.5 2002/03/11 01:32:31 dd Exp $
 */

/*
 * MPSAFE NOTE:
 * Almost all functions in this file are acquiring the tty token due to their
 * access and modifications of the 'tp' (struct tty) objects.
 */

/*-
 * TODO:
 *	o Fix races for sending the start char in ttyflush().
 *	o Handle inter-byte timeout for "MIN > 0, TIME > 0" in ttyselect().
 *	  With luck, there will be MIN chars before select() returns().
 *	o Handle CLOCAL consistently for ptys.  Perhaps disallow setting it.
 *	o Don't allow input in TS_ZOMBIE case.  It would be visible through
 *	  FIONREAD.
 *	o Do the new sio locking stuff here and use it to avoid special
 *	  case for EXTPROC?
 *	o Lock PENDIN too?
 *	o Move EXTPROC and/or PENDIN to t_state?
 *	o Wrap most of ttioctl in spltty/splx.
 *	o Implement TIOCNOTTY or remove it from <sys/ioctl.h>.
 *	o Send STOP if IXOFF is toggled off while TS_TBLOCK is set.
 *	o Don't allow certain termios flags to affect disciplines other
 *	  than TTYDISC.  Cancel their effects before switch disciplines
 *	  and ignore them if they are set while we are in another
 *	  discipline.
 *	o Now that historical speed conversions are handled here, don't
 *	  do them in drivers.
 *	o Check for TS_CARR_ON being set while everything is closed and not
 *	  waiting for carrier.  TS_CARR_ON isn't cleared if nothing is open,
 *	  so it would live until the next open even if carrier drops.
 *	o Restore TS_WOPEN since it is useful in pstat.  It must be cleared
 *	  only when _all_ openers leave open().
 */

#include "opt_compat.h"
#include "opt_uconsole.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filio.h>
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
#include <sys/ioctl_compat.h>
#endif
#include <sys/proc.h>
#include <sys/priv.h>
#define	TTYDEFCHARS
#include <sys/tty.h>
#include <sys/clist.h>
#undef	TTYDEFCHARS
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/dkstat.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/signalvar.h>
#include <sys/signal2.h>
#include <sys/resourcevar.h>
#include <sys/malloc.h>
#include <sys/filedesc.h>
#include <sys/sysctl.h>
#include <sys/thread2.h>

#include <vm/vm.h>
#include <sys/lock.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

MALLOC_DEFINE(M_TTYS, "ttys", "tty data structures");

static int	proc_compare (struct proc *p1, struct proc *p2);
static int	ttnread (struct tty *tp);
static void	ttyecho (int c, struct tty *tp);
static int	ttyoutput (int c, struct tty *tp);
static void	ttypend (struct tty *tp);
static void	ttyretype (struct tty *tp);
static void	ttyrub (int c, struct tty *tp);
static void	ttyrubo (struct tty *tp, int cnt);
static void	ttyunblock (struct tty *tp);
static int	ttywflush (struct tty *tp);
static int	filt_ttyread (struct knote *kn, long hint);
static void 	filt_ttyrdetach (struct knote *kn);
static int	filt_ttywrite (struct knote *kn, long hint);
static void 	filt_ttywdetach (struct knote *kn);

/*
 * Table with character classes and parity. The 8th bit indicates parity,
 * the 7th bit indicates the character is an alphameric or underscore (for
 * ALTWERASE), and the low 6 bits indicate delay type.  If the low 6 bits
 * are 0 then the character needs no special processing on output; classes
 * other than 0 might be translated or (not currently) require delays.
 */
#define	E	0x00	/* Even parity. */
#define	O	0x80	/* Odd parity. */
#define	PARITY(c)	(char_type[c] & O)

#define	ALPHA	0x40	/* Alpha or underscore. */
#define	ISALPHA(c)	(char_type[(c) & TTY_CHARMASK] & ALPHA)

#define	CCLASSMASK	0x3f
#define	CCLASS(c)	(char_type[c] & CCLASSMASK)

#define	BS	BACKSPACE
#define	CC	CONTROL
#define	CR	RETURN
#define	NA	ORDINARY | ALPHA
#define	NL	NEWLINE
#define	NO	ORDINARY
#define	TB	TAB
#define	VT	VTAB

static u_char const char_type[] = {
	E|CC, O|CC, O|CC, E|CC, O|CC, E|CC, E|CC, O|CC,	/* nul - bel */
	O|BS, E|TB, E|NL, O|CC, E|VT, O|CR, O|CC, E|CC, /* bs - si */
	O|CC, E|CC, E|CC, O|CC, E|CC, O|CC, O|CC, E|CC, /* dle - etb */
	E|CC, O|CC, O|CC, E|CC, O|CC, E|CC, E|CC, O|CC, /* can - us */
	O|NO, E|NO, E|NO, O|NO, E|NO, O|NO, O|NO, E|NO, /* sp - ' */
	E|NO, O|NO, O|NO, E|NO, O|NO, E|NO, E|NO, O|NO, /* ( - / */
	E|NA, O|NA, O|NA, E|NA, O|NA, E|NA, E|NA, O|NA, /* 0 - 7 */
	O|NA, E|NA, E|NO, O|NO, E|NO, O|NO, O|NO, E|NO, /* 8 - ? */
	O|NO, E|NA, E|NA, O|NA, E|NA, O|NA, O|NA, E|NA, /* @ - G */
	E|NA, O|NA, O|NA, E|NA, O|NA, E|NA, E|NA, O|NA, /* H - O */
	E|NA, O|NA, O|NA, E|NA, O|NA, E|NA, E|NA, O|NA, /* P - W */
	O|NA, E|NA, E|NA, O|NO, E|NO, O|NO, O|NO, O|NA, /* X - _ */
	E|NO, O|NA, O|NA, E|NA, O|NA, E|NA, E|NA, O|NA, /* ` - g */
	O|NA, E|NA, E|NA, O|NA, E|NA, O|NA, O|NA, E|NA, /* h - o */
	O|NA, E|NA, E|NA, O|NA, E|NA, O|NA, O|NA, E|NA, /* p - w */
	E|NA, O|NA, O|NA, E|NO, O|NO, E|NO, E|NO, O|CC, /* x - del */
	/*
	 * Meta chars; should be settable per character set;
	 * for now, treat them all as normal characters.
	 */
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
};
#undef	BS
#undef	CC
#undef	CR
#undef	NA
#undef	NL
#undef	NO
#undef	TB
#undef	VT

/* Macros to clear/set/test flags. */
#define	SET(t, f)	(t) |= (f)
#define	CLR(t, f)	(t) &= ~(f)
#define	ISSET(t, f)	((t) & (f))

#undef MAX_INPUT		/* XXX wrong in <sys/syslimits.h> */
#define	MAX_INPUT	TTYHOG	/* XXX limit is usually larger for !ICANON */

uint64_t tk_nin;
SYSCTL_OPAQUE(_kern, OID_AUTO, tk_nin, CTLFLAG_RD, &tk_nin, sizeof(tk_nin),
    "LU", "TTY input statistic");
uint64_t tk_nout;
SYSCTL_OPAQUE(_kern, OID_AUTO, tk_nout, CTLFLAG_RD, &tk_nout, sizeof(tk_nout),
    "LU", "TTY output statistic");
uint64_t tk_rawcc;

/*
 * list of struct tty where pstat(8) can pick it up with sysctl
 */
static TAILQ_HEAD(, tty) tty_list = TAILQ_HEAD_INITIALIZER(tty_list);

/*
 * Initial open of tty, or (re)entry to standard tty line discipline.
 */
int
ttyopen(cdev_t device, struct tty *tp)
{
	crit_enter();
	lwkt_gettoken(&tty_token);
	tp->t_dev = device;
	if (!ISSET(tp->t_state, TS_ISOPEN)) {
		SET(tp->t_state, TS_ISOPEN);
		if (ISSET(tp->t_cflag, CLOCAL)) {
			SET(tp->t_state, TS_CONNECTED);
		}
		bzero(&tp->t_winsize, sizeof(tp->t_winsize));
	}
	ttsetwater(tp);
	lwkt_reltoken(&tty_token);
	crit_exit();
	return (0);
}

/*
 * Handle close() on a tty line: flush and set to initial state,
 * bumping generation number so that pending read/write calls
 * can detect recycling of the tty.
 *
 * XXX our caller should have done `spltty(); l_close(); ttyclose();'
 * and l_close() should have flushed, but we repeat the spltty() and
 * the flush in case there are buggy callers.
 */
int
ttyclose(struct tty *tp)
{
	crit_enter();
	lwkt_gettoken(&tty_token);
	funsetown(&tp->t_sigio);
	if (constty == tp)
		constty = NULL;

	ttyflush(tp, FREAD | FWRITE);
	clist_free_cblocks(&tp->t_canq);
	clist_free_cblocks(&tp->t_outq);
	clist_free_cblocks(&tp->t_rawq);

	tp->t_gen++;
	tp->t_line = TTYDISC;
	ttyclearsession(tp);
	tp->t_state &= TS_REGISTERED;	/* clear all bits except */
	lwkt_reltoken(&tty_token);
	crit_exit();
	return (0);
}

/*
 * Disassociate the tty from its session.  Traditionally this has only been
 * a half-close, meaning that the session was still allowed to point at the
 * tty (resulting in the tty in the ps command showing something like 'p0-'),
 * even though the tty is no longer pointing at the session.
 *
 * The half close seems to be useful only for 'ps' output but there is as
 * yet no reason to remove the feature.  The full-close code is currently
 * #if 0'd out.  See also sess_rele() in kern/kern_proc.c.
 */
void
ttyclearsession(struct tty *tp)
{
	struct session *sp;
	struct pgrp *opgrp;

	lwkt_gettoken(&tty_token);
	opgrp = tp->t_pgrp;
	tp->t_pgrp = NULL;
	if (opgrp) {
		pgrel(opgrp);
		opgrp = NULL;
	}

	if ((sp = tp->t_session) != NULL) {
		tp->t_session = NULL;
#ifdef TTY_DO_FULL_CLOSE
		/* FULL CLOSE (not yet) */
		if (sp->s_ttyp == tp) {
			sp->s_ttyp = NULL;
			ttyunhold(tp);
		} else {
			kprintf("ttyclearsession: warning: sp->s_ttyp != tp "
				"%p/%p\n", sp->s_ttyp, tp);
		}
#endif
	}
	lwkt_reltoken(&tty_token);
}

/*
 * Release the tty vnode association for a session.  This is the 
 * 'other half' of the close.  Because multiple opens of /dev/tty
 * only generate a single open to the actual tty, the file modes
 * are locked to FREAD|FWRITE.
 *
 * If dorevoke is non-zero, the session is also revoked.  We have to
 * close the vnode if VCTTYISOPEN is set.
 */
void
ttyclosesession(struct session *sp, int dorevoke)
{
	struct vnode *vp;

	lwkt_gettoken(&tty_token);
retry:
	/*
	 * There may not be a controlling terminal or it may have been closed
	 * out from under us.
	 */
	if ((vp = sp->s_ttyvp) == NULL) {
		lwkt_reltoken(&tty_token);
		return;
	}

	/*
	 * We need a lock if we have to close or revoke.
	 */
	if ((vp->v_flag & VCTTYISOPEN) || dorevoke) {
		vhold(vp);
		if (vn_lock(vp, LK_EXCLUSIVE|LK_RETRY)) {
			vdrop(vp);
			goto retry;
		}

		/*
		 * Retry if the vnode was ripped out from under us
		 */
		if (vp != sp->s_ttyvp) {
			vn_unlock(vp);
			vdrop(vp);
			goto retry;
		}

		/*
		 * Close and revoke as needed
		 */
		sp->s_ttyvp = NULL;
		if (vp->v_flag & VCTTYISOPEN) {
			vclrflags(vp, VCTTYISOPEN);
			VOP_CLOSE(vp, FREAD|FWRITE);
		}
		vn_unlock(vp);
		if (dorevoke)
			vrevoke(vp, proc0.p_ucred);
		vdrop(vp);
	} else {
		sp->s_ttyvp = NULL;
	}
	vrele(vp);
	lwkt_reltoken(&tty_token);
}

#define	FLUSHQ(q) {							\
	if ((q)->c_cc)							\
		ndflush(q, (q)->c_cc);					\
}

/* Is 'c' a line delimiter ("break" character)? */
#define	TTBREAKC(c, lflag)							\
	((c) == '\n' || (((c) == cc[VEOF] ||				\
	  (c) == cc[VEOL] || ((c) == cc[VEOL2] && lflag & IEXTEN)) &&	\
	 (c) != _POSIX_VDISABLE))

/*
 * Process input of a single character received on a tty.
 */
int
ttyinput(int c, struct tty *tp)
{
	tcflag_t iflag, lflag;
	cc_t *cc;
	int i, err;

	lwkt_gettoken(&tty_token);
	/*
	 * If input is pending take it first.
	 */
	lflag = tp->t_lflag;
	if (ISSET(lflag, PENDIN))
		ttypend(tp);
	/*
	 * Gather stats.
	 */
	if (ISSET(lflag, ICANON))
		++tp->t_cancc;
	else
		++tp->t_rawcc;
	++tk_nin;

	/*
	 * Block further input iff:
	 * current input > threshold AND input is available to user program
	 * AND input flow control is enabled and not yet invoked.
	 * The 3 is slop for PARMRK.
	 */
	iflag = tp->t_iflag;
	if (tp->t_rawq.c_cc + tp->t_canq.c_cc > tp->t_ihiwat - 3 &&
	    (!ISSET(lflag, ICANON) || tp->t_canq.c_cc != 0) &&
	    (ISSET(tp->t_cflag, CRTS_IFLOW) || ISSET(iflag, IXOFF)) &&
	    !ISSET(tp->t_state, TS_TBLOCK))
		ttyblock(tp);

	/* Handle exceptional conditions (break, parity, framing). */
	cc = tp->t_cc;
	err = (ISSET(c, TTY_ERRORMASK));
	if (err) {
		CLR(c, TTY_ERRORMASK);
		if (ISSET(err, TTY_BI)) {
			if (ISSET(iflag, IGNBRK)) {
				lwkt_reltoken(&tty_token);
				return (0);
			}
			if (ISSET(iflag, BRKINT)) {
				ttyflush(tp, FREAD | FWRITE);
				pgsignal(tp->t_pgrp, SIGINT, 1);
				goto endcase;
			}
			if (ISSET(iflag, PARMRK))
				goto parmrk;
		} else if ((ISSET(err, TTY_PE) && ISSET(iflag, INPCK))
			|| ISSET(err, TTY_FE)) {
			if (ISSET(iflag, IGNPAR)) {
				lwkt_reltoken(&tty_token);
				return (0);
			}
			else if (ISSET(iflag, PARMRK)) {
parmrk:
				if (tp->t_rawq.c_cc + tp->t_canq.c_cc >
				    MAX_INPUT - 3)
					goto input_overflow;
				clist_putc(0377 | TTY_QUOTE, &tp->t_rawq);
				clist_putc(0 | TTY_QUOTE, &tp->t_rawq);
				clist_putc(c | TTY_QUOTE, &tp->t_rawq);
				goto endcase;
			} else
				c = 0;
		}
	}

	if (!ISSET(tp->t_state, TS_TYPEN) && ISSET(iflag, ISTRIP))
		CLR(c, 0x80);
	if (!ISSET(lflag, EXTPROC)) {
		/*
		 * Check for literal nexting very first
		 */
		if (ISSET(tp->t_state, TS_LNCH)) {
			SET(c, TTY_QUOTE);
			CLR(tp->t_state, TS_LNCH);
		}
		/*
		 * Scan for special characters.  This code
		 * is really just a big case statement with
		 * non-constant cases.  The bottom of the
		 * case statement is labeled ``endcase'', so goto
		 * it after a case match, or similar.
		 */

		/*
		 * Control chars which aren't controlled
		 * by ICANON, ISIG, or IXON.
		 */
		if (ISSET(lflag, IEXTEN)) {
			if (CCEQ(cc[VLNEXT], c)) {
				if (ISSET(lflag, ECHO)) {
					if (ISSET(lflag, ECHOE)) {
						(void)ttyoutput('^', tp);
						(void)ttyoutput('\b', tp);
					} else
						ttyecho(c, tp);
				}
				SET(tp->t_state, TS_LNCH);
				goto endcase;
			}
			if (CCEQ(cc[VDISCARD], c)) {
				if (ISSET(lflag, FLUSHO))
					CLR(tp->t_lflag, FLUSHO);
				else {
					ttyflush(tp, FWRITE);
					ttyecho(c, tp);
					if (tp->t_rawq.c_cc + tp->t_canq.c_cc)
						ttyretype(tp);
					SET(tp->t_lflag, FLUSHO);
				}
				goto startoutput;
			}
		}
		/*
		 * Signals.
		 */
		if (ISSET(lflag, ISIG)) {
			if (CCEQ(cc[VINTR], c) || CCEQ(cc[VQUIT], c)) {
				if (!ISSET(lflag, NOFLSH))
					ttyflush(tp, FREAD | FWRITE);
				ttyecho(c, tp);
				pgsignal(tp->t_pgrp,
				    CCEQ(cc[VINTR], c) ? SIGINT : SIGQUIT, 1);
				goto endcase;
			}
			if (CCEQ(cc[VSUSP], c)) {
				if (!ISSET(lflag, NOFLSH))
					ttyflush(tp, FREAD);
				ttyecho(c, tp);
				pgsignal(tp->t_pgrp, SIGTSTP, 1);
				goto endcase;
			}
		}
		/*
		 * Handle start/stop characters.
		 */
		if (ISSET(iflag, IXON)) {
			if (CCEQ(cc[VSTOP], c)) {
				if (!ISSET(tp->t_state, TS_TTSTOP)) {
					SET(tp->t_state, TS_TTSTOP);
					(*tp->t_stop)(tp, 0);
					lwkt_reltoken(&tty_token);
					return (0);
				}
				if (!CCEQ(cc[VSTART], c)) {
					lwkt_reltoken(&tty_token);
					return (0);
				}
				/*
				 * if VSTART == VSTOP then toggle
				 */
				goto endcase;
			}
			if (CCEQ(cc[VSTART], c))
				goto restartoutput;
		}
		/*
		 * IGNCR, ICRNL, & INLCR
		 */
		if (c == '\r') {
			if (ISSET(iflag, IGNCR)) {
				lwkt_reltoken(&tty_token);
				return (0);
			}
			else if (ISSET(iflag, ICRNL))
				c = '\n';
		} else if (c == '\n' && ISSET(iflag, INLCR))
			c = '\r';
	}
	if (!ISSET(tp->t_lflag, EXTPROC) && ISSET(lflag, ICANON)) {
		/*
		 * From here on down canonical mode character
		 * processing takes place.
		 */
		/*
		 * erase or erase2 (^H / ^?)
		 */
		if (CCEQ(cc[VERASE], c) || CCEQ(cc[VERASE2], c) ) {
			if (tp->t_rawq.c_cc)
				ttyrub(clist_unputc(&tp->t_rawq), tp);
			goto endcase;
		}
		/*
		 * kill (^U)
		 */
		if (CCEQ(cc[VKILL], c)) {
			if (ISSET(lflag, ECHOKE) &&
			    tp->t_rawq.c_cc == tp->t_rocount &&
			    !ISSET(lflag, ECHOPRT))
				while (tp->t_rawq.c_cc)
					ttyrub(clist_unputc(&tp->t_rawq), tp);
			else {
				ttyecho(c, tp);
				if (ISSET(lflag, ECHOK) ||
				    ISSET(lflag, ECHOKE))
					ttyecho('\n', tp);
				FLUSHQ(&tp->t_rawq);
				tp->t_rocount = 0;
			}
			CLR(tp->t_state, TS_LOCAL);
			goto endcase;
		}
		/*
		 * word erase (^W)
		 */
		if (CCEQ(cc[VWERASE], c) && ISSET(lflag, IEXTEN)) {
			int ctype;

			/*
			 * erase whitespace
			 */
			while ((c = clist_unputc(&tp->t_rawq)) == ' ' || c == '\t')
				ttyrub(c, tp);
			if (c == -1)
				goto endcase;
			/*
			 * erase last char of word and remember the
			 * next chars type (for ALTWERASE)
			 */
			ttyrub(c, tp);
			c = clist_unputc(&tp->t_rawq);
			if (c == -1)
				goto endcase;
			if (c == ' ' || c == '\t') {
				clist_putc(c, &tp->t_rawq);
				goto endcase;
			}
			ctype = ISALPHA(c);
			/*
			 * erase rest of word
			 */
			do {
				ttyrub(c, tp);
				c = clist_unputc(&tp->t_rawq);
				if (c == -1)
					goto endcase;
			} while (c != ' ' && c != '\t' &&
			    (!ISSET(lflag, ALTWERASE) || ISALPHA(c) == ctype));
			clist_putc(c, &tp->t_rawq);
			goto endcase;
		}
		/*
		 * reprint line (^R)
		 */
		if (CCEQ(cc[VREPRINT], c) && ISSET(lflag, IEXTEN)) {
			ttyretype(tp);
			goto endcase;
		}
		/*
		 * ^T - kernel info and generate SIGINFO
		 */
		if (CCEQ(cc[VSTATUS], c) && ISSET(lflag, IEXTEN)) {
			if (ISSET(lflag, ISIG))
				pgsignal(tp->t_pgrp, SIGINFO, 1);
			if (!ISSET(lflag, NOKERNINFO))
				ttyinfo(tp);
			goto endcase;
		}
		if (CCEQ(cc[VCHECKPT], c) && ISSET(lflag, IEXTEN)) {
			if (ISSET(lflag, ISIG))
				pgsignal(tp->t_pgrp, SIGCKPT, 1);
			goto endcase;
		}
	}
	/*
	 * Check for input buffer overflow
	 */
	if (tp->t_rawq.c_cc + tp->t_canq.c_cc >= MAX_INPUT) {
input_overflow:
		if (ISSET(iflag, IMAXBEL)) {
			if (tp->t_outq.c_cc < tp->t_ohiwat)
				(void)ttyoutput(CTRL('g'), tp);
		}
		goto endcase;
	}

	if (   c == 0377 && ISSET(iflag, PARMRK) && !ISSET(iflag, ISTRIP)
	     && ISSET(iflag, IGNBRK|IGNPAR) != (IGNBRK|IGNPAR))
		clist_putc(0377 | TTY_QUOTE, &tp->t_rawq);

	/*
	 * Put data char in q for user and
	 * wakeup on seeing a line delimiter.
	 */
	if (clist_putc(c, &tp->t_rawq) >= 0) {
		if (!ISSET(lflag, ICANON)) {
			ttwakeup(tp);
			ttyecho(c, tp);
			goto endcase;
		}
		if (TTBREAKC(c, lflag)) {
			tp->t_rocount = 0;
			catq(&tp->t_rawq, &tp->t_canq);
			ttwakeup(tp);
		} else if (tp->t_rocount++ == 0)
			tp->t_rocol = tp->t_column;
		if (ISSET(tp->t_state, TS_ERASE)) {
			/*
			 * end of prterase \.../
			 */
			CLR(tp->t_state, TS_ERASE);
			(void)ttyoutput('/', tp);
		}
		i = tp->t_column;
		ttyecho(c, tp);
		if (CCEQ(cc[VEOF], c) && ISSET(lflag, ECHO)) {
			/*
			 * Place the cursor over the '^' of the ^D.
			 */
			i = imin(2, tp->t_column - i);
			while (i > 0) {
				(void)ttyoutput('\b', tp);
				i--;
			}
		}
	}
endcase:
	/*
	 * IXANY means allow any character to restart output.
	 */
	if (ISSET(tp->t_state, TS_TTSTOP) &&
	    !ISSET(iflag, IXANY) && cc[VSTART] != cc[VSTOP]) {
		lwkt_reltoken(&tty_token);
		return (0);
	}
restartoutput:
	CLR(tp->t_lflag, FLUSHO);
	CLR(tp->t_state, TS_TTSTOP);
startoutput:
	lwkt_reltoken(&tty_token);
	return (ttstart(tp));
}

/*
 * Output a single character on a tty, doing output processing
 * as needed (expanding tabs, newline processing, etc.).
 * Returns < 0 if succeeds, otherwise returns char to resend.
 * Must be recursive.
 */
static int
ttyoutput(int c, struct tty *tp)
{
	tcflag_t oflag;
	int col;

	lwkt_gettoken(&tty_token);
	oflag = tp->t_oflag;
	if (!ISSET(oflag, OPOST)) {
		if (ISSET(tp->t_lflag, FLUSHO)) {
			lwkt_reltoken(&tty_token);
			return (-1);
		}
		if (clist_putc(c, &tp->t_outq)) {
			lwkt_reltoken(&tty_token);
			return (c);
		}
		tk_nout++;
		tp->t_outcc++;
		lwkt_reltoken(&tty_token);
		return (-1);
	}
	/*
	 * Do tab expansion if OXTABS is set.  Special case if we external
	 * processing, we don't do the tab expansion because we'll probably
	 * get it wrong.  If tab expansion needs to be done, let it happen
	 * externally.
	 */
	CLR(c, ~TTY_CHARMASK);
	if (c == '\t' &&
	    ISSET(oflag, OXTABS) && !ISSET(tp->t_lflag, EXTPROC)) {
		c = 8 - (tp->t_column & 7);
		if (!ISSET(tp->t_lflag, FLUSHO)) {
			crit_enter();		/* Don't interrupt tabs. */
			c -= b_to_q("        ", c, &tp->t_outq);
			tk_nout += c;
			tp->t_outcc += c;
			crit_exit();
		}
		tp->t_column += c;
		lwkt_reltoken(&tty_token);
		return (c ? -1 : '\t');
	}
	if (c == CEOT && ISSET(oflag, ONOEOT)) {
		lwkt_reltoken(&tty_token);
		return (-1);
	}

	/*
	 * Newline translation: if ONLCR is set,
	 * translate newline into "\r\n".
	 */
	if (c == '\n' && ISSET(tp->t_oflag, ONLCR)) {
		tk_nout++;
		tp->t_outcc++;
		if (!ISSET(tp->t_lflag, FLUSHO) && clist_putc('\r', &tp->t_outq)) {
			lwkt_reltoken(&tty_token);
			return (c);
		}
	}
	/* If OCRNL is set, translate "\r" into "\n". */
	else if (c == '\r' && ISSET(tp->t_oflag, OCRNL))
		c = '\n';
	/* If ONOCR is set, don't transmit CRs when on column 0. */
	else if (c == '\r' && ISSET(tp->t_oflag, ONOCR) && tp->t_column == 0) {
		lwkt_reltoken(&tty_token);
		return (-1);
	}

	tk_nout++;
	tp->t_outcc++;
	if (!ISSET(tp->t_lflag, FLUSHO) && clist_putc(c, &tp->t_outq)) {
		lwkt_reltoken(&tty_token);
		return (c);
	}

	col = tp->t_column;
	switch (CCLASS(c)) {
	case BACKSPACE:
		if (col > 0)
			--col;
		break;
	case CONTROL:
		break;
	case NEWLINE:
		if (ISSET(tp->t_oflag, ONLCR | ONLRET))
			col = 0;
		break;
	case RETURN:
		col = 0;
		break;
	case ORDINARY:
		++col;
		break;
	case TAB:
		col = (col + 8) & ~7;
		break;
	}
	tp->t_column = col;
	lwkt_reltoken(&tty_token);
	return (-1);
}

/*
 * Ioctls for all tty devices.  Called after line-discipline specific ioctl
 * has been called to do discipline-specific functions and/or reject any
 * of these ioctl commands.
 */
/* ARGSUSED */
int
ttioctl(struct tty *tp, u_long cmd, void *data, int flag)
{
	struct thread *td = curthread;
	struct lwp *lp = td->td_lwp;
	struct proc *p = td->td_proc;
	struct pgrp *opgrp;
	struct tty *otp;
	int error;

	KKASSERT(p);
	lwkt_gettoken(&tty_token);
	lwkt_gettoken(&proc_token);
	lwkt_gettoken(&p->p_token);

	/* If the ioctl involves modification, hang if in the background. */
	switch (cmd) {
	case  TIOCCBRK:
	case  TIOCCONS:
	case  TIOCDRAIN:
	case  TIOCEXCL:
	case  TIOCFLUSH:
#ifdef TIOCHPCL
	case  TIOCHPCL:
#endif
	case  TIOCNXCL:
	case  TIOCSBRK:
	case  TIOCSCTTY:
	case  TIOCSDRAINWAIT:
	case  TIOCSETA:
	case  TIOCSETAF:
	case  TIOCSETAW:
	case  TIOCSETD:
	case  TIOCSPGRP:
	case  TIOCSTART:
	case  TIOCSTAT:
	case  TIOCSTI:
	case  TIOCSTOP:
	case  TIOCSWINSZ:
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
	case  TIOCLBIC:
	case  TIOCLBIS:
	case  TIOCLSET:
	case  TIOCSETC:
	case OTIOCSETD:
	case  TIOCSETN:
	case  TIOCSETP:
	case  TIOCSLTC:
#endif
		while (isbackground(p, tp) && !(p->p_flags & P_PPWAIT) &&
		    !SIGISMEMBER(p->p_sigignore, SIGTTOU) &&
		    !SIGISMEMBER(lp->lwp_sigmask, SIGTTOU)) {
			if (p->p_pgrp->pg_jobc == 0) {
				lwkt_reltoken(&p->p_token);
				lwkt_reltoken(&proc_token);
				lwkt_reltoken(&tty_token);
				return (EIO);
			}
			pgsignal(p->p_pgrp, SIGTTOU, 1);
			error = ttysleep(tp, &lbolt, PCATCH, "ttybg1",
					 0);
			if (error) {
				lwkt_reltoken(&p->p_token);
				lwkt_reltoken(&proc_token);
				lwkt_reltoken(&tty_token);
				return (error);
			}
		}
		break;
	}

	switch (cmd) {			/* Process the ioctl. */
	case FIOASYNC:			/* set/clear async i/o */
		crit_enter();
		if (*(int *)data)
			SET(tp->t_state, TS_ASYNC);
		else
			CLR(tp->t_state, TS_ASYNC);
		crit_exit();
		break;
	case FIONREAD:			/* get # bytes to read */
		crit_enter();
		*(int *)data = ttnread(tp);
		crit_exit();
		break;

	case FIOSETOWN:
		/*
		 * Policy -- Don't allow FIOSETOWN on someone else's 
		 *           controlling tty
		 */
		if (tp->t_session != NULL && !isctty(p, tp)) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (ENOTTY);
		}

		error = fsetown(*(int *)data, &tp->t_sigio);
		if (error) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (error);
		}
		break;
	case FIOGETOWN:
		if (tp->t_session != NULL && !isctty(p, tp)) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (ENOTTY);
		}
		*(int *)data = fgetown(&tp->t_sigio);
		break;

	case TIOCEXCL:			/* set exclusive use of tty */
		crit_enter();
		SET(tp->t_state, TS_XCLUDE);
		crit_exit();
		break;
	case TIOCFLUSH: {		/* flush buffers */
		int flags = *(int *)data;

		if (flags == 0)
			flags = FREAD | FWRITE;
		else
			flags &= FREAD | FWRITE;
		ttyflush(tp, flags);
		break;
	}
	case TIOCCONS:			/* become virtual console */
		if (*(int *)data) {
			if (constty && constty != tp &&
			    ISSET(constty->t_state, TS_CONNECTED)) {
				lwkt_reltoken(&p->p_token);
				lwkt_reltoken(&proc_token);
				lwkt_reltoken(&tty_token);
				return (EBUSY);
			}
#ifndef	UCONSOLE
			if ((error = priv_check(td, PRIV_ROOT)) != 0) {
				lwkt_reltoken(&p->p_token);
				lwkt_reltoken(&proc_token);
				lwkt_reltoken(&tty_token);
				return (error);
			}
#endif
			constty = tp;
		} else if (tp == constty)
			constty = NULL;
		break;
	case TIOCDRAIN:			/* wait till output drained */
		error = ttywait(tp);
		if (error) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (error);
		}
		break;
	case TIOCGETA: {		/* get termios struct */
		struct termios *t = (struct termios *)data;

		bcopy(&tp->t_termios, t, sizeof(struct termios));
		break;
	}
	case TIOCGETD:			/* get line discipline */
		*(int *)data = tp->t_line;
		break;
	case TIOCGWINSZ:		/* get window size */
		*(struct winsize *)data = tp->t_winsize;
		break;
	case TIOCGPGRP:			/* get pgrp of tty */
		if (!isctty(p, tp)) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (ENOTTY);
		}
		*(int *)data = tp->t_pgrp ? tp->t_pgrp->pg_id : NO_PID;
		break;
	case TIOCGSID:                  /* get sid of tty */
		if (!isctty(p, tp)) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (ENOTTY);
		}
		*(int *)data = tp->t_session->s_sid;
		break;
#ifdef TIOCHPCL
	case TIOCHPCL:			/* hang up on last close */
		crit_enter();
		SET(tp->t_cflag, HUPCL);
		crit_exit();
		break;
#endif
	case TIOCNXCL:			/* reset exclusive use of tty */
		crit_enter();
		CLR(tp->t_state, TS_XCLUDE);
		crit_exit();
		break;
	case TIOCOUTQ:			/* output queue size */
		*(int *)data = tp->t_outq.c_cc;
		break;
	case TIOCSETA:			/* set termios struct */
	case TIOCSETAW:			/* drain output, set */
	case TIOCSETAF: {		/* drn out, fls in, set */
		struct termios *t = (struct termios *)data;

		if (t->c_ispeed == 0)
			t->c_ispeed = t->c_ospeed;
		if (t->c_ispeed == 0)
			t->c_ispeed = tp->t_ospeed;
		if (t->c_ispeed == 0) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (EINVAL);
		}
		crit_enter();
		if (cmd == TIOCSETAW || cmd == TIOCSETAF) {
			error = ttywait(tp);
			if (error) {
				crit_exit();
				lwkt_reltoken(&p->p_token);
				lwkt_reltoken(&proc_token);
				lwkt_reltoken(&tty_token);
				return (error);
			}
			if (cmd == TIOCSETAF)
				ttyflush(tp, FREAD);
		}
		if (!ISSET(t->c_cflag, CIGNORE)) {
			/*
			 * Set device hardware.
			 */
			if (tp->t_param && (error = (*tp->t_param)(tp, t))) {
				crit_exit();
				lwkt_reltoken(&p->p_token);
				lwkt_reltoken(&proc_token);
				lwkt_reltoken(&tty_token);
				return (error);
			}
			if (ISSET(t->c_cflag, CLOCAL) &&
			    !ISSET(tp->t_cflag, CLOCAL)) {
				/*
				 * XXX disconnections would be too hard to
				 * get rid of without this kludge.  The only
				 * way to get rid of controlling terminals
				 * is to exit from the session leader.
				 */
				CLR(tp->t_state, TS_ZOMBIE);

				wakeup(TSA_CARR_ON(tp));
				ttwakeup(tp);
				ttwwakeup(tp);
			}
			if ((ISSET(tp->t_state, TS_CARR_ON) ||
			     ISSET(t->c_cflag, CLOCAL)) &&
			    !ISSET(tp->t_state, TS_ZOMBIE))
				SET(tp->t_state, TS_CONNECTED);
			else
				CLR(tp->t_state, TS_CONNECTED);
			tp->t_cflag = t->c_cflag;
			tp->t_ispeed = t->c_ispeed;
			if (t->c_ospeed != 0)
				tp->t_ospeed = t->c_ospeed;
			ttsetwater(tp);
		}
		if (ISSET(t->c_lflag, ICANON) != ISSET(tp->t_lflag, ICANON) &&
		    cmd != TIOCSETAF) {
			if (ISSET(t->c_lflag, ICANON))
				SET(tp->t_lflag, PENDIN);
			else {
				/*
				 * XXX we really shouldn't allow toggling
				 * ICANON while we're in a non-termios line
				 * discipline.  Now we have to worry about
				 * panicing for a null queue.
				 */
				if (tp->t_canq.c_cbreserved > 0 &&
				    tp->t_rawq.c_cbreserved > 0) {
					catq(&tp->t_rawq, &tp->t_canq);
					/*
					 * XXX the queue limits may be
					 * different, so the old queue
					 * swapping method no longer works.
					 */
					catq(&tp->t_canq, &tp->t_rawq);
				}
				CLR(tp->t_lflag, PENDIN);
			}
			ttwakeup(tp);
		}
		tp->t_iflag = t->c_iflag;
		tp->t_oflag = t->c_oflag;
		/*
		 * Make the EXTPROC bit read only.
		 */
		if (ISSET(tp->t_lflag, EXTPROC))
			SET(t->c_lflag, EXTPROC);
		else
			CLR(t->c_lflag, EXTPROC);
		tp->t_lflag = t->c_lflag | ISSET(tp->t_lflag, PENDIN);
		if (t->c_cc[VMIN] != tp->t_cc[VMIN] ||
		    t->c_cc[VTIME] != tp->t_cc[VTIME])
			ttwakeup(tp);
		bcopy(t->c_cc, tp->t_cc, sizeof(t->c_cc));
		crit_exit();
		break;
	}
	case TIOCSETD: {		/* set line discipline */
		int t = *(int *)data;
		cdev_t device = tp->t_dev;

		if ((u_int)t >= nlinesw) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (ENXIO);
		}
		if (t != tp->t_line) {
			crit_enter();
			(*linesw[tp->t_line].l_close)(tp, flag);
			error = (*linesw[t].l_open)(device, tp);
			if (error) {
				(void)(*linesw[tp->t_line].l_open)(device, tp);
				crit_exit();
				lwkt_reltoken(&p->p_token);
				lwkt_reltoken(&proc_token);
				lwkt_reltoken(&tty_token);
				return (error);
			}
			tp->t_line = t;
			crit_exit();
		}
		break;
	}
	case TIOCSTART:			/* start output, like ^Q */
		crit_enter();
		if (ISSET(tp->t_state, TS_TTSTOP) ||
		    ISSET(tp->t_lflag, FLUSHO)) {
			CLR(tp->t_lflag, FLUSHO);
			CLR(tp->t_state, TS_TTSTOP);
			ttstart(tp);
		}
		crit_exit();
		break;
	case TIOCSTI:			/* simulate terminal input */
		if ((flag & FREAD) == 0 && priv_check(td, PRIV_ROOT)) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (EPERM);
		}
		if (!isctty(p, tp) && priv_check(td, PRIV_ROOT)) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (EACCES);
		}
		crit_enter();
		(*linesw[tp->t_line].l_rint)(*(u_char *)data, tp);
		crit_exit();
		break;
	case TIOCSTOP:			/* stop output, like ^S */
		crit_enter();
		if (!ISSET(tp->t_state, TS_TTSTOP)) {
			SET(tp->t_state, TS_TTSTOP);
			(*tp->t_stop)(tp, 0);
		}
		crit_exit();
		break;
	case TIOCSCTTY:			/* become controlling tty */
		/* Session ctty vnode pointer set in vnode layer. */
		if (!SESS_LEADER(p) ||
		    ((p->p_session->s_ttyvp || tp->t_session) &&
		    (tp->t_session != p->p_session))) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (EPERM);
		}
		ttyhold(tp);
		tp->t_session = p->p_session;
		opgrp = tp->t_pgrp;
		pgref(p->p_pgrp);
		tp->t_pgrp = p->p_pgrp;
		otp = p->p_session->s_ttyp;
		p->p_session->s_ttyp = tp;
		p->p_flags |= P_CONTROLT;
		if (otp)
			ttyunhold(otp);
		if (opgrp) {
			pgrel(opgrp);
			opgrp = NULL;
		}
		break;
	case TIOCSPGRP: {		/* set pgrp of tty */
		pid_t pgid = *(int *)data;

		if (!isctty(p, tp)) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (ENOTTY);
		}
		else if (pgid < 1 || pgid > PID_MAX) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (EINVAL);
		} else {
			struct pgrp *pgrp = pgfind(pgid);
			if (pgrp == NULL || pgrp->pg_session != p->p_session) {
				if (pgrp)
					pgrel(pgrp);
				lwkt_reltoken(&p->p_token);
				lwkt_reltoken(&proc_token);
				lwkt_reltoken(&tty_token);
				return (EPERM);
			}
			opgrp = tp->t_pgrp;
			tp->t_pgrp = pgrp;
			if (opgrp) {
				pgrel(opgrp);
				opgrp = NULL;
			}
		}
		break;
	}
	case TIOCSTAT:			/* simulate control-T */
		crit_enter();
		ttyinfo(tp);
		crit_exit();
		break;
	case TIOCSWINSZ:		/* set window size */
		if (bcmp((caddr_t)&tp->t_winsize, data,
		    sizeof (struct winsize))) {
			tp->t_winsize = *(struct winsize *)data;
			pgsignal(tp->t_pgrp, SIGWINCH, 1);
		}
		break;
	case TIOCSDRAINWAIT:
		error = priv_check(td, PRIV_ROOT);
		if (error) {
			lwkt_reltoken(&p->p_token);
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (error);
		}
		tp->t_timeout = *(int *)data * hz;
		wakeup(TSA_OCOMPLETE(tp));
		wakeup(TSA_OLOWAT(tp));
		break;
	case TIOCGDRAINWAIT:
		*(int *)data = tp->t_timeout / hz;
		break;
	default:
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
		lwkt_reltoken(&p->p_token);
		lwkt_reltoken(&proc_token);
		lwkt_reltoken(&tty_token);
		return (ttcompat(tp, cmd, data, flag));
#else
		lwkt_reltoken(&p->p_token);
		lwkt_reltoken(&proc_token);
		lwkt_reltoken(&tty_token);
		return (ENOIOCTL);
#endif
	}
	lwkt_reltoken(&p->p_token);
	lwkt_reltoken(&proc_token);
	lwkt_reltoken(&tty_token);
	return (0);
}

static struct filterops ttyread_filtops =
	{ FILTEROP_ISFD|FILTEROP_MPSAFE, NULL, filt_ttyrdetach, filt_ttyread };
static struct filterops ttywrite_filtops =
	{ FILTEROP_ISFD|FILTEROP_MPSAFE, NULL, filt_ttywdetach, filt_ttywrite };

int
ttykqfilter(struct dev_kqfilter_args *ap)
{
	cdev_t dev = ap->a_head.a_dev;
	struct knote *kn = ap->a_kn;
	struct tty *tp = dev->si_tty;
	struct klist *klist;

	ap->a_result = 0;

	lwkt_gettoken(&tty_token);
	switch (kn->kn_filter) {
	case EVFILT_READ:
		klist = &tp->t_rkq.ki_note;
		kn->kn_fop = &ttyread_filtops;
		break;
	case EVFILT_WRITE:
		klist = &tp->t_wkq.ki_note;
		kn->kn_fop = &ttywrite_filtops;
		break;
	default:
		ap->a_result = EOPNOTSUPP;
		lwkt_reltoken(&tty_token);
		return (0);
	}
	lwkt_reltoken(&tty_token);
	kn->kn_hook = (caddr_t)dev;
	knote_insert(klist, kn);

	return (0);
}

static void
filt_ttyrdetach(struct knote *kn)
{
	struct tty *tp = ((cdev_t)kn->kn_hook)->si_tty;

	lwkt_gettoken(&tty_token);
	knote_remove(&tp->t_rkq.ki_note, kn);
	lwkt_reltoken(&tty_token);
}

static int
filt_ttyread(struct knote *kn, long hint)
{
	struct tty *tp = ((cdev_t)kn->kn_hook)->si_tty;

	lwkt_gettoken(&tty_token);
	kn->kn_data = ttnread(tp);
	if (ISSET(tp->t_state, TS_ZOMBIE)) {
		kn->kn_flags |= (EV_EOF | EV_NODATA);
		lwkt_reltoken(&tty_token);
		return (1);
	}
	lwkt_reltoken(&tty_token);
	return (kn->kn_data > 0);
}

static void
filt_ttywdetach(struct knote *kn)
{
	struct tty *tp = ((cdev_t)kn->kn_hook)->si_tty;

	lwkt_gettoken(&tty_token);
	knote_remove(&tp->t_wkq.ki_note, kn);
	lwkt_reltoken(&tty_token);
}

static int
filt_ttywrite(struct knote *kn, long hint)
{
	struct tty *tp = ((cdev_t)kn->kn_hook)->si_tty;
	int ret;

	lwkt_gettoken(&tty_token);
	kn->kn_data = tp->t_outq.c_cc;
	if (ISSET(tp->t_state, TS_ZOMBIE)) {
		lwkt_reltoken(&tty_token);
		return (1);
	}
	ret = (kn->kn_data <= tp->t_olowat &&
	    ISSET(tp->t_state, TS_CONNECTED));
	lwkt_reltoken(&tty_token);
	return ret;
}

/*
 * Must be called while in a critical section.
 * NOTE: tty_token must be held.
 */
static int
ttnread(struct tty *tp)
{
	int nread;

	ASSERT_LWKT_TOKEN_HELD(&tty_token);
	if (ISSET(tp->t_lflag, PENDIN))
		ttypend(tp);
	nread = tp->t_canq.c_cc;
	if (!ISSET(tp->t_lflag, ICANON)) {
		nread += tp->t_rawq.c_cc;
		if (nread < tp->t_cc[VMIN] && tp->t_cc[VTIME] == 0)
			nread = 0;
	}
	return (nread);
}

/*
 * Wait for output to drain.
 */
int
ttywait(struct tty *tp)
{
	int error;

	error = 0;
	crit_enter();
	lwkt_gettoken(&tty_token);
	while ((tp->t_outq.c_cc || ISSET(tp->t_state, TS_BUSY)) &&
	       ISSET(tp->t_state, TS_CONNECTED) && tp->t_oproc) {
		(*tp->t_oproc)(tp);
		if ((tp->t_outq.c_cc || ISSET(tp->t_state, TS_BUSY)) &&
		    ISSET(tp->t_state, TS_CONNECTED)) {
			SET(tp->t_state, TS_SO_OCOMPLETE);
			error = ttysleep(tp, TSA_OCOMPLETE(tp),
					 PCATCH, "ttywai",
					 tp->t_timeout);
			if (error) {
				if (error == EWOULDBLOCK)
					error = EIO;
				break;
			}
		} else
			break;
	}
	if (!error && (tp->t_outq.c_cc || ISSET(tp->t_state, TS_BUSY)))
		error = EIO;
	lwkt_reltoken(&tty_token);
	crit_exit();
	return (error);
}

/*
 * Flush if successfully wait.
 */
static int
ttywflush(struct tty *tp)
{
	int error;

	if ((error = ttywait(tp)) == 0)
		ttyflush(tp, FREAD);
	return (error);
}

/*
 * Flush tty read and/or write queues, notifying anyone waiting.
 */
void
ttyflush(struct tty *tp, int rw)
{
	crit_enter();
	lwkt_gettoken(&tty_token);
#if 0
again:
#endif
	if (rw & FWRITE) {
		FLUSHQ(&tp->t_outq);
		CLR(tp->t_state, TS_TTSTOP);
	}
	(*tp->t_stop)(tp, rw);
	if (rw & FREAD) {
		FLUSHQ(&tp->t_canq);
		FLUSHQ(&tp->t_rawq);
		CLR(tp->t_lflag, PENDIN);
		tp->t_rocount = 0;
		tp->t_rocol = 0;
		CLR(tp->t_state, TS_LOCAL);
		ttwakeup(tp);
		if (ISSET(tp->t_state, TS_TBLOCK)) {
			if (rw & FWRITE)
				FLUSHQ(&tp->t_outq);
			ttyunblock(tp);

			/*
			 * Don't let leave any state that might clobber the
			 * next line discipline (although we should do more
			 * to send the START char).  Not clearing the state
			 * may have caused the "putc to a clist with no
			 * reserved cblocks" panic/kprintf.
			 */
			CLR(tp->t_state, TS_TBLOCK);

#if 0 /* forget it, sleeping isn't always safe and we don't know when it is */
			if (ISSET(tp->t_iflag, IXOFF)) {
				/*
				 * XXX wait a bit in the hope that the stop
				 * character (if any) will go out.  Waiting
				 * isn't good since it allows races.  This
				 * will be fixed when the stop character is
				 * put in a special queue.  Don't bother with
				 * the checks in ttywait() since the timeout
				 * will save us.
				 */
				SET(tp->t_state, TS_SO_OCOMPLETE);
				ttysleep(tp, TSA_OCOMPLETE(tp), 0,
					 "ttyfls", hz / 10);
				/*
				 * Don't try sending the stop character again.
				 */
				CLR(tp->t_state, TS_TBLOCK);
				goto again;
			}
#endif
		}
	}
	if (rw & FWRITE) {
		FLUSHQ(&tp->t_outq);
		ttwwakeup(tp);
	}
	lwkt_reltoken(&tty_token);
	crit_exit();
}

/*
 * Copy in the default termios characters.
 */
void
termioschars(struct termios *t)
{
	lwkt_gettoken(&tty_token);
	bcopy(ttydefchars, t->c_cc, sizeof t->c_cc);
	lwkt_reltoken(&tty_token);
}

/*
 * Old interface.
 */
void
ttychars(struct tty *tp)
{
	lwkt_gettoken(&tty_token);
	termioschars(&tp->t_termios);
	lwkt_reltoken(&tty_token);
}

/*
 * Handle input high water.  Send stop character for the IXOFF case.  Turn
 * on our input flow control bit and propagate the changes to the driver.
 * XXX the stop character should be put in a special high priority queue.
 */
void
ttyblock(struct tty *tp)
{
	lwkt_gettoken(&tty_token);
	SET(tp->t_state, TS_TBLOCK);
	if (ISSET(tp->t_iflag, IXOFF) && tp->t_cc[VSTOP] != _POSIX_VDISABLE &&
	    clist_putc(tp->t_cc[VSTOP], &tp->t_outq) != 0)
		CLR(tp->t_state, TS_TBLOCK);	/* try again later */
	ttstart(tp);
	lwkt_reltoken(&tty_token);
}

/*
 * Handle input low water.  Send start character for the IXOFF case.  Turn
 * off our input flow control bit and propagate the changes to the driver.
 * XXX the start character should be put in a special high priority queue.
 */
static void
ttyunblock(struct tty *tp)
{
	lwkt_gettoken(&tty_token);
	CLR(tp->t_state, TS_TBLOCK);
	if (ISSET(tp->t_iflag, IXOFF) && tp->t_cc[VSTART] != _POSIX_VDISABLE &&
	    clist_putc(tp->t_cc[VSTART], &tp->t_outq) != 0)
		SET(tp->t_state, TS_TBLOCK);	/* try again later */
	ttstart(tp);
	lwkt_reltoken(&tty_token);
}

#ifdef notyet
/* Not used by any current (i386) drivers. */
/*
 * Restart after an inter-char delay.
 */
void
ttrstrt(void *tp_arg)
{
	struct tty *tp;

	KASSERT(tp_arg != NULL, ("ttrstrt"));

	tp = tp_arg;
	crit_enter();
	lwkt_gettoken(&tty_token);
	CLR(tp->t_state, TS_TIMEOUT);
	ttstart(tp);
	lwkt_reltoken(&tty_token);
	crit_exit();
}
#endif

int
ttstart(struct tty *tp)
{
	lwkt_gettoken(&tty_token);
	if (tp->t_oproc != NULL)	/* XXX: Kludge for pty. */
		(*tp->t_oproc)(tp);
	lwkt_reltoken(&tty_token);
	return (0);
}

/*
 * "close" a line discipline
 */
int
ttylclose(struct tty *tp, int flag)
{
	lwkt_gettoken(&tty_token);
	if (flag & FNONBLOCK || ttywflush(tp))
		ttyflush(tp, FREAD | FWRITE);
	lwkt_reltoken(&tty_token);
	return (0);
}

void
ttyhold(struct tty *tp)
{
	++tp->t_refs;
}

void
ttyunhold(struct tty *tp)
{
	if (tp->t_unhold)
		tp->t_unhold(tp);
	else
		--tp->t_refs;
}

/*
 * Handle modem control transition on a tty.
 * Flag indicates new state of carrier.
 * Returns 0 if the line should be turned off, otherwise 1.
 */
int
ttymodem(struct tty *tp, int flag)
{
	lwkt_gettoken(&tty_token);
	if (ISSET(tp->t_state, TS_CARR_ON) && ISSET(tp->t_cflag, MDMBUF)) {
		/*
		 * MDMBUF: do flow control according to carrier flag
		 * XXX TS_CAR_OFLOW doesn't do anything yet.  TS_TTSTOP
		 * works if IXON and IXANY are clear.
		 */
		if (flag) {
			CLR(tp->t_state, TS_CAR_OFLOW);
			CLR(tp->t_state, TS_TTSTOP);
			ttstart(tp);
		} else if (!ISSET(tp->t_state, TS_CAR_OFLOW)) {
			SET(tp->t_state, TS_CAR_OFLOW);
			SET(tp->t_state, TS_TTSTOP);
			(*tp->t_stop)(tp, 0);
		}
	} else if (flag == 0) {
		/*
		 * Lost carrier.
		 */
		CLR(tp->t_state, TS_CARR_ON);
		if (ISSET(tp->t_state, TS_ISOPEN) &&
		    !ISSET(tp->t_cflag, CLOCAL)) {
			SET(tp->t_state, TS_ZOMBIE);
			CLR(tp->t_state, TS_CONNECTED);
			if (tp->t_session && tp->t_session->s_leader)
				ksignal(tp->t_session->s_leader, SIGHUP);
			ttyflush(tp, FREAD | FWRITE);
			lwkt_reltoken(&tty_token);
			return (0);
		}
	} else {
		/*
		 * Carrier now on.
		 */
		SET(tp->t_state, TS_CARR_ON);
		if (!ISSET(tp->t_state, TS_ZOMBIE))
			SET(tp->t_state, TS_CONNECTED);
		wakeup(TSA_CARR_ON(tp));
		ttwakeup(tp);
		ttwwakeup(tp);
	}
	lwkt_reltoken(&tty_token);
	return (1);
}

/*
 * Reinput pending characters after state switch
 * call from a critical section.
 */
static void
ttypend(struct tty *tp)
{
	struct clist tq;
	int c;

	lwkt_gettoken(&tty_token);
	CLR(tp->t_lflag, PENDIN);
	SET(tp->t_state, TS_TYPEN);
	/*
	 * XXX this assumes too much about clist internals.  It may even
	 * fail if the cblock slush pool is empty.  We can't allocate more
	 * cblocks here because we are called from an interrupt handler
	 * and clist_alloc_cblocks() can wait.
	 */
	tq = tp->t_rawq;
	bzero(&tp->t_rawq, sizeof tp->t_rawq);
	tp->t_rawq.c_cbmax = tq.c_cbmax;
	tp->t_rawq.c_cbreserved = tq.c_cbreserved;
	while ((c = clist_getc(&tq)) >= 0)
		ttyinput(c, tp);
	CLR(tp->t_state, TS_TYPEN);
	lwkt_reltoken(&tty_token);
}

/*
 * Process a read call on a tty device.
 */
int
ttread(struct tty *tp, struct uio *uio, int flag)
{
	struct clist *qp;
	int c;
	tcflag_t lflag;
	cc_t *cc = tp->t_cc;
	struct proc *pp;
	struct lwp *lp;
	int first, error = 0;
	int has_stime = 0, last_cc = 0;
	long slp = 0;		/* XXX this should be renamed `timo'. */
	struct timeval stime;

	lp = curthread->td_lwp;
	stime.tv_sec = 0;	/* fix compiler warnings */
	stime.tv_usec = 0;

	lwkt_gettoken(&tty_token);
loop:
	crit_enter();
	lflag = tp->t_lflag;
	/*
	 * take pending input first
	 */
	if (ISSET(lflag, PENDIN)) {
		ttypend(tp);
		splz();		/* reduce latency */
		lflag = tp->t_lflag;	/* XXX ttypend() clobbers it */
	}

	/*
	 * Hang process if it's in the background.
	 */
	lwkt_gettoken(&proc_token);
	if ((pp = curproc) && isbackground(pp, tp)) {
		crit_exit();
		if (SIGISMEMBER(pp->p_sigignore, SIGTTIN) ||
		    SIGISMEMBER(lp->lwp_sigmask, SIGTTIN) ||
		    (pp->p_flags & P_PPWAIT) || pp->p_pgrp->pg_jobc == 0) {
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (EIO);
		}
		pgsignal(pp->p_pgrp, SIGTTIN, 1);
		error = ttysleep(tp, &lbolt, PCATCH, "ttybg2", 0);
		if (error) {
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return (error);
		}
		lwkt_reltoken(&proc_token);
		goto loop;
	}
	lwkt_reltoken(&proc_token);

	if (ISSET(tp->t_state, TS_ZOMBIE)) {
		crit_exit();
		lwkt_reltoken(&tty_token);
		return (0);	/* EOF */
	}

	/*
	 * If canonical, use the canonical queue,
	 * else use the raw queue.
	 *
	 * (should get rid of clists...)
	 */
	qp = ISSET(lflag, ICANON) ? &tp->t_canq : &tp->t_rawq;

	if (flag & IO_NDELAY) {
		if (qp->c_cc > 0)
			goto read;
		if (!ISSET(lflag, ICANON) && cc[VMIN] == 0) {
			crit_exit();
			lwkt_reltoken(&tty_token);
			return (0);
		}
		crit_exit();
		lwkt_reltoken(&tty_token);
		return (EWOULDBLOCK);
	}
	if (!ISSET(lflag, ICANON)) {
		int m = cc[VMIN];
		long t = cc[VTIME];
		struct timeval timecopy;

		/*
		 * Check each of the four combinations.
		 * (m > 0 && t == 0) is the normal read case.
		 * It should be fairly efficient, so we check that and its
		 * companion case (m == 0 && t == 0) first.
		 * For the other two cases, we compute the target sleep time
		 * into slp.
		 */
		if (t == 0) {
			if (qp->c_cc < m)
				goto sleep;
			if (qp->c_cc > 0)
				goto read;

			/* m, t and qp->c_cc are all 0.  0 is enough input. */
			crit_exit();
			lwkt_reltoken(&tty_token);
			return (0);
		}
		t *= 100000;		/* time in us */
#define diff(t1, t2) (((t1).tv_sec - (t2).tv_sec) * 1000000 + \
			 ((t1).tv_usec - (t2).tv_usec))
		if (m > 0) {
			if (qp->c_cc <= 0)
				goto sleep;
			if (qp->c_cc >= m)
				goto read;
			getmicrotime(&timecopy);
			if (has_stime == 0) {
				/* first character, start timer */
				has_stime = 1;
				stime = timecopy;
				slp = t;
			} else if (qp->c_cc > last_cc) {
				/* got a character, restart timer */
				stime = timecopy;
				slp = t;
			} else {
				/* nothing, check expiration */
				slp = t - diff(timecopy, stime);
				if (slp <= 0)
					goto read;
			}
			last_cc = qp->c_cc;
		} else {	/* m == 0 */
			if (qp->c_cc > 0)
				goto read;
			getmicrotime(&timecopy);
			if (has_stime == 0) {
				has_stime = 1;
				stime = timecopy;
				slp = t;
			} else {
				slp = t - diff(timecopy, stime);
				if (slp <= 0) {
					/* Timed out, but 0 is enough input. */
					crit_exit();
					lwkt_reltoken(&tty_token);
					return (0);
				}
			}
		}
#undef diff
		/*
		 * Rounding down may make us wake up just short
		 * of the target, so we round up.
		 * The formula is ceiling(slp * hz/1000000).
		 * 32-bit arithmetic is enough for hz < 169.
		 * XXX see tvtohz() for how to avoid overflow if hz
		 * is large (divide by `tick' and/or arrange to
		 * use tvtohz() if hz is large).
		 */
		slp = (long) (((u_long)slp * hz) + 999999) / 1000000;
		goto sleep;
	}
	if (qp->c_cc <= 0) {
sleep:
		/*
		 * There is no input, or not enough input and we can block.
		 */
		error = ttysleep(tp, TSA_HUP_OR_INPUT(tp), PCATCH,
				 ISSET(tp->t_state, TS_CONNECTED) ?
				 "ttyin" : "ttyhup", (int)slp);
		crit_exit();
		if (error == EWOULDBLOCK)
			error = 0;
		else if (error) {
			lwkt_reltoken(&tty_token);
			return (error);
		}
		/*
		 * XXX what happens if another process eats some input
		 * while we are asleep (not just here)?  It would be
		 * safest to detect changes and reset our state variables
		 * (has_stime and last_cc).
		 */
		slp = 0;
		goto loop;
	}
read:
	crit_exit();
	/*
	 * Input present, check for input mapping and processing.
	 */
	first = 1;
	if (ISSET(lflag, ICANON | ISIG))
		goto slowcase;
	for (;;) {
		char ibuf[IBUFSIZ];
		int icc;

		icc = (int)szmin(uio->uio_resid, IBUFSIZ);
		icc = q_to_b(qp, ibuf, icc);
		if (icc <= 0) {
			if (first)
				goto loop;
			break;
		}
		error = uiomove(ibuf, (size_t)icc, uio);
		/*
		 * XXX if there was an error then we should ungetc() the
		 * unmoved chars and reduce icc here.
		 */
		if (error)
			break;
		if (uio->uio_resid == 0)
			break;
		first = 0;
	}
	goto out;
slowcase:
	for (;;) {
		c = clist_getc(qp);
		if (c < 0) {
			if (first)
				goto loop;
			break;
		}
		/*
		 * delayed suspend (^Y)
		 */
		if (CCEQ(cc[VDSUSP], c) &&
		    ISSET(lflag, IEXTEN | ISIG) == (IEXTEN | ISIG)) {
			pgsignal(tp->t_pgrp, SIGTSTP, 1);
			if (first) {
				error = ttysleep(tp, &lbolt, PCATCH,
						 "ttybg3", 0);
				if (error)
					break;
				goto loop;
			}
			break;
		}
		/*
		 * Interpret EOF only in canonical mode.
		 */
		if (CCEQ(cc[VEOF], c) && ISSET(lflag, ICANON))
			break;
		/*
		 * Give user character.
		 */
		error = ureadc(c, uio);
		if (error)
			/* XXX should ungetc(c, qp). */
			break;
		if (uio->uio_resid == 0)
			break;
		/*
		 * In canonical mode check for a "break character"
		 * marking the end of a "line of input".
		 */
		if (ISSET(lflag, ICANON) && TTBREAKC(c, lflag))
			break;
		first = 0;
	}

out:
	/*
	 * Look to unblock input now that (presumably)
	 * the input queue has gone down.
	 */
	crit_enter();
	if (ISSET(tp->t_state, TS_TBLOCK) &&
	    tp->t_rawq.c_cc + tp->t_canq.c_cc <= tp->t_ilowat)
		ttyunblock(tp);
	crit_exit();

	lwkt_reltoken(&tty_token);
	return (error);
}

/*
 * Check the output queue on tp for space for a kernel message (from uprintf
 * or tprintf).  Allow some space over the normal hiwater mark so we don't
 * lose messages due to normal flow control, but don't let the tty run amok.
 * Sleeps here are not interruptible, but we return prematurely if new signals
 * arrive.
 */
int
ttycheckoutq(struct tty *tp, int wait)
{
	struct lwp *lp = curthread->td_lwp;
	int hiwat;
	sigset_t oldset, newset;

	lwkt_gettoken(&tty_token);
	hiwat = tp->t_ohiwat;
	SIGEMPTYSET(oldset);
	SIGEMPTYSET(newset);
	crit_enter();
	if (wait)
		oldset = lwp_sigpend(lp);
	if (tp->t_outq.c_cc > hiwat + OBUFSIZ + 100) {
		while (tp->t_outq.c_cc > hiwat) {
			ttstart(tp);
			if (tp->t_outq.c_cc <= hiwat)
				break;
			if (wait)
				newset = lwp_sigpend(lp);
			if (!wait || SIGSETNEQ(oldset, newset)) {
				crit_exit();
				lwkt_reltoken(&tty_token);
				return (0);
			}
			SET(tp->t_state, TS_SO_OLOWAT);
			tsleep(TSA_OLOWAT(tp), 0, "ttoutq", hz);
		}
	}
	crit_exit();
	lwkt_reltoken(&tty_token);
	return (1);
}

/*
 * Process a write call on a tty device.
 */
int
ttwrite(struct tty *tp, struct uio *uio, int flag)
{
	char *cp = NULL;
	int cc, ce;
	struct proc *pp;
	struct lwp *lp;
	int i, hiwat, error;
	size_t cnt;

	char obuf[OBUFSIZ];

	lwkt_gettoken(&tty_token);
	lp = curthread->td_lwp;
	hiwat = tp->t_ohiwat;
	cnt = uio->uio_resid;
	error = 0;
	cc = 0;
loop:
	crit_enter();
	if (ISSET(tp->t_state, TS_ZOMBIE)) {
		crit_exit();
		if (uio->uio_resid == cnt)
			error = EIO;
		goto out;
	}
	if (!ISSET(tp->t_state, TS_CONNECTED)) {
		if (flag & IO_NDELAY) {
			crit_exit();
			error = EWOULDBLOCK;
			goto out;
		}
		error = ttysleep(tp, TSA_CARR_ON(tp), PCATCH, "ttydcd", 0);
		crit_exit();
		if (error)
			goto out;
		goto loop;
	}
	crit_exit();

	/*
	 * Hang the process if it's in the background.
	 */
	lwkt_gettoken(&proc_token);
	if ((pp = curproc) && isbackground(pp, tp) &&
	    ISSET(tp->t_lflag, TOSTOP) && !(pp->p_flags & P_PPWAIT) &&
	    !SIGISMEMBER(pp->p_sigignore, SIGTTOU) &&
	    !SIGISMEMBER(lp->lwp_sigmask, SIGTTOU)) {
		if (pp->p_pgrp->pg_jobc == 0) {
			error = EIO;
			lwkt_reltoken(&proc_token);
			goto out;
		}
		pgsignal(pp->p_pgrp, SIGTTOU, 1);
		lwkt_reltoken(&proc_token);
		error = ttysleep(tp, &lbolt, PCATCH, "ttybg4", 0);
		if (error)
			goto out;
		goto loop;
	}
	lwkt_reltoken(&proc_token);
	/*
	 * Process the user's data in at most OBUFSIZ chunks.  Perform any
	 * output translation.  Keep track of high water mark, sleep on
	 * overflow awaiting device aid in acquiring new space.
	 */
	while (uio->uio_resid > 0 || cc > 0) {
		if (ISSET(tp->t_lflag, FLUSHO)) {
			uio->uio_resid = 0;
			lwkt_reltoken(&tty_token);
			return (0);
		}
		if (tp->t_outq.c_cc > hiwat)
			goto ovhiwat;
		/*
		 * Grab a hunk of data from the user, unless we have some
		 * leftover from last time.
		 */
		if (cc == 0) {
			cc = szmin(uio->uio_resid, OBUFSIZ);
			cp = obuf;
			error = uiomove(cp, (size_t)cc, uio);
			if (error) {
				cc = 0;
				break;
			}
		}
		/*
		 * If nothing fancy need be done, grab those characters we
		 * can handle without any of ttyoutput's processing and
		 * just transfer them to the output q.  For those chars
		 * which require special processing (as indicated by the
		 * bits in char_type), call ttyoutput.  After processing
		 * a hunk of data, look for FLUSHO so ^O's will take effect
		 * immediately.
		 */
		while (cc > 0) {
			if (!ISSET(tp->t_oflag, OPOST))
				ce = cc;
			else {
				ce = cc - scanc((u_int)cc, (u_char *)cp,
						char_type, CCLASSMASK);
				/*
				 * If ce is zero, then we're processing
				 * a special character through ttyoutput.
				 */
				if (ce == 0) {
					tp->t_rocount = 0;
					if (ttyoutput(*cp, tp) >= 0) {
						/* No Clists, wait a bit. */
						ttstart(tp);
						if (flag & IO_NDELAY) {
							error = EWOULDBLOCK;
							goto out;
						}
						error = ttysleep(tp, &lbolt,
								 PCATCH,
								 "ttybf1", 0);
						if (error)
							goto out;
						goto loop;
					}
					cp++;
					cc--;
					if (ISSET(tp->t_lflag, FLUSHO) ||
					    tp->t_outq.c_cc > hiwat)
						goto ovhiwat;
					continue;
				}
			}
			/*
			 * A bunch of normal characters have been found.
			 * Transfer them en masse to the output queue and
			 * continue processing at the top of the loop.
			 * If there are any further characters in this
			 * <= OBUFSIZ chunk, the first should be a character
			 * requiring special handling by ttyoutput.
			 */
			tp->t_rocount = 0;
			i = b_to_q(cp, ce, &tp->t_outq);
			ce -= i;
			tp->t_column += ce;
			cp += ce, cc -= ce, tk_nout += ce;
			tp->t_outcc += ce;
			if (i > 0) {
				/* No Clists, wait a bit. */
				ttstart(tp);
				if (flag & IO_NDELAY) {
					error = EWOULDBLOCK;
					goto out;
				}
				error = ttysleep(tp, &lbolt, PCATCH,
						 "ttybf2", 0);
				if (error)
					goto out;
				goto loop;
			}
			if (ISSET(tp->t_lflag, FLUSHO) ||
			    tp->t_outq.c_cc > hiwat)
				break;
		}
		ttstart(tp);
	}
out:
	/*
	 * If cc is nonzero, we leave the uio structure inconsistent, as the
	 * offset and iov pointers have moved forward, but it doesn't matter
	 * (the call will either return short or restart with a new uio).
	 */
	uio->uio_resid += cc;
	lwkt_reltoken(&tty_token);
	return (error);

ovhiwat:
	ttstart(tp);
	crit_enter();
	/*
	 * This can only occur if FLUSHO is set in t_lflag,
	 * or if ttstart/oproc is synchronous (or very fast).
	 */
	if (tp->t_outq.c_cc <= hiwat) {
		crit_exit();
		goto loop;
	}
	if (flag & IO_NDELAY) {
		crit_exit();
		uio->uio_resid += cc;
		lwkt_reltoken(&tty_token);
		return (uio->uio_resid == cnt ? EWOULDBLOCK : 0);
	}
	SET(tp->t_state, TS_SO_OLOWAT);
	error = ttysleep(tp, TSA_OLOWAT(tp), PCATCH, "ttywri", tp->t_timeout);
	crit_exit();
	if (error == EWOULDBLOCK)
		error = EIO;
	if (error)
		goto out;
	goto loop;
}

/*
 * Rubout one character from the rawq of tp
 * as cleanly as possible.
 * NOTE: Must be called with tty_token held
 */
static void
ttyrub(int c, struct tty *tp)
{
	char *cp;
	int savecol;
	int tabc;

	ASSERT_LWKT_TOKEN_HELD(&tty_token);
	if (!ISSET(tp->t_lflag, ECHO) || ISSET(tp->t_lflag, EXTPROC))
		return;
	CLR(tp->t_lflag, FLUSHO);
	if (ISSET(tp->t_lflag, ECHOE)) {
		if (tp->t_rocount == 0) {
			/*
			 * Screwed by ttwrite; retype
			 */
			ttyretype(tp);
			return;
		}
		if (c == ('\t' | TTY_QUOTE) || c == ('\n' | TTY_QUOTE))
			ttyrubo(tp, 2);
		else {
			CLR(c, ~TTY_CHARMASK);
			switch (CCLASS(c)) {
			case ORDINARY:
				ttyrubo(tp, 1);
				break;
			case BACKSPACE:
			case CONTROL:
			case NEWLINE:
			case RETURN:
			case VTAB:
				if (ISSET(tp->t_lflag, ECHOCTL))
					ttyrubo(tp, 2);
				break;
			case TAB:
				if (tp->t_rocount < tp->t_rawq.c_cc) {
					ttyretype(tp);
					return;
				}
				crit_enter();
				savecol = tp->t_column;
				SET(tp->t_state, TS_CNTTB);
				SET(tp->t_lflag, FLUSHO);
				tp->t_column = tp->t_rocol;
				cp = tp->t_rawq.c_cf;
				if (cp)
					tabc = *cp;	/* XXX FIX NEXTC */
				for (; cp; cp = nextc(&tp->t_rawq, cp, &tabc))
					ttyecho(tabc, tp);
				CLR(tp->t_lflag, FLUSHO);
				CLR(tp->t_state, TS_CNTTB);
				crit_exit();

				/* savecol will now be length of the tab. */
				savecol -= tp->t_column;
				tp->t_column += savecol;
				if (savecol > 8)
					savecol = 8;	/* overflow screw */
				while (--savecol >= 0)
					(void)ttyoutput('\b', tp);
				break;
			default:			/* XXX */
#define	PANICSTR	"ttyrub: would panic c = %d, val = %d\n"
				(void)kprintf(PANICSTR, c, CCLASS(c));
#ifdef notdef
				panic(PANICSTR, c, CCLASS(c));
#endif
			}
		}
	} else if (ISSET(tp->t_lflag, ECHOPRT)) {
		if (!ISSET(tp->t_state, TS_ERASE)) {
			SET(tp->t_state, TS_ERASE);
			(void)ttyoutput('\\', tp);
		}
		ttyecho(c, tp);
	} else {
		ttyecho(tp->t_cc[VERASE], tp);
		/*
		 * This code may be executed not only when an ERASE key
		 * is pressed, but also when ^U (KILL) or ^W (WERASE) are.
		 * So, I didn't think it was worthwhile to pass the extra
		 * information (which would need an extra parameter,
		 * changing every call) needed to distinguish the ERASE2
		 * case from the ERASE.
		 */
	}
	--tp->t_rocount;
}

/*
 * Back over cnt characters, erasing them.
 * NOTE: Must be called with tty_token held
 */
static void
ttyrubo(struct tty *tp, int cnt)
{
	ASSERT_LWKT_TOKEN_HELD(&tty_token);
	while (cnt-- > 0) {
		(void)ttyoutput('\b', tp);
		(void)ttyoutput(' ', tp);
		(void)ttyoutput('\b', tp);
	}
}

/*
 * ttyretype --
 *	Reprint the rawq line.  Note, it is assumed that c_cc has already
 *	been checked.
 * NOTE: Must be called with tty_token held
 */
static void
ttyretype(struct tty *tp)
{
	char *cp;
	int c;

	ASSERT_LWKT_TOKEN_HELD(&tty_token);
	/* Echo the reprint character. */
	if (tp->t_cc[VREPRINT] != _POSIX_VDISABLE)
		ttyecho(tp->t_cc[VREPRINT], tp);

	(void)ttyoutput('\n', tp);

	/*
	 * XXX
	 * FIX: NEXTC IS BROKEN - DOESN'T CHECK QUOTE
	 * BIT OF FIRST CHAR.
	 */
	crit_enter();
	for (cp = tp->t_canq.c_cf, c = (cp != NULL ? *cp : 0);
	    cp != NULL; cp = nextc(&tp->t_canq, cp, &c))
		ttyecho(c, tp);
	for (cp = tp->t_rawq.c_cf, c = (cp != NULL ? *cp : 0);
	    cp != NULL; cp = nextc(&tp->t_rawq, cp, &c))
		ttyecho(c, tp);
	CLR(tp->t_state, TS_ERASE);
	crit_exit();

	tp->t_rocount = tp->t_rawq.c_cc;
	tp->t_rocol = 0;
}

/*
 * Echo a typed character to the terminal.
 * NOTE: Must be called with tty_token held
 */
static void
ttyecho(int c, struct tty *tp)
{
	ASSERT_LWKT_TOKEN_HELD(&tty_token);

	if (!ISSET(tp->t_state, TS_CNTTB))
		CLR(tp->t_lflag, FLUSHO);
	if ((!ISSET(tp->t_lflag, ECHO) &&
	     (c != '\n' || !ISSET(tp->t_lflag, ECHONL))) ||
	    ISSET(tp->t_lflag, EXTPROC))
		return;
	if (ISSET(tp->t_lflag, ECHOCTL) &&
	    ((ISSET(c, TTY_CHARMASK) <= 037 && c != '\t' && c != '\n') ||
	    ISSET(c, TTY_CHARMASK) == 0177)) {
		(void)ttyoutput('^', tp);
		CLR(c, ~TTY_CHARMASK);
		if (c == 0177)
			c = '?';
		else
			c += 'A' - 1;
	}
	(void)ttyoutput(c, tp);
}

/*
 * Wake up any readers on a tty.
 */
void
ttwakeup(struct tty *tp)
{
	lwkt_gettoken(&tty_token);
	if (ISSET(tp->t_state, TS_ASYNC) && tp->t_sigio != NULL)
		pgsigio(tp->t_sigio, SIGIO, (tp->t_session != NULL));
	wakeup(TSA_HUP_OR_INPUT(tp));
	KNOTE(&tp->t_rkq.ki_note, 0);
	lwkt_reltoken(&tty_token);
}

/*
 * Wake up any writers on a tty.
 */
void
ttwwakeup(struct tty *tp)
{
	lwkt_gettoken(&tty_token);
	if (ISSET(tp->t_state, TS_ASYNC) && tp->t_sigio != NULL)
		pgsigio(tp->t_sigio, SIGIO, (tp->t_session != NULL));
	if (ISSET(tp->t_state, TS_BUSY | TS_SO_OCOMPLETE) ==
	    TS_SO_OCOMPLETE && tp->t_outq.c_cc == 0) {
		CLR(tp->t_state, TS_SO_OCOMPLETE);
		wakeup(TSA_OCOMPLETE(tp));
	}
	if (ISSET(tp->t_state, TS_SO_OLOWAT) &&
	    tp->t_outq.c_cc <= tp->t_olowat) {
		CLR(tp->t_state, TS_SO_OLOWAT);
		wakeup(TSA_OLOWAT(tp));
	}
	KNOTE(&tp->t_wkq.ki_note, 0);
	lwkt_reltoken(&tty_token);
}

/*
 * Look up a code for a specified speed in a conversion table;
 * used by drivers to map software speed values to hardware parameters.
 * No requirements
 */
int
ttspeedtab(int speed, struct speedtab *table)
{

	for ( ; table->sp_speed != -1; table++)
		if (table->sp_speed == speed)
			return (table->sp_code);
	return (-1);
}

/*
 * Set input and output watermarks and buffer sizes.  For input, the
 * high watermark is about one second's worth of input above empty, the
 * low watermark is slightly below high water, and the buffer size is a
 * driver-dependent amount above high water.  For output, the watermarks
 * are near the ends of the buffer, with about 1 second's worth of input
 * between them.  All this only applies to the standard line discipline.
 */
void
ttsetwater(struct tty *tp)
{
	int cps, ttmaxhiwat, x;

	lwkt_gettoken(&tty_token);
	/* Input. */
	clist_alloc_cblocks(&tp->t_canq, TTYHOG, 512);
	switch (tp->t_ispeedwat) {
	case (speed_t)-1:
		cps = tp->t_ispeed / 10;
		break;
	case 0:
		/*
		 * This case is for old drivers that don't know about
		 * t_ispeedwat.  Arrange for them to get the old buffer
		 * sizes and watermarks.
		 */
		cps = TTYHOG - 2 * 256;
		tp->t_ififosize = 2 * 2048;
		break;
	default:
		cps = tp->t_ispeedwat / 10;
		break;
	}
	tp->t_ihiwat = cps;
	tp->t_ilowat = 7 * cps / 8;
	x = cps + tp->t_ififosize;
	clist_alloc_cblocks(&tp->t_rawq, x, x);

	/* Output. */
	switch (tp->t_ospeedwat) {
	case (speed_t)-1:
		cps = tp->t_ospeed / 10;
		ttmaxhiwat = 2 * TTMAXHIWAT;
		break;
	case 0:
		cps = tp->t_ospeed / 10;
		ttmaxhiwat = TTMAXHIWAT;
		break;
	default:
		cps = tp->t_ospeedwat / 10;
		ttmaxhiwat = 8 * TTMAXHIWAT;
		break;
	}
#define CLAMP(x, h, l)	((x) > h ? h : ((x) < l) ? l : (x))
	tp->t_olowat = x = CLAMP(cps / 2, TTMAXLOWAT, TTMINLOWAT);
	x += cps;
	x = CLAMP(x, ttmaxhiwat, TTMINHIWAT);	/* XXX clamps are too magic */
	tp->t_ohiwat = roundup(x, CBSIZE);	/* XXX for compat */
	x = imax(tp->t_ohiwat, TTMAXHIWAT);	/* XXX for compat/safety */
	x += OBUFSIZ + 100;
	clist_alloc_cblocks(&tp->t_outq, x, x);
#undef	CLAMP
	lwkt_reltoken(&tty_token);
}

/*
 * Report on state of foreground process group.
 */
void
ttyinfo(struct tty *tp)
{
	struct proc *p, *pick;
	struct lwp *lp;
	struct rusage ru;
	int tmp;

	if (ttycheckoutq(tp,0) == 0)
		return;

	lwkt_gettoken(&tty_token);
	lwkt_gettoken(&proc_token);
	/*
	 * We always print the load average, then figure out what else to
	 * print based on the state of the current process group.
	 */
	tmp = (averunnable.ldavg[0] * 100 + FSCALE / 2) >> FSHIFT;
	ttyprintf(tp, "load: %d.%02d ", tmp / 100, tmp % 100);

	if (tp->t_session == NULL) {
		ttyprintf(tp, "not a controlling terminal\n");
	} else if (tp->t_pgrp == NULL) {
		ttyprintf(tp, "no foreground process group\n");
	} else if ((p = LIST_FIRST(&tp->t_pgrp->pg_members)) == NULL) {
		ttyprintf(tp, "empty foreground process group\n");
	} else {
		/*
		 * Pick an interesting process.  Note that certain elements,
		 * in particular the wmesg, require a critical section for
		 * safe access (YYY and we are still not MP safe).
		 *
		 * NOTE: lwp_wmesg is lwp_thread->td_wmesg.
		 */
		char buf[64];
		const char *str;
		long vmsz;
		int pctcpu;

		crit_enter();

		/* XXX lwp should compare lwps */

		for (pick = NULL; p != NULL; p = LIST_NEXT(p, p_pglist)) {
			if (proc_compare(pick, p))
				pick = p;
		}

		/* XXX lwp */
		lp = FIRST_LWP_IN_PROC(pick);
		if (lp == NULL) {
			ttyprintf(tp, "foreground process without lwp\n");
			tp->t_rocount = 0;
			crit_exit();
			lwkt_reltoken(&proc_token);
			lwkt_reltoken(&tty_token);
			return;
		}

		/*
		 * Figure out what wait/process-state message, and command
		 * buffer to present
		 */
		/*
		 * XXX lwp This is a horrible mixture.  We need to rework this
		 * as soon as lwps have their own runnable status.
		 */
		if (pick->p_flags & P_WEXIT)
			str = "exiting";
		else if (lp->lwp_stat == LSRUN)
			str = "running";
		else if (pick->p_stat == SIDL)
			str = "spawning";
		else if (lp->lwp_wmesg)	/* lwp_thread must not be NULL */
			str = lp->lwp_wmesg;
		else
			str = "iowait";

		ksnprintf(buf, sizeof(buf), "cmd: %s %d [%s]",
			pick->p_comm, pick->p_pid, str);

		/*
		 * Calculate cpu usage, percent cpu, and cmsz.  Note that
		 * 'pick' becomes invalid the moment we exit the critical
		 * section.
		 */
		if (lp->lwp_thread && (pick->p_flags & P_SWAPPEDOUT) == 0)
			calcru_proc(pick, &ru);

		pctcpu = (lp->lwp_pctcpu * 10000 + FSCALE / 2) >> FSHIFT;

		if (pick->p_stat == SIDL || pick->p_stat == SZOMB) {
		    vmsz = 0;
		} else {
		    lwkt_gettoken(&pick->p_vmspace->vm_map.token);
		    vmsz = pgtok(vmspace_resident_count(pick->p_vmspace));
		    lwkt_reltoken(&pick->p_vmspace->vm_map.token);
		}

		crit_exit();

		/*
		 * Dump the output
		 */
		ttyprintf(tp, " %s ", buf);
		ttyprintf(tp, "%ld.%02ldu ",
			ru.ru_utime.tv_sec, ru.ru_utime.tv_usec / 10000);
		ttyprintf(tp, "%ld.%02lds ",
			ru.ru_stime.tv_sec, ru.ru_stime.tv_usec / 10000);
		ttyprintf(tp, "%d%% %ldk\n", pctcpu / 100, vmsz);
	}
	tp->t_rocount = 0;	/* so pending input will be retyped if BS */
	lwkt_reltoken(&proc_token);
	lwkt_reltoken(&tty_token);
}

/*
 * Returns 1 if p2 is "better" than p1
 *
 * The algorithm for picking the "interesting" process is thus:
 *
 *	1) Only foreground processes are eligible - implied.
 *	2) Runnable processes are favored over anything else.  The runner
 *	   with the highest cpu utilization is picked (p_cpticks).  Ties are
 *	   broken by picking the highest pid.
 *	3) The sleeper with the shortest sleep time is next.  With ties,
 *	   we pick out just "short-term" sleepers (LWP_SINTR == 0).
 *	4) Further ties are broken by picking the highest pid.
 *
 * NOTE: must be called with proc_token held.
 */
#define ISRUN(lp)	((lp)->lwp_stat == LSRUN)
#define TESTAB(a, b)    ((a)<<1 | (b))
#define ONLYA   2
#define ONLYB   1
#define BOTH    3

static int
proc_compare(struct proc *p1, struct proc *p2)
{
	struct lwp *lp1, *lp2;

	ASSERT_LWKT_TOKEN_HELD(&proc_token);

	if (p1 == NULL)
		return (1);

	/*
 	 * weed out zombies
	 */
	switch (TESTAB(p1->p_stat == SZOMB, p2->p_stat == SZOMB)) {
	case ONLYA:
		return (1);
	case ONLYB:
		return (0);
	case BOTH:
		return (p2->p_pid > p1->p_pid); /* tie - return highest pid */
	}

	/* XXX lwp */
	lp1 = FIRST_LWP_IN_PROC(p1);
	lp2 = FIRST_LWP_IN_PROC(p2);

	/*
	 * see if at least one of them is runnable
	 */
	switch (TESTAB(ISRUN(lp1), ISRUN(lp2))) {
	case ONLYA:
		return (0);
	case ONLYB:
		return (1);
	case BOTH:
		/*
		 * tie - favor one with highest recent cpu utilization
		 */
		if (lp2->lwp_cpticks > lp1->lwp_cpticks)
			return (1);
		if (lp1->lwp_cpticks > lp2->lwp_cpticks)
			return (0);
		return (p2->p_pid > p1->p_pid);	/* tie - return highest pid */
	}
	/*
	 * pick the one with the smallest sleep time
	 */
	if (lp2->lwp_slptime > lp1->lwp_slptime)
		return (0);
	if (lp1->lwp_slptime > lp2->lwp_slptime)
		return (1);
	/*
	 * favor one sleeping in a non-interruptible sleep
	 */
	if (lp1->lwp_flags & LWP_SINTR && (lp2->lwp_flags & LWP_SINTR) == 0)
		return (1);
	if (lp2->lwp_flags & LWP_SINTR && (lp1->lwp_flags & LWP_SINTR) == 0)
		return (0);
	return (p2->p_pid > p1->p_pid);		/* tie - return highest pid */
}

/*
 * Output char to tty; console putchar style.
 */
int
tputchar(int c, struct tty *tp)
{
	crit_enter();
	lwkt_gettoken(&tty_token);
	if (!ISSET(tp->t_state, TS_CONNECTED)) {
		lwkt_reltoken(&tty_token);
		crit_exit();
		return (-1);
	}
	if (c == '\n')
		(void)ttyoutput('\r', tp);
	(void)ttyoutput(c, tp);
	ttstart(tp);
	lwkt_reltoken(&tty_token);
	crit_exit();
	return (0);
}

/*
 * Sleep on chan, returning ERESTART if tty changed while we napped and
 * returning any errors (e.g. EINTR/EWOULDBLOCK) reported by tsleep.  If
 * the tty is revoked, restarting a pending call will redo validation done
 * at the start of the call.
 */
int
ttysleep(struct tty *tp, void *chan, int slpflags, char *wmesg, int timo)
{
	int error;
	int gen;

	gen = tp->t_gen;
	error = tsleep(chan, slpflags, wmesg, timo);
	if (error)
		return (error);
	return (tp->t_gen == gen ? 0 : ERESTART);
}

/*
 * Revoke a tty.
 *
 * We bump the gen to force any ttysleep()'s to return with ERESTART
 * and flush the tty.  The related fp's should already have been
 * replaced so the tty will close when the last references on the
 * original fp's go away.
 */
int
ttyrevoke(struct dev_revoke_args *ap)
{
	struct tty *tp;

	lwkt_gettoken(&tty_token);
	tp = ap->a_head.a_dev->si_tty;
	tp->t_gen++;
	ttyflush(tp, FREAD | FWRITE);
	wakeup(TSA_CARR_ON(tp));
	ttwakeup(tp);
	ttwwakeup(tp);
	lwkt_reltoken(&tty_token);
	return (0);
}

/*
 * Allocate a tty struct.  Clists in the struct will be allocated by
 * ttyopen().
 */
struct tty *
ttymalloc(struct tty *tp)
{

	if (tp) {
		return(tp);
	}
	tp = kmalloc(sizeof *tp, M_TTYS, M_WAITOK|M_ZERO);
	ttyregister(tp);
        return (tp);
}

void
ttyunregister(struct tty *tp)
{
	lwkt_gettoken(&tty_token);
	KKASSERT(ISSET(tp->t_state, TS_REGISTERED));
	CLR(tp->t_state, TS_REGISTERED);
	TAILQ_REMOVE(&tty_list, tp, t_list);
	lwkt_reltoken(&tty_token);
}

void
ttyregister(struct tty *tp)
{
	lwkt_gettoken(&tty_token);
	KKASSERT(!ISSET(tp->t_state, TS_REGISTERED));
	SET(tp->t_state, TS_REGISTERED);
	TAILQ_INSERT_HEAD(&tty_list, tp, t_list);
	lwkt_reltoken(&tty_token);
}

static int
sysctl_kern_ttys(SYSCTL_HANDLER_ARGS)
{
	int error;
	struct tty *tp;
	struct tty t;
	struct tty marker;

	bzero(&marker, sizeof(marker));
	marker.t_state = TS_MARKER;
	error = 0;

	lwkt_gettoken(&tty_token);

	TAILQ_INSERT_HEAD(&tty_list, &marker, t_list);
	while ((tp = TAILQ_NEXT(&marker, t_list)) != NULL) {
		TAILQ_REMOVE(&tty_list, &marker, t_list);
		TAILQ_INSERT_AFTER(&tty_list, tp, &marker, t_list);
		if (tp->t_state & TS_MARKER)
			continue;
		t = *tp;
		if (t.t_dev)
			t.t_dev = (cdev_t)(uintptr_t)dev2udev(t.t_dev);
		error = SYSCTL_OUT(req, (caddr_t)&t, sizeof(t));
		if (error)
			break;
	}
	TAILQ_REMOVE(&tty_list, &marker, t_list);
	lwkt_reltoken(&tty_token);
	return (error);
}

SYSCTL_PROC(_kern, OID_AUTO, ttys, CTLTYPE_OPAQUE|CTLFLAG_RD,
	0, 0, sysctl_kern_ttys, "S,tty", "All struct ttys");

void
nottystop(struct tty *tp, int rw)
{
	return;
}

int
ttyread(struct dev_read_args *ap)
{
	struct tty *tp;
	int ret;

	tp = ap->a_head.a_dev->si_tty;
	if (tp == NULL)
		return (ENODEV);
	lwkt_gettoken(&tty_token);
	ret = ((*linesw[tp->t_line].l_read)(tp, ap->a_uio, ap->a_ioflag));
	lwkt_reltoken(&tty_token);

	return ret;
}

int
ttywrite(struct dev_write_args *ap)
{
	struct tty *tp;
	int ret;

	tp = ap->a_head.a_dev->si_tty;
	if (tp == NULL)
		return (ENODEV);
	lwkt_gettoken(&tty_token);
	ret = ((*linesw[tp->t_line].l_write)(tp, ap->a_uio, ap->a_ioflag));
	lwkt_reltoken(&tty_token);

	return ret;
}
