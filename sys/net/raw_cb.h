/*
 * Copyright (c) 1980, 1986, 1993
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
 *	@(#)raw_cb.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/net/raw_cb.h,v 1.12 1999/12/29 04:38:37 peter Exp $
 * $DragonFly: src/sys/net/raw_cb.h,v 1.6 2006/05/20 02:42:08 dillon Exp $
 */

#ifndef _NET_RAW_CB_H_
#define _NET_RAW_CB_H_

#ifndef _SYS_QUEUE_H_
#include <sys/queue.h>
#endif
#ifndef _SYS_RESOURCE_H_
#include <sys/resource.h>
#endif
#ifndef _SYS_MBUF_H_
#include <sys/mbuf.h>
#endif
#ifndef _SYS_SOCKET_H_
#include <sys/socket.h>
#endif

/*
 * Raw protocol interface control block.  Used
 * to tie a socket to the generic raw interface.
 */
struct rawcb {
	LIST_ENTRY(rawcb)	list;
	struct socket		*rcb_socket;	/* back pointer to socket */
	const struct sockaddr	*rcb_faddr;	/* destination address */
	struct sockaddr		*rcb_laddr;	/* socket's address */
	struct sockproto	rcb_proto;	/* protocol family, protocol */
};

#define	sotorawcb(so)		((struct rawcb *)(so)->so_pcb)

/*
 * Nominal space allocated to a raw socket.
 */
#define	RAWSNDQ		8192
#define	RAWRCVQ		8192

#ifdef _KERNEL
extern LIST_HEAD(rawcb_list_head, rawcb) rawcb_list;

union netmsg;

int	 raw_attach (struct socket *, int, struct rlimit *);
void	 raw_ctlinput (union netmsg *);
void	 raw_detach (struct rawcb *);
void	 raw_disconnect (struct rawcb *);
void	 raw_init (void);
void	 raw_input (struct mbuf *, const struct sockproto *,
		    const struct sockaddr *, const struct sockaddr *,
		    const struct rawcb *);

extern	struct pr_usrreqs raw_usrreqs;
#endif

#endif
