/*
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *	@(#)raw_ip.c	8.7 (Berkeley) 5/15/95
 * $FreeBSD: src/sys/netinet/raw_ip.c,v 1.64.2.16 2003/08/24 08:24:38 hsu Exp $
 * $DragonFly: src/sys/netinet/raw_ip.c,v 1.33 2008/10/28 03:07:28 sephe Exp $
 */

#include "opt_inet6.h"
#include "opt_ipsec.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/thread2.h>

#include <machine/stdarg.h>

#include <net/if.h>
#include <net/route.h>

#define _IP_VHL
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>

#include <net/ip_mroute/ip_mroute.h>
#include <net/ipfw/ip_fw.h>
#include <net/dummynet/ip_dummynet.h>

#ifdef FAST_IPSEC
#include <netproto/ipsec/ipsec.h>
#endif /*FAST_IPSEC*/

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

struct	inpcbinfo ripcbinfo;

/* control hooks for ipfw and dummynet */
ip_fw_ctl_t *ip_fw_ctl_ptr;
ip_dn_ctl_t *ip_dn_ctl_ptr;

/*
 * hooks for multicast routing. They all default to NULL,
 * so leave them not initialized and rely on BSS being set to 0.
 */

/* The socket used to communicate with the multicast routing daemon.  */
struct socket  *ip_mrouter;

/* The various mrouter and rsvp functions */
int (*ip_mrouter_set)(struct socket *, struct sockopt *);
int (*ip_mrouter_get)(struct socket *, struct sockopt *);
int (*ip_mrouter_done)(void);
int (*ip_mforward)(struct ip *, struct ifnet *, struct mbuf *,
		struct ip_moptions *);
int (*mrt_ioctl)(int, caddr_t);
int (*legal_vif_num)(int);
u_long (*ip_mcast_src)(int);

void (*rsvp_input_p)(struct mbuf *m, ...);
int (*ip_rsvp_vif)(struct socket *, struct sockopt *);
void (*ip_rsvp_force_done)(struct socket *);

/*
 * Nominal space allocated to a raw ip socket.
 */
#define	RIPSNDQ		8192
#define	RIPRCVQ		8192

/*
 * Raw interface to IP protocol.
 */

/*
 * Initialize raw connection block queue.
 */
void
rip_init(void)
{
	in_pcbinfo_init(&ripcbinfo);
	/*
	 * XXX We don't use the hash list for raw IP, but it's easier
	 * to allocate a one entry hash list than it is to check all
	 * over the place for hashbase == NULL.
	 */
	ripcbinfo.hashbase = hashinit(1, M_PCB, &ripcbinfo.hashmask);
	ripcbinfo.porthashbase = hashinit(1, M_PCB, &ripcbinfo.porthashmask);
	ripcbinfo.wildcardhashbase = hashinit(1, M_PCB,
					      &ripcbinfo.wildcardhashmask);
	ripcbinfo.ipi_size = sizeof(struct inpcb);
}

/*
 * Setup generic address and protocol structures
 * for raw_input routine, then pass them along with
 * mbuf chain.
 */
void
rip_input(struct mbuf *m, ...)
{
	struct sockaddr_in ripsrc = { sizeof ripsrc, AF_INET };
	struct ip *ip = mtod(m, struct ip *);
	struct inpcb *inp;
	struct inpcb *last = NULL;
	struct mbuf *opts = NULL;
	int off, proto;
	__va_list ap;

	__va_start(ap, m);
	off = __va_arg(ap, int);
	proto = __va_arg(ap, int);
	__va_end(ap);

	ripsrc.sin_addr = ip->ip_src;
	LIST_FOREACH(inp, &ripcbinfo.pcblisthead, inp_list) {
		if (inp->inp_flags & INP_PLACEMARKER)
			continue;
#ifdef INET6
		if ((inp->inp_vflag & INP_IPV4) == 0)
			continue;
#endif
		if (inp->inp_ip_p && inp->inp_ip_p != proto)
			continue;
		if (inp->inp_laddr.s_addr != INADDR_ANY &&
		    inp->inp_laddr.s_addr != ip->ip_dst.s_addr)
			continue;
		if (inp->inp_faddr.s_addr != INADDR_ANY &&
		    inp->inp_faddr.s_addr != ip->ip_src.s_addr)
			continue;
		if (last) {
			struct mbuf *n = m_copypacket(m, MB_DONTWAIT);

#ifdef IPSEC
			/* check AH/ESP integrity. */
			if (n && ipsec4_in_reject_so(n, last->inp_socket)) {
				m_freem(n);
				ipsecstat.in_polvio++;
				/* do not inject data to pcb */
			} else
#endif /*IPSEC*/
#ifdef FAST_IPSEC
			/* check AH/ESP integrity. */
			if (ipsec4_in_reject(n, last)) {
				m_freem(n);
				/* do not inject data to pcb */
			} else
#endif /*FAST_IPSEC*/
			if (n) {
				if (last->inp_flags & INP_CONTROLOPTS ||
				    last->inp_socket->so_options & SO_TIMESTAMP)
				    ip_savecontrol(last, &opts, ip, n);
				if (ssb_appendaddr(&last->inp_socket->so_rcv,
				    (struct sockaddr *)&ripsrc, n,
				    opts) == 0) {
					/* should notify about lost packet */
					m_freem(n);
					if (opts)
					    m_freem(opts);
				} else
					sorwakeup(last->inp_socket);
				opts = 0;
			}
		}
		last = inp;
	}
#ifdef IPSEC
	/* check AH/ESP integrity. */
	if (last && ipsec4_in_reject_so(m, last->inp_socket)) {
		m_freem(m);
		ipsecstat.in_polvio++;
		ipstat.ips_delivered--;
		/* do not inject data to pcb */
	} else
#endif /*IPSEC*/
#ifdef FAST_IPSEC
	/* check AH/ESP integrity. */
	if (last && ipsec4_in_reject(m, last)) {
		m_freem(m);
		ipstat.ips_delivered--;
		/* do not inject data to pcb */
	} else
#endif /*FAST_IPSEC*/
	/* Check the minimum TTL for socket. */
	if (last && ip->ip_ttl < last->inp_ip_minttl) {
		m_freem(opts);
		ipstat.ips_delivered--;
	} else if (last) {
		if (last->inp_flags & INP_CONTROLOPTS ||
		    last->inp_socket->so_options & SO_TIMESTAMP)
			ip_savecontrol(last, &opts, ip, m);
		if (ssb_appendaddr(&last->inp_socket->so_rcv,
		    (struct sockaddr *)&ripsrc, m, opts) == 0) {
			m_freem(m);
			if (opts)
			    m_freem(opts);
		} else
			sorwakeup(last->inp_socket);
	} else {
		m_freem(m);
		ipstat.ips_noproto++;
		ipstat.ips_delivered--;
	}
}

/*
 * Generate IP header and pass packet to ip_output.
 * Tack on options user may have setup with control call.
 */
int
rip_output(struct mbuf *m, struct socket *so, ...)
{
	struct ip *ip;
	struct inpcb *inp = so->so_pcb;
	__va_list ap;
	int flags = (so->so_options & SO_DONTROUTE) | IP_ALLOWBROADCAST;
	u_long dst;

	__va_start(ap, so);
	dst = __va_arg(ap, u_long);
	__va_end(ap);

	/*
	 * If the user handed us a complete IP packet, use it.
	 * Otherwise, allocate an mbuf for a header and fill it in.
	 */
	if ((inp->inp_flags & INP_HDRINCL) == 0) {
		if (m->m_pkthdr.len + sizeof(struct ip) > IP_MAXPACKET) {
			m_freem(m);
			return(EMSGSIZE);
		}
		M_PREPEND(m, sizeof(struct ip), MB_WAIT);
		if (m == NULL)
			return(ENOBUFS);
		ip = mtod(m, struct ip *);
		ip->ip_tos = inp->inp_ip_tos;
		ip->ip_off = 0;
		ip->ip_p = inp->inp_ip_p;
		ip->ip_len = m->m_pkthdr.len;
		ip->ip_src = inp->inp_laddr;
		ip->ip_dst.s_addr = dst;
		ip->ip_ttl = inp->inp_ip_ttl;
	} else {
		int hlen;

		if (m->m_pkthdr.len > IP_MAXPACKET) {
			m_freem(m);
			return(EMSGSIZE);
		}
		if (m->m_len < sizeof(struct ip)) {
			m = m_pullup(m, sizeof(struct ip));
			if (m == NULL)
				return ENOBUFS;
		}
		ip = mtod(m, struct ip *);
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;

		/* Don't allow header length less than the minimum. */
		if (hlen < sizeof(struct ip)) {
			m_freem(m);
			return EINVAL;
		}

		/*
		 * Don't allow both user specified and setsockopt options.
		 * Don't allow packet length sizes that will crash.
		 */
		if ((hlen != sizeof(struct ip) && inp->inp_options) ||
		    ip->ip_len > m->m_pkthdr.len || ip->ip_len < hlen) {
			m_freem(m);
			return EINVAL;
		}
		if (ip->ip_id == 0)
			ip->ip_id = ip_newid();

		/* Prevent ip_output from overwriting header fields */
		flags |= IP_RAWOUTPUT;
		ipstat.ips_rawout++;
	}

	return ip_output(m, inp->inp_options, &inp->inp_route, flags,
			 inp->inp_moptions, inp);
}

/*
 * Raw IP socket option processing.
 */
int
rip_ctloutput(struct socket *so, struct sockopt *sopt)
{
	struct	inpcb *inp = so->so_pcb;
	int	error, optval;

	if (sopt->sopt_level != IPPROTO_IP)
		return (EINVAL);

	error = 0;

	switch (sopt->sopt_dir) {
	case SOPT_GET:
		switch (sopt->sopt_name) {
		case IP_HDRINCL:
			optval = inp->inp_flags & INP_HDRINCL;
			soopt_from_kbuf(sopt, &optval, sizeof optval);
			break;

		case IP_FW_ADD: /* ADD actually returns the body... */
		case IP_FW_GET:
			if (IPFW_LOADED)
				error = ip_fw_sockopt(sopt);
			else
				error = ENOPROTOOPT;
			break;

		case IP_DUMMYNET_GET:
			error = ip_dn_sockopt(sopt);
			break ;

		case MRT_INIT:
		case MRT_DONE:
		case MRT_ADD_VIF:
		case MRT_DEL_VIF:
		case MRT_ADD_MFC:
		case MRT_DEL_MFC:
		case MRT_VERSION:
		case MRT_ASSERT:
		case MRT_API_SUPPORT:
		case MRT_API_CONFIG:
		case MRT_ADD_BW_UPCALL:
		case MRT_DEL_BW_UPCALL:
			error = ip_mrouter_get ? ip_mrouter_get(so, sopt) :
				EOPNOTSUPP;
			break;

		default:
			error = ip_ctloutput(so, sopt);
			break;
		}
		break;

	case SOPT_SET:
		switch (sopt->sopt_name) {
		case IP_HDRINCL:
			error = soopt_to_kbuf(sopt, &optval, sizeof optval,
					      sizeof optval);
			if (error)
				break;
			if (optval)
				inp->inp_flags |= INP_HDRINCL;
			else
				inp->inp_flags &= ~INP_HDRINCL;
			break;

		case IP_FW_ADD:
		case IP_FW_DEL:
		case IP_FW_FLUSH:
		case IP_FW_ZERO:
		case IP_FW_RESETLOG:
			if (IPFW_LOADED)
				error = ip_fw_ctl_ptr(sopt);
			else
				error = ENOPROTOOPT;
			break;

		case IP_DUMMYNET_CONFIGURE:
		case IP_DUMMYNET_DEL:
		case IP_DUMMYNET_FLUSH:
			error = ip_dn_sockopt(sopt);
			break ;

		case IP_RSVP_ON:
			error = ip_rsvp_init(so);
			break;

		case IP_RSVP_OFF:
			error = ip_rsvp_done();
			break;

		case IP_RSVP_VIF_ON:
		case IP_RSVP_VIF_OFF:
			error = ip_rsvp_vif ?
				ip_rsvp_vif(so, sopt) : EINVAL;
			break;

		case MRT_INIT:
		case MRT_DONE:
		case MRT_ADD_VIF:
		case MRT_DEL_VIF:
		case MRT_ADD_MFC:
		case MRT_DEL_MFC:
		case MRT_VERSION:
		case MRT_ASSERT:
		case MRT_API_SUPPORT:
		case MRT_API_CONFIG:
		case MRT_ADD_BW_UPCALL:
		case MRT_DEL_BW_UPCALL:
			error = ip_mrouter_set ? ip_mrouter_set(so, sopt) :
					EOPNOTSUPP;
			break;

		default:
			error = ip_ctloutput(so, sopt);
			break;
		}
		break;
	}

	return (error);
}

/*
 * This function exists solely to receive the PRC_IFDOWN messages which
 * are sent by if_down().  It looks for an ifaddr whose ifa_addr is sa,
 * and calls in_ifadown() to remove all routes corresponding to that address.
 * It also receives the PRC_IFUP messages from if_up() and reinstalls the
 * interface routes.
 */
void
rip_ctlinput(int cmd, struct sockaddr *sa, void *vip)
{
	struct in_ifaddr *ia;
	struct in_ifaddr_container *iac;
	struct ifnet *ifp;
	int err;
	int flags;

	switch (cmd) {
	case PRC_IFDOWN:
		TAILQ_FOREACH(iac, &in_ifaddrheads[mycpuid], ia_link) {
			ia = iac->ia;

			if (ia->ia_ifa.ifa_addr == sa &&
			    (ia->ia_flags & IFA_ROUTE)) {
				/*
				 * in_ifscrub kills the interface route.
				 */
				in_ifscrub(ia->ia_ifp, ia);
				/*
				 * in_ifadown gets rid of all the rest of
				 * the routes.  This is not quite the right
				 * thing to do, but at least if we are running
				 * a routing process they will come back.
				 */
				in_ifadown(&ia->ia_ifa, 0);
				break;
			}
		}
		break;

	case PRC_IFUP:
		ia = NULL;
		TAILQ_FOREACH(iac, &in_ifaddrheads[mycpuid], ia_link) {
			if (iac->ia->ia_ifa.ifa_addr == sa) {
				ia = iac->ia;
				break;
			}
		}
		if (ia == NULL || (ia->ia_flags & IFA_ROUTE))
			return;
		flags = RTF_UP;
		ifp = ia->ia_ifa.ifa_ifp;

		if ((ifp->if_flags & IFF_LOOPBACK) ||
		    (ifp->if_flags & IFF_POINTOPOINT))
			flags |= RTF_HOST;

		err = rtinit(&ia->ia_ifa, RTM_ADD, flags);
		if (err == 0)
			ia->ia_flags |= IFA_ROUTE;
		break;
	}
}

u_long	rip_sendspace = RIPSNDQ;
u_long	rip_recvspace = RIPRCVQ;

SYSCTL_INT(_net_inet_raw, OID_AUTO, maxdgram, CTLFLAG_RW,
    &rip_sendspace, 0, "Maximum outgoing raw IP datagram size");
SYSCTL_INT(_net_inet_raw, OID_AUTO, recvspace, CTLFLAG_RW,
    &rip_recvspace, 0, "Maximum incoming raw IP datagram size");

static int
rip_attach(struct socket *so, int proto, struct pru_attach_info *ai)
{
	struct inpcb *inp;
	int error;

	inp = so->so_pcb;
	if (inp)
		panic("rip_attach");
	error = priv_check_cred(ai->p_ucred, PRIV_NETINET_RAW, NULL_CRED_OKAY);
	if (error)
		return error;

	error = soreserve(so, rip_sendspace, rip_recvspace, ai->sb_rlimit);
	if (error)
		return error;
	crit_enter();
	error = in_pcballoc(so, &ripcbinfo);
	crit_exit();
	if (error)
		return error;
	inp = (struct inpcb *)so->so_pcb;
	inp->inp_vflag |= INP_IPV4;
	inp->inp_ip_p = proto;
	inp->inp_ip_ttl = ip_defttl;
	return 0;
}

static int
rip_detach(struct socket *so)
{
	struct inpcb *inp;

	inp = so->so_pcb;
	if (inp == 0)
		panic("rip_detach");
	if (so == ip_mrouter && ip_mrouter_done)
		ip_mrouter_done();
	if (ip_rsvp_force_done)
		ip_rsvp_force_done(so);
	if (so == ip_rsvpd)
		ip_rsvp_done();
	in_pcbdetach(inp);
	return 0;
}

static int
rip_abort(struct socket *so)
{
	soisdisconnected(so);
	if (so->so_state & SS_NOFDREF)
		return rip_detach(so);
	return 0;
}

static int
rip_disconnect(struct socket *so)
{
	if ((so->so_state & SS_ISCONNECTED) == 0)
		return ENOTCONN;
	return rip_abort(so);
}

static int
rip_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct inpcb *inp = so->so_pcb;
	struct sockaddr_in *addr = (struct sockaddr_in *)nam;

	if (nam->sa_len != sizeof(*addr))
		return EINVAL;

	if (TAILQ_EMPTY(&ifnet) || ((addr->sin_family != AF_INET) &&
				    (addr->sin_family != AF_IMPLINK)) ||
	    (addr->sin_addr.s_addr != INADDR_ANY &&
	     ifa_ifwithaddr((struct sockaddr *)addr) == 0))
		return EADDRNOTAVAIL;
	inp->inp_laddr = addr->sin_addr;
	return 0;
}

static int
rip_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	struct inpcb *inp = so->so_pcb;
	struct sockaddr_in *addr = (struct sockaddr_in *)nam;

	if (nam->sa_len != sizeof(*addr))
		return EINVAL;
	if (TAILQ_EMPTY(&ifnet))
		return EADDRNOTAVAIL;
	if ((addr->sin_family != AF_INET) &&
	    (addr->sin_family != AF_IMPLINK))
		return EAFNOSUPPORT;
	inp->inp_faddr = addr->sin_addr;
	soisconnected(so);
	return 0;
}

static int
rip_shutdown(struct socket *so)
{
	socantsendmore(so);
	return 0;
}

static int
rip_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	 struct mbuf *control, struct thread *td)
{
	struct inpcb *inp = so->so_pcb;
	u_long dst;

	if (so->so_state & SS_ISCONNECTED) {
		if (nam) {
			m_freem(m);
			return EISCONN;
		}
		dst = inp->inp_faddr.s_addr;
	} else {
		if (nam == NULL) {
			m_freem(m);
			return ENOTCONN;
		}
		dst = ((struct sockaddr_in *)nam)->sin_addr.s_addr;
	}
	return rip_output(m, so, dst);
}

SYSCTL_PROC(_net_inet_raw, OID_AUTO/*XXX*/, pcblist, CTLFLAG_RD, &ripcbinfo, 0,
	    in_pcblist_global, "S,xinpcb", "List of active raw IP sockets");

struct pr_usrreqs rip_usrreqs = {
	.pru_abort = rip_abort,
	.pru_accept = pru_accept_notsupp,
	.pru_attach = rip_attach,
	.pru_bind = rip_bind,
	.pru_connect = rip_connect,
	.pru_connect2 = pru_connect2_notsupp,
	.pru_control = in_control,
	.pru_detach = rip_detach,
	.pru_disconnect = rip_disconnect,
	.pru_listen = pru_listen_notsupp,
	.pru_peeraddr = in_setpeeraddr,
	.pru_rcvd = pru_rcvd_notsupp,
	.pru_rcvoob = pru_rcvoob_notsupp,
	.pru_send = rip_send,
	.pru_sense = pru_sense_null,
	.pru_shutdown = rip_shutdown,
	.pru_sockaddr = in_setsockaddr,
	.pru_sosend = sosend,
	.pru_soreceive = soreceive
};
