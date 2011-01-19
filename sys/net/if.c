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
 *	@(#)if.c	8.3 (Berkeley) 1/4/94
 * $FreeBSD: src/sys/net/if.c,v 1.185 2004/03/13 02:35:03 brooks Exp $
 * $DragonFly: src/sys/net/if.c,v 1.84 2008/11/15 11:58:16 sephe Exp $
 */

#include "opt_compat.h"
#include "opt_inet6.h"
#include "opt_inet.h"
#include "opt_polling.h"
#include "opt_ifpoll.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/socketops.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/sockio.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/domain.h>
#include <sys/thread.h>
#include <sys/thread2.h>
#include <sys/serialize.h>
#include <sys/msgport2.h>
#include <sys/bus.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/ifq_var.h>
#include <net/radix.h>
#include <net/route.h>
#include <net/if_clone.h>
#include <net/netisr.h>
#include <net/netmsg2.h>

#include <machine/atomic.h>
#include <machine/stdarg.h>
#include <machine/smp.h>

#if defined(INET) || defined(INET6)
/*XXX*/
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#ifdef INET6
#include <netinet6/in6_var.h>
#include <netinet6/in6_ifattach.h>
#endif
#endif

#if defined(COMPAT_43)
#include <emulation/43bsd/43bsd_socket.h>
#endif /* COMPAT_43 */

struct netmsg_ifaddr {
	struct netmsg_base base;
	struct ifaddr	*ifa;
	struct ifnet	*ifp;
	int		tail;
};

/*
 * System initialization
 */
static void	if_attachdomain(void *);
static void	if_attachdomain1(struct ifnet *);
static int	ifconf(u_long, caddr_t, struct ucred *);
static void	ifinit(void *);
static void	ifnetinit(void *);
static void	if_slowtimo(void *);
static void	link_rtrequest(int, struct rtentry *, struct rt_addrinfo *);
static int	if_rtdel(struct radix_node *, void *);

#ifdef INET6
/*
 * XXX: declare here to avoid to include many inet6 related files..
 * should be more generalized?
 */
extern void	nd6_setmtu(struct ifnet *);
#endif

SYSCTL_NODE(_net, PF_LINK, link, CTLFLAG_RW, 0, "Link layers");
SYSCTL_NODE(_net_link, 0, generic, CTLFLAG_RW, 0, "Generic link-management");

SYSINIT(interfaces, SI_SUB_PROTO_IF, SI_ORDER_FIRST, ifinit, NULL)
/* Must be after netisr_init */
SYSINIT(ifnet, SI_SUB_PRE_DRIVERS, SI_ORDER_SECOND, ifnetinit, NULL)

static  if_com_alloc_t *if_com_alloc[256];
static  if_com_free_t *if_com_free[256];

MALLOC_DEFINE(M_IFADDR, "ifaddr", "interface address");
MALLOC_DEFINE(M_IFMADDR, "ether_multi", "link-level multicast address");
MALLOC_DEFINE(M_IFNET, "ifnet", "interface structure");

int			ifqmaxlen = IFQ_MAXLEN;
struct ifnethead	ifnet = TAILQ_HEAD_INITIALIZER(ifnet);

/* In ifq_dispatch(), try to do direct ifnet.if_start first */
static int		ifq_dispatch_schedonly = 0;
SYSCTL_INT(_net_link_generic, OID_AUTO, ifq_dispatch_schedonly, CTLFLAG_RW,
           &ifq_dispatch_schedonly, 0, "");

/* In ifq_dispatch(), schedule ifnet.if_start without checking ifnet.if_snd */
static int		ifq_dispatch_schednochk = 0;
SYSCTL_INT(_net_link_generic, OID_AUTO, ifq_dispatch_schednochk, CTLFLAG_RW,
           &ifq_dispatch_schednochk, 0, "");

/* In if_devstart(), try to do direct ifnet.if_start first */
static int		if_devstart_schedonly = 0;
SYSCTL_INT(_net_link_generic, OID_AUTO, if_devstart_schedonly, CTLFLAG_RW,
           &if_devstart_schedonly, 0, "");

/* In if_devstart(), schedule ifnet.if_start without checking ifnet.if_snd */
static int		if_devstart_schednochk = 0;
SYSCTL_INT(_net_link_generic, OID_AUTO, if_devstart_schednochk, CTLFLAG_RW,
           &if_devstart_schednochk, 0, "");

#ifdef SMP
/* Schedule ifnet.if_start on the current CPU */
static int		if_start_oncpu_sched = 0;
SYSCTL_INT(_net_link_generic, OID_AUTO, if_start_oncpu_sched, CTLFLAG_RW,
           &if_start_oncpu_sched, 0, "");
#endif

struct callout		if_slowtimo_timer;

int			if_index = 0;
struct ifnet		**ifindex2ifnet = NULL;
static struct thread	ifnet_threads[MAXCPU];

#define IFQ_KTR_STRING		"ifq=%p"
#define IFQ_KTR_ARG_SIZE	(sizeof(void *))
#ifndef KTR_IFQ
#define KTR_IFQ			KTR_ALL
#endif
KTR_INFO_MASTER(ifq);
KTR_INFO(KTR_IFQ, ifq, enqueue, 0, IFQ_KTR_STRING, IFQ_KTR_ARG_SIZE);
KTR_INFO(KTR_IFQ, ifq, dequeue, 1, IFQ_KTR_STRING, IFQ_KTR_ARG_SIZE);
#define logifq(name, arg)	KTR_LOG(ifq_ ## name, arg)

#define IF_START_KTR_STRING	"ifp=%p"
#define IF_START_KTR_ARG_SIZE	(sizeof(void *))
#ifndef KTR_IF_START
#define KTR_IF_START		KTR_ALL
#endif
KTR_INFO_MASTER(if_start);
KTR_INFO(KTR_IF_START, if_start, run, 0,
	 IF_START_KTR_STRING, IF_START_KTR_ARG_SIZE);
KTR_INFO(KTR_IF_START, if_start, sched, 1,
	 IF_START_KTR_STRING, IF_START_KTR_ARG_SIZE);
KTR_INFO(KTR_IF_START, if_start, avoid, 2,
	 IF_START_KTR_STRING, IF_START_KTR_ARG_SIZE);
KTR_INFO(KTR_IF_START, if_start, contend_sched, 3,
	 IF_START_KTR_STRING, IF_START_KTR_ARG_SIZE);
#ifdef SMP
KTR_INFO(KTR_IF_START, if_start, chase_sched, 4,
	 IF_START_KTR_STRING, IF_START_KTR_ARG_SIZE);
#endif
#define logifstart(name, arg)	KTR_LOG(if_start_ ## name, arg)

TAILQ_HEAD(, ifg_group) ifg_head = TAILQ_HEAD_INITIALIZER(ifg_head);

/*
 * Network interface utility routines.
 *
 * Routines with ifa_ifwith* names take sockaddr *'s as
 * parameters.
 */
/* ARGSUSED*/
void
ifinit(void *dummy)
{
	struct ifnet *ifp;

	callout_init(&if_slowtimo_timer);

	crit_enter();
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (ifp->if_snd.ifq_maxlen == 0) {
			if_printf(ifp, "XXX: driver didn't set ifq_maxlen\n");
			ifp->if_snd.ifq_maxlen = ifqmaxlen;
		}
	}
	crit_exit();

	if_slowtimo(0);
}

static int
if_start_cpuid(struct ifnet *ifp)
{
	return ifp->if_cpuid;
}

#ifdef DEVICE_POLLING
static int
if_start_cpuid_poll(struct ifnet *ifp)
{
	int poll_cpuid = ifp->if_poll_cpuid;

	if (poll_cpuid >= 0)
		return poll_cpuid;
	else
		return ifp->if_cpuid;
}
#endif

static void
if_start_ipifunc(void *arg)
{
	struct ifnet *ifp = arg;
	struct lwkt_msg *lmsg = &ifp->if_start_nmsg[mycpuid].lmsg;

	crit_enter();
	if (lmsg->ms_flags & MSGF_DONE)
		lwkt_sendmsg(ifnet_portfn(mycpuid), lmsg);
	crit_exit();
}

/*
 * Schedule ifnet.if_start on ifnet's CPU
 */
static void
if_start_schedule(struct ifnet *ifp)
{
#ifdef SMP
	int cpu;

	if (if_start_oncpu_sched)
		cpu = mycpuid;
	else
		cpu = ifp->if_start_cpuid(ifp);

	if (cpu != mycpuid)
		lwkt_send_ipiq(globaldata_find(cpu), if_start_ipifunc, ifp);
	else
#endif
	if_start_ipifunc(ifp);
}

/*
 * NOTE:
 * This function will release ifnet.if_start interlock,
 * if ifnet.if_start does not need to be scheduled
 */
static __inline int
if_start_need_schedule(struct ifaltq *ifq, int running)
{
	if (!running || ifq_is_empty(ifq)
#ifdef ALTQ
	    || ifq->altq_tbr != NULL
#endif
	) {
		ALTQ_LOCK(ifq);
		/*
		 * ifnet.if_start interlock is released, if:
		 * 1) Hardware can not take any packets, due to
		 *    o  interface is marked down
		 *    o  hardware queue is full (IFF_OACTIVE)
		 *    Under the second situation, hardware interrupt
		 *    or polling(4) will call/schedule ifnet.if_start
		 *    when hardware queue is ready
		 * 2) There is not packet in the ifnet.if_snd.
		 *    Further ifq_dispatch or ifq_handoff will call/
		 *    schedule ifnet.if_start
		 * 3) TBR is used and it does not allow further
		 *    dequeueing.
		 *    TBR callout will call ifnet.if_start
		 */
		if (!running || !ifq_data_ready(ifq)) {
			ifq->altq_started = 0;
			ALTQ_UNLOCK(ifq);
			return 0;
		}
		ALTQ_UNLOCK(ifq);
	}
	return 1;
}

static void
if_start_dispatch(netmsg_t msg)
{
	struct lwkt_msg *lmsg = &msg->base.lmsg;
	struct ifnet *ifp = lmsg->u.ms_resultp;
	struct ifaltq *ifq = &ifp->if_snd;
	int running = 0;

	crit_enter();
	lwkt_replymsg(lmsg, 0);	/* reply ASAP */
	crit_exit();

#ifdef SMP
	if (!if_start_oncpu_sched && mycpuid != ifp->if_start_cpuid(ifp)) {
		/*
		 * If the ifnet is still up, we need to
		 * chase its CPU change.
		 */
		if (ifp->if_flags & IFF_UP) {
			logifstart(chase_sched, ifp);
			if_start_schedule(ifp);
			return;
		} else {
			goto check;
		}
	}
#endif

	if (ifp->if_flags & IFF_UP) {
		ifnet_serialize_tx(ifp); /* XXX try? */
		if ((ifp->if_flags & IFF_OACTIVE) == 0) {
			logifstart(run, ifp);
			ifp->if_start(ifp);
			if ((ifp->if_flags &
			(IFF_OACTIVE | IFF_RUNNING)) == IFF_RUNNING)
				running = 1;
		}
		ifnet_deserialize_tx(ifp);
	}
#ifdef SMP
check:
#endif
	if (if_start_need_schedule(ifq, running)) {
		crit_enter();
		if (lmsg->ms_flags & MSGF_DONE)	{ /* XXX necessary? */
			logifstart(sched, ifp);
			lwkt_sendmsg(ifnet_portfn(mycpuid), lmsg);
		}
		crit_exit();
	}
}

/* Device driver ifnet.if_start helper function */
void
if_devstart(struct ifnet *ifp)
{
	struct ifaltq *ifq = &ifp->if_snd;
	int running = 0;

	ASSERT_IFNET_SERIALIZED_TX(ifp);

	ALTQ_LOCK(ifq);
	if (ifq->altq_started || !ifq_data_ready(ifq)) {
		logifstart(avoid, ifp);
		ALTQ_UNLOCK(ifq);
		return;
	}
	ifq->altq_started = 1;
	ALTQ_UNLOCK(ifq);

	if (if_devstart_schedonly) {
		/*
		 * Always schedule ifnet.if_start on ifnet's CPU,
		 * short circuit the rest of this function.
		 */
		logifstart(sched, ifp);
		if_start_schedule(ifp);
		return;
	}

	logifstart(run, ifp);
	ifp->if_start(ifp);

	if ((ifp->if_flags & (IFF_OACTIVE | IFF_RUNNING)) == IFF_RUNNING)
		running = 1;

	if (if_devstart_schednochk || if_start_need_schedule(ifq, running)) {
		/*
		 * More data need to be transmitted, ifnet.if_start is
		 * scheduled on ifnet's CPU, and we keep going.
		 * NOTE: ifnet.if_start interlock is not released.
		 */
		logifstart(sched, ifp);
		if_start_schedule(ifp);
	}
}

static void
if_default_serialize(struct ifnet *ifp, enum ifnet_serialize slz __unused)
{
	lwkt_serialize_enter(ifp->if_serializer);
}

static void
if_default_deserialize(struct ifnet *ifp, enum ifnet_serialize slz __unused)
{
	lwkt_serialize_exit(ifp->if_serializer);
}

static int
if_default_tryserialize(struct ifnet *ifp, enum ifnet_serialize slz __unused)
{
	return lwkt_serialize_try(ifp->if_serializer);
}

#ifdef INVARIANTS
static void
if_default_serialize_assert(struct ifnet *ifp,
			    enum ifnet_serialize slz __unused,
			    boolean_t serialized)
{
	if (serialized)
		ASSERT_SERIALIZED(ifp->if_serializer);
	else
		ASSERT_NOT_SERIALIZED(ifp->if_serializer);
}
#endif

/*
 * Attach an interface to the list of "active" interfaces.
 *
 * The serializer is optional.  If non-NULL access to the interface
 * may be MPSAFE.
 */
void
if_attach(struct ifnet *ifp, lwkt_serialize_t serializer)
{
	unsigned socksize, ifasize;
	int namelen, masklen;
	struct sockaddr_dl *sdl;
	struct ifaddr *ifa;
	struct ifaltq *ifq;
	int i;

	static int if_indexlim = 8;

	if (ifp->if_serialize != NULL) {
		KASSERT(ifp->if_deserialize != NULL &&
			ifp->if_tryserialize != NULL &&
			ifp->if_serialize_assert != NULL,
			("serialize functions are partially setup\n"));

		/*
		 * If the device supplies serialize functions,
		 * then clear if_serializer to catch any invalid
		 * usage of this field.
		 */
		KASSERT(serializer == NULL,
			("both serialize functions and default serializer "
			 "are supplied\n"));
		ifp->if_serializer = NULL;
	} else {
		KASSERT(ifp->if_deserialize == NULL &&
			ifp->if_tryserialize == NULL &&
			ifp->if_serialize_assert == NULL,
			("serialize functions are partially setup\n"));
		ifp->if_serialize = if_default_serialize;
		ifp->if_deserialize = if_default_deserialize;
		ifp->if_tryserialize = if_default_tryserialize;
#ifdef INVARIANTS
		ifp->if_serialize_assert = if_default_serialize_assert;
#endif

		/*
		 * The serializer can be passed in from the device,
		 * allowing the same serializer to be used for both
		 * the interrupt interlock and the device queue.
		 * If not specified, the netif structure will use an
		 * embedded serializer.
		 */
		if (serializer == NULL) {
			serializer = &ifp->if_default_serializer;
			lwkt_serialize_init(serializer);
		}
		ifp->if_serializer = serializer;
	}

	ifp->if_start_cpuid = if_start_cpuid;
	ifp->if_cpuid = 0;

#ifdef DEVICE_POLLING
	/* Device is not in polling mode by default */
	ifp->if_poll_cpuid = -1;
	if (ifp->if_poll != NULL)
		ifp->if_start_cpuid = if_start_cpuid_poll;
#endif

	ifp->if_start_nmsg = kmalloc(ncpus * sizeof(*ifp->if_start_nmsg),
				     M_LWKTMSG, M_WAITOK);
	for (i = 0; i < ncpus; ++i) {
		netmsg_init(&ifp->if_start_nmsg[i], NULL, &netisr_adone_rport,
			    0, if_start_dispatch);
		ifp->if_start_nmsg[i].lmsg.u.ms_resultp = ifp;
	}

	TAILQ_INSERT_TAIL(&ifnet, ifp, if_link);
	ifp->if_index = ++if_index;

	/*
	 * XXX -
	 * The old code would work if the interface passed a pre-existing
	 * chain of ifaddrs to this code.  We don't trust our callers to
	 * properly initialize the tailq, however, so we no longer allow
	 * this unlikely case.
	 */
	ifp->if_addrheads = kmalloc(ncpus * sizeof(struct ifaddrhead),
				    M_IFADDR, M_WAITOK | M_ZERO);
	for (i = 0; i < ncpus; ++i)
		TAILQ_INIT(&ifp->if_addrheads[i]);

	TAILQ_INIT(&ifp->if_prefixhead);
	TAILQ_INIT(&ifp->if_multiaddrs);
	TAILQ_INIT(&ifp->if_groups);
	getmicrotime(&ifp->if_lastchange);
	if (ifindex2ifnet == NULL || if_index >= if_indexlim) {
		unsigned int n;
		struct ifnet **q;

		if_indexlim <<= 1;

		/* grow ifindex2ifnet */
		n = if_indexlim * sizeof(*q);
		q = kmalloc(n, M_IFADDR, M_WAITOK | M_ZERO);
		if (ifindex2ifnet) {
			bcopy(ifindex2ifnet, q, n/2);
			kfree(ifindex2ifnet, M_IFADDR);
		}
		ifindex2ifnet = q;
	}

	ifindex2ifnet[if_index] = ifp;

	/*
	 * create a Link Level name for this device
	 */
	namelen = strlen(ifp->if_xname);
#define _offsetof(t, m) ((int)((caddr_t)&((t *)0)->m))
	masklen = _offsetof(struct sockaddr_dl, sdl_data[0]) + namelen;
	socksize = masklen + ifp->if_addrlen;
#define ROUNDUP(a) (1 + (((a) - 1) | (sizeof(long) - 1)))
	if (socksize < sizeof(*sdl))
		socksize = sizeof(*sdl);
	socksize = ROUNDUP(socksize);
	ifasize = sizeof(struct ifaddr) + 2 * socksize;
	ifa = ifa_create(ifasize, M_WAITOK);
	sdl = (struct sockaddr_dl *)(ifa + 1);
	sdl->sdl_len = socksize;
	sdl->sdl_family = AF_LINK;
	bcopy(ifp->if_xname, sdl->sdl_data, namelen);
	sdl->sdl_nlen = namelen;
	sdl->sdl_index = ifp->if_index;
	sdl->sdl_type = ifp->if_type;
	ifp->if_lladdr = ifa;
	ifa->ifa_ifp = ifp;
	ifa->ifa_rtrequest = link_rtrequest;
	ifa->ifa_addr = (struct sockaddr *)sdl;
	sdl = (struct sockaddr_dl *)(socksize + (caddr_t)sdl);
	ifa->ifa_netmask = (struct sockaddr *)sdl;
	sdl->sdl_len = masklen;
	while (namelen != 0)
		sdl->sdl_data[--namelen] = 0xff;
	ifa_iflink(ifa, ifp, 0 /* Insert head */);

	EVENTHANDLER_INVOKE(ifnet_attach_event, ifp);
	devctl_notify("IFNET", ifp->if_xname, "ATTACH", NULL);

	ifq = &ifp->if_snd;
	ifq->altq_type = 0;
	ifq->altq_disc = NULL;
	ifq->altq_flags &= ALTQF_CANTCHANGE;
	ifq->altq_tbr = NULL;
	ifq->altq_ifp = ifp;
	ifq->altq_started = 0;
	ifq->altq_prepended = NULL;
	ALTQ_LOCK_INIT(ifq);
	ifq_set_classic(ifq);

	if (!SLIST_EMPTY(&domains))
		if_attachdomain1(ifp);

	/* Announce the interface. */
	rt_ifannouncemsg(ifp, IFAN_ARRIVAL);
}

static void
if_attachdomain(void *dummy)
{
	struct ifnet *ifp;

	crit_enter();
	TAILQ_FOREACH(ifp, &ifnet, if_list)
		if_attachdomain1(ifp);
	crit_exit();
}
SYSINIT(domainifattach, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_FIRST,
	if_attachdomain, NULL);

static void
if_attachdomain1(struct ifnet *ifp)
{
	struct domain *dp;

	crit_enter();

	/* address family dependent data region */
	bzero(ifp->if_afdata, sizeof(ifp->if_afdata));
	SLIST_FOREACH(dp, &domains, dom_next)
		if (dp->dom_ifattach)
			ifp->if_afdata[dp->dom_family] =
				(*dp->dom_ifattach)(ifp);
	crit_exit();
}

/*
 * Purge all addresses whose type is _not_ AF_LINK
 */
void
if_purgeaddrs_nolink(struct ifnet *ifp)
{
	struct ifaddr_container *ifac, *next;

	TAILQ_FOREACH_MUTABLE(ifac, &ifp->if_addrheads[mycpuid],
			      ifa_link, next) {
		struct ifaddr *ifa = ifac->ifa;

		/* Leave link ifaddr as it is */
		if (ifa->ifa_addr->sa_family == AF_LINK)
			continue;
#ifdef INET
		/* XXX: Ugly!! ad hoc just for INET */
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
			struct ifaliasreq ifr;
#ifdef IFADDR_DEBUG_VERBOSE
			int i;

			kprintf("purge in4 addr %p: ", ifa);
			for (i = 0; i < ncpus; ++i)
				kprintf("%d ", ifa->ifa_containers[i].ifa_refcnt);
			kprintf("\n");
#endif

			bzero(&ifr, sizeof ifr);
			ifr.ifra_addr = *ifa->ifa_addr;
			if (ifa->ifa_dstaddr)
				ifr.ifra_broadaddr = *ifa->ifa_dstaddr;
			if (in_control(NULL, SIOCDIFADDR, (caddr_t)&ifr, ifp,
				       NULL) == 0)
				continue;
		}
#endif /* INET */
#ifdef INET6
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
#ifdef IFADDR_DEBUG_VERBOSE
			int i;

			kprintf("purge in6 addr %p: ", ifa);
			for (i = 0; i < ncpus; ++i)
				kprintf("%d ", ifa->ifa_containers[i].ifa_refcnt);
			kprintf("\n");
#endif

			in6_purgeaddr(ifa);
			/* ifp_addrhead is already updated */
			continue;
		}
#endif /* INET6 */
		ifa_ifunlink(ifa, ifp);
		ifa_destroy(ifa);
	}
}

/*
 * Detach an interface, removing it from the
 * list of "active" interfaces.
 */
void
if_detach(struct ifnet *ifp)
{
	struct radix_node_head	*rnh;
	int i;
	int cpu, origcpu;
	struct domain *dp;

	EVENTHANDLER_INVOKE(ifnet_detach_event, ifp);

	/*
	 * Remove routes and flush queues.
	 */
	crit_enter();
#ifdef DEVICE_POLLING
	if (ifp->if_flags & IFF_POLLING)
		ether_poll_deregister(ifp);
#endif
#ifdef IFPOLL_ENABLE
	if (ifp->if_flags & IFF_NPOLLING)
		ifpoll_deregister(ifp);
#endif
	if_down(ifp);

#ifdef ALTQ
	if (ifq_is_enabled(&ifp->if_snd))
		altq_disable(&ifp->if_snd);
	if (ifq_is_attached(&ifp->if_snd))
		altq_detach(&ifp->if_snd);
#endif

	/*
	 * Clean up all addresses.
	 */
	ifp->if_lladdr = NULL;

	if_purgeaddrs_nolink(ifp);
	if (!TAILQ_EMPTY(&ifp->if_addrheads[mycpuid])) {
		struct ifaddr *ifa;

		ifa = TAILQ_FIRST(&ifp->if_addrheads[mycpuid])->ifa;
		KASSERT(ifa->ifa_addr->sa_family == AF_LINK,
			("non-link ifaddr is left on if_addrheads"));

		ifa_ifunlink(ifa, ifp);
		ifa_destroy(ifa);
		KASSERT(TAILQ_EMPTY(&ifp->if_addrheads[mycpuid]),
			("there are still ifaddrs left on if_addrheads"));
	}

#ifdef INET
	/*
	 * Remove all IPv4 kernel structures related to ifp.
	 */
	in_ifdetach(ifp);
#endif

#ifdef INET6
	/*
	 * Remove all IPv6 kernel structs related to ifp.  This should be done
	 * before removing routing entries below, since IPv6 interface direct
	 * routes are expected to be removed by the IPv6-specific kernel API.
	 * Otherwise, the kernel will detect some inconsistency and bark it.
	 */
	in6_ifdetach(ifp);
#endif

	/*
	 * Delete all remaining routes using this interface
	 * Unfortuneatly the only way to do this is to slog through
	 * the entire routing table looking for routes which point
	 * to this interface...oh well...
	 */
	origcpu = mycpuid;
	for (cpu = 0; cpu < ncpus2; cpu++) {
		lwkt_migratecpu(cpu);
		for (i = 1; i <= AF_MAX; i++) {
			if ((rnh = rt_tables[cpu][i]) == NULL)
				continue;
			rnh->rnh_walktree(rnh, if_rtdel, ifp);
		}
	}
	lwkt_migratecpu(origcpu);

	/* Announce that the interface is gone. */
	rt_ifannouncemsg(ifp, IFAN_DEPARTURE);
	devctl_notify("IFNET", ifp->if_xname, "DETACH", NULL);

	SLIST_FOREACH(dp, &domains, dom_next)
		if (dp->dom_ifdetach && ifp->if_afdata[dp->dom_family])
			(*dp->dom_ifdetach)(ifp,
				ifp->if_afdata[dp->dom_family]);

	/*
	 * Remove interface from ifindex2ifp[] and maybe decrement if_index.
	 */
	ifindex2ifnet[ifp->if_index] = NULL;
	while (if_index > 0 && ifindex2ifnet[if_index] == NULL)
		if_index--;

	TAILQ_REMOVE(&ifnet, ifp, if_link);
	kfree(ifp->if_addrheads, M_IFADDR);
	kfree(ifp->if_start_nmsg, M_LWKTMSG);
	crit_exit();
}

/*
 * Create interface group without members
 */
struct ifg_group *
if_creategroup(const char *groupname)
{
        struct ifg_group        *ifg = NULL;

        if ((ifg = (struct ifg_group *)kmalloc(sizeof(struct ifg_group),
            M_TEMP, M_NOWAIT)) == NULL)
                return (NULL);

        strlcpy(ifg->ifg_group, groupname, sizeof(ifg->ifg_group));
        ifg->ifg_refcnt = 0;
        ifg->ifg_carp_demoted = 0;
        TAILQ_INIT(&ifg->ifg_members);
#if NPF > 0
        pfi_attach_ifgroup(ifg);
#endif
        TAILQ_INSERT_TAIL(&ifg_head, ifg, ifg_next);

        return (ifg);
}

/*
 * Add a group to an interface
 */
int
if_addgroup(struct ifnet *ifp, const char *groupname)
{
	struct ifg_list		*ifgl;
	struct ifg_group	*ifg = NULL;
	struct ifg_member	*ifgm;

	if (groupname[0] && groupname[strlen(groupname) - 1] >= '0' &&
	    groupname[strlen(groupname) - 1] <= '9')
		return (EINVAL);

	TAILQ_FOREACH(ifgl, &ifp->if_groups, ifgl_next)
		if (!strcmp(ifgl->ifgl_group->ifg_group, groupname))
			return (EEXIST);

	if ((ifgl = kmalloc(sizeof(*ifgl), M_TEMP, M_NOWAIT)) == NULL)
		return (ENOMEM);

	if ((ifgm = kmalloc(sizeof(*ifgm), M_TEMP, M_NOWAIT)) == NULL) {
		kfree(ifgl, M_TEMP);
		return (ENOMEM);
	}

	TAILQ_FOREACH(ifg, &ifg_head, ifg_next)
		if (!strcmp(ifg->ifg_group, groupname))
			break;

	if (ifg == NULL && (ifg = if_creategroup(groupname)) == NULL) {
		kfree(ifgl, M_TEMP);
		kfree(ifgm, M_TEMP);
		return (ENOMEM);
	}

	ifg->ifg_refcnt++;
	ifgl->ifgl_group = ifg;
	ifgm->ifgm_ifp = ifp;

	TAILQ_INSERT_TAIL(&ifg->ifg_members, ifgm, ifgm_next);
	TAILQ_INSERT_TAIL(&ifp->if_groups, ifgl, ifgl_next);

#if NPF > 0
	pfi_group_change(groupname);
#endif

	return (0);
}

/*
 * Remove a group from an interface
 */
int
if_delgroup(struct ifnet *ifp, const char *groupname)
{
	struct ifg_list		*ifgl;
	struct ifg_member	*ifgm;

	TAILQ_FOREACH(ifgl, &ifp->if_groups, ifgl_next)
		if (!strcmp(ifgl->ifgl_group->ifg_group, groupname))
			break;
	if (ifgl == NULL)
		return (ENOENT);

	TAILQ_REMOVE(&ifp->if_groups, ifgl, ifgl_next);

	TAILQ_FOREACH(ifgm, &ifgl->ifgl_group->ifg_members, ifgm_next)
		if (ifgm->ifgm_ifp == ifp)
			break;

	if (ifgm != NULL) {
		TAILQ_REMOVE(&ifgl->ifgl_group->ifg_members, ifgm, ifgm_next);
		kfree(ifgm, M_TEMP);
	}

	if (--ifgl->ifgl_group->ifg_refcnt == 0) {
		TAILQ_REMOVE(&ifg_head, ifgl->ifgl_group, ifg_next);
#if NPF > 0
		pfi_detach_ifgroup(ifgl->ifgl_group);
#endif
		kfree(ifgl->ifgl_group, M_TEMP);
	}

	kfree(ifgl, M_TEMP);

#if NPF > 0
	pfi_group_change(groupname);
#endif

	return (0);
}

/*
 * Stores all groups from an interface in memory pointed
 * to by data
 */
int
if_getgroup(caddr_t data, struct ifnet *ifp)
{
	int			 len, error;
	struct ifg_list		*ifgl;
	struct ifg_req		 ifgrq, *ifgp;
	struct ifgroupreq	*ifgr = (struct ifgroupreq *)data;

	if (ifgr->ifgr_len == 0) {
		TAILQ_FOREACH(ifgl, &ifp->if_groups, ifgl_next)
			ifgr->ifgr_len += sizeof(struct ifg_req);
		return (0);
	}

	len = ifgr->ifgr_len;
	ifgp = ifgr->ifgr_groups;
	TAILQ_FOREACH(ifgl, &ifp->if_groups, ifgl_next) {
		if (len < sizeof(ifgrq))
			return (EINVAL);
		bzero(&ifgrq, sizeof ifgrq);
		strlcpy(ifgrq.ifgrq_group, ifgl->ifgl_group->ifg_group,
		    sizeof(ifgrq.ifgrq_group));
		if ((error = copyout((caddr_t)&ifgrq, (caddr_t)ifgp,
		    sizeof(struct ifg_req))))
			return (error);
		len -= sizeof(ifgrq);
		ifgp++;
	}

	return (0);
}

/*
 * Stores all members of a group in memory pointed to by data
 */
int
if_getgroupmembers(caddr_t data)
{
	struct ifgroupreq	*ifgr = (struct ifgroupreq *)data;
	struct ifg_group	*ifg;
	struct ifg_member	*ifgm;
	struct ifg_req		 ifgrq, *ifgp;
	int			 len, error;

	TAILQ_FOREACH(ifg, &ifg_head, ifg_next)
		if (!strcmp(ifg->ifg_group, ifgr->ifgr_name))
			break;
	if (ifg == NULL)
		return (ENOENT);

	if (ifgr->ifgr_len == 0) {
		TAILQ_FOREACH(ifgm, &ifg->ifg_members, ifgm_next)
			ifgr->ifgr_len += sizeof(ifgrq);
		return (0);
	}

	len = ifgr->ifgr_len;
	ifgp = ifgr->ifgr_groups;
	TAILQ_FOREACH(ifgm, &ifg->ifg_members, ifgm_next) {
		if (len < sizeof(ifgrq))
			return (EINVAL);
		bzero(&ifgrq, sizeof ifgrq);
		strlcpy(ifgrq.ifgrq_member, ifgm->ifgm_ifp->if_xname,
		    sizeof(ifgrq.ifgrq_member));
		if ((error = copyout((caddr_t)&ifgrq, (caddr_t)ifgp,
		    sizeof(struct ifg_req))))
			return (error);
		len -= sizeof(ifgrq);
		ifgp++;
	}

	return (0);
}

/*
 * Delete Routes for a Network Interface
 *
 * Called for each routing entry via the rnh->rnh_walktree() call above
 * to delete all route entries referencing a detaching network interface.
 *
 * Arguments:
 *	rn	pointer to node in the routing table
 *	arg	argument passed to rnh->rnh_walktree() - detaching interface
 *
 * Returns:
 *	0	successful
 *	errno	failed - reason indicated
 *
 */
static int
if_rtdel(struct radix_node *rn, void *arg)
{
	struct rtentry	*rt = (struct rtentry *)rn;
	struct ifnet	*ifp = arg;
	int		err;

	if (rt->rt_ifp == ifp) {

		/*
		 * Protect (sorta) against walktree recursion problems
		 * with cloned routes
		 */
		if (!(rt->rt_flags & RTF_UP))
			return (0);

		err = rtrequest(RTM_DELETE, rt_key(rt), rt->rt_gateway,
				rt_mask(rt), rt->rt_flags,
				NULL);
		if (err) {
			log(LOG_WARNING, "if_rtdel: error %d\n", err);
		}
	}

	return (0);
}

/*
 * Locate an interface based on a complete address.
 */
struct ifaddr *
ifa_ifwithaddr(struct sockaddr *addr)
{
	struct ifnet *ifp;

	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		struct ifaddr_container *ifac;

		TAILQ_FOREACH(ifac, &ifp->if_addrheads[mycpuid], ifa_link) {
			struct ifaddr *ifa = ifac->ifa;

			if (ifa->ifa_addr->sa_family != addr->sa_family)
				continue;
			if (sa_equal(addr, ifa->ifa_addr))
				return (ifa);
			if ((ifp->if_flags & IFF_BROADCAST) &&
			    ifa->ifa_broadaddr &&
			    /* IPv6 doesn't have broadcast */
			    ifa->ifa_broadaddr->sa_len != 0 &&
			    sa_equal(ifa->ifa_broadaddr, addr))
				return (ifa);
		}
	}
	return (NULL);
}
/*
 * Locate the point to point interface with a given destination address.
 */
struct ifaddr *
ifa_ifwithdstaddr(struct sockaddr *addr)
{
	struct ifnet *ifp;

	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		struct ifaddr_container *ifac;

		if (!(ifp->if_flags & IFF_POINTOPOINT))
			continue;

		TAILQ_FOREACH(ifac, &ifp->if_addrheads[mycpuid], ifa_link) {
			struct ifaddr *ifa = ifac->ifa;

			if (ifa->ifa_addr->sa_family != addr->sa_family)
				continue;
			if (ifa->ifa_dstaddr &&
			    sa_equal(addr, ifa->ifa_dstaddr))
				return (ifa);
		}
	}
	return (NULL);
}

/*
 * Find an interface on a specific network.  If many, choice
 * is most specific found.
 */
struct ifaddr *
ifa_ifwithnet(struct sockaddr *addr)
{
	struct ifnet *ifp;
	struct ifaddr *ifa_maybe = NULL;
	u_int af = addr->sa_family;
	char *addr_data = addr->sa_data, *cplim;

	/*
	 * AF_LINK addresses can be looked up directly by their index number,
	 * so do that if we can.
	 */
	if (af == AF_LINK) {
		struct sockaddr_dl *sdl = (struct sockaddr_dl *)addr;

		if (sdl->sdl_index && sdl->sdl_index <= if_index)
			return (ifindex2ifnet[sdl->sdl_index]->if_lladdr);
	}

	/*
	 * Scan though each interface, looking for ones that have
	 * addresses in this address family.
	 */
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		struct ifaddr_container *ifac;

		TAILQ_FOREACH(ifac, &ifp->if_addrheads[mycpuid], ifa_link) {
			struct ifaddr *ifa = ifac->ifa;
			char *cp, *cp2, *cp3;

			if (ifa->ifa_addr->sa_family != af)
next:				continue;
			if (af == AF_INET && ifp->if_flags & IFF_POINTOPOINT) {
				/*
				 * This is a bit broken as it doesn't
				 * take into account that the remote end may
				 * be a single node in the network we are
				 * looking for.
				 * The trouble is that we don't know the
				 * netmask for the remote end.
				 */
				if (ifa->ifa_dstaddr != NULL &&
				    sa_equal(addr, ifa->ifa_dstaddr))
					return (ifa);
			} else {
				/*
				 * if we have a special address handler,
				 * then use it instead of the generic one.
				 */
				if (ifa->ifa_claim_addr) {
					if ((*ifa->ifa_claim_addr)(ifa, addr)) {
						return (ifa);
					} else {
						continue;
					}
				}

				/*
				 * Scan all the bits in the ifa's address.
				 * If a bit dissagrees with what we are
				 * looking for, mask it with the netmask
				 * to see if it really matters.
				 * (A byte at a time)
				 */
				if (ifa->ifa_netmask == 0)
					continue;
				cp = addr_data;
				cp2 = ifa->ifa_addr->sa_data;
				cp3 = ifa->ifa_netmask->sa_data;
				cplim = ifa->ifa_netmask->sa_len +
					(char *)ifa->ifa_netmask;
				while (cp3 < cplim)
					if ((*cp++ ^ *cp2++) & *cp3++)
						goto next; /* next address! */
				/*
				 * If the netmask of what we just found
				 * is more specific than what we had before
				 * (if we had one) then remember the new one
				 * before continuing to search
				 * for an even better one.
				 */
				if (ifa_maybe == 0 ||
				    rn_refines((char *)ifa->ifa_netmask,
					       (char *)ifa_maybe->ifa_netmask))
					ifa_maybe = ifa;
			}
		}
	}
	return (ifa_maybe);
}

/*
 * Find an interface address specific to an interface best matching
 * a given address.
 */
struct ifaddr *
ifaof_ifpforaddr(struct sockaddr *addr, struct ifnet *ifp)
{
	struct ifaddr_container *ifac;
	char *cp, *cp2, *cp3;
	char *cplim;
	struct ifaddr *ifa_maybe = 0;
	u_int af = addr->sa_family;

	if (af >= AF_MAX)
		return (0);
	TAILQ_FOREACH(ifac, &ifp->if_addrheads[mycpuid], ifa_link) {
		struct ifaddr *ifa = ifac->ifa;

		if (ifa->ifa_addr->sa_family != af)
			continue;
		if (ifa_maybe == 0)
			ifa_maybe = ifa;
		if (ifa->ifa_netmask == NULL) {
			if (sa_equal(addr, ifa->ifa_addr) ||
			    (ifa->ifa_dstaddr != NULL &&
			     sa_equal(addr, ifa->ifa_dstaddr)))
				return (ifa);
			continue;
		}
		if (ifp->if_flags & IFF_POINTOPOINT) {
			if (sa_equal(addr, ifa->ifa_dstaddr))
				return (ifa);
		} else {
			cp = addr->sa_data;
			cp2 = ifa->ifa_addr->sa_data;
			cp3 = ifa->ifa_netmask->sa_data;
			cplim = ifa->ifa_netmask->sa_len + (char *)ifa->ifa_netmask;
			for (; cp3 < cplim; cp3++)
				if ((*cp++ ^ *cp2++) & *cp3)
					break;
			if (cp3 == cplim)
				return (ifa);
		}
	}
	return (ifa_maybe);
}

/*
 * Default action when installing a route with a Link Level gateway.
 * Lookup an appropriate real ifa to point to.
 * This should be moved to /sys/net/link.c eventually.
 */
static void
link_rtrequest(int cmd, struct rtentry *rt, struct rt_addrinfo *info)
{
	struct ifaddr *ifa;
	struct sockaddr *dst;
	struct ifnet *ifp;

	if (cmd != RTM_ADD || (ifa = rt->rt_ifa) == NULL ||
	    (ifp = ifa->ifa_ifp) == NULL || (dst = rt_key(rt)) == NULL)
		return;
	ifa = ifaof_ifpforaddr(dst, ifp);
	if (ifa != NULL) {
		IFAFREE(rt->rt_ifa);
		IFAREF(ifa);
		rt->rt_ifa = ifa;
		if (ifa->ifa_rtrequest && ifa->ifa_rtrequest != link_rtrequest)
			ifa->ifa_rtrequest(cmd, rt, info);
	}
}

/*
 * Mark an interface down and notify protocols of
 * the transition.
 * NOTE: must be called at splnet or eqivalent.
 */
void
if_unroute(struct ifnet *ifp, int flag, int fam)
{
	struct ifaddr_container *ifac;

	ifp->if_flags &= ~flag;
	getmicrotime(&ifp->if_lastchange);
	TAILQ_FOREACH(ifac, &ifp->if_addrheads[mycpuid], ifa_link) {
		struct ifaddr *ifa = ifac->ifa;

		if (fam == PF_UNSPEC || (fam == ifa->ifa_addr->sa_family))
			kpfctlinput(PRC_IFDOWN, ifa->ifa_addr);
	}
	ifq_purge(&ifp->if_snd);
	rt_ifmsg(ifp);
}

/*
 * Mark an interface up and notify protocols of
 * the transition.
 * NOTE: must be called at splnet or eqivalent.
 */
void
if_route(struct ifnet *ifp, int flag, int fam)
{
	struct ifaddr_container *ifac;

	ifq_purge(&ifp->if_snd);
	ifp->if_flags |= flag;
	getmicrotime(&ifp->if_lastchange);
	TAILQ_FOREACH(ifac, &ifp->if_addrheads[mycpuid], ifa_link) {
		struct ifaddr *ifa = ifac->ifa;

		if (fam == PF_UNSPEC || (fam == ifa->ifa_addr->sa_family))
			kpfctlinput(PRC_IFUP, ifa->ifa_addr);
	}
	rt_ifmsg(ifp);
#ifdef INET6
	in6_if_up(ifp);
#endif
}

/*
 * Mark an interface down and notify protocols of the transition.  An
 * interface going down is also considered to be a synchronizing event.
 * We must ensure that all packet processing related to the interface
 * has completed before we return so e.g. the caller can free the ifnet
 * structure that the mbufs may be referencing.
 *
 * NOTE: must be called at splnet or eqivalent.
 */
void
if_down(struct ifnet *ifp)
{
	if_unroute(ifp, IFF_UP, AF_UNSPEC);
	netmsg_service_sync();
}

/*
 * Mark an interface up and notify protocols of
 * the transition.
 * NOTE: must be called at splnet or eqivalent.
 */
void
if_up(struct ifnet *ifp)
{
	if_route(ifp, IFF_UP, AF_UNSPEC);
}

/*
 * Process a link state change.
 * NOTE: must be called at splsoftnet or equivalent.
 */
void
if_link_state_change(struct ifnet *ifp)
{
	int link_state = ifp->if_link_state;

	rt_ifmsg(ifp);
	devctl_notify("IFNET", ifp->if_xname,
	    (link_state == LINK_STATE_UP) ? "LINK_UP" : "LINK_DOWN", NULL);
}

/*
 * Handle interface watchdog timer routines.  Called
 * from softclock, we decrement timers (if set) and
 * call the appropriate interface routine on expiration.
 */
static void
if_slowtimo(void *arg)
{
	struct ifnet *ifp;

	crit_enter();

	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (ifp->if_timer == 0 || --ifp->if_timer)
			continue;
		if (ifp->if_watchdog) {
			if (ifnet_tryserialize_all(ifp)) {
				(*ifp->if_watchdog)(ifp);
				ifnet_deserialize_all(ifp);
			} else {
				/* try again next timeout */
				++ifp->if_timer;
			}
		}
	}

	crit_exit();

	callout_reset(&if_slowtimo_timer, hz / IFNET_SLOWHZ, if_slowtimo, NULL);
}

/*
 * Map interface name to
 * interface structure pointer.
 */
struct ifnet *
ifunit(const char *name)
{
	struct ifnet *ifp;

	/*
	 * Search all the interfaces for this name/number
	 */

	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (strncmp(ifp->if_xname, name, IFNAMSIZ) == 0)
			break;
	}
	return (ifp);
}


/*
 * Map interface name in a sockaddr_dl to
 * interface structure pointer.
 */
struct ifnet *
if_withname(struct sockaddr *sa)
{
	char ifname[IFNAMSIZ+1];
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;

	if ( (sa->sa_family != AF_LINK) || (sdl->sdl_nlen == 0) ||
	     (sdl->sdl_nlen > IFNAMSIZ) )
		return NULL;

	/*
	 * ifunit wants a null-terminated name.  It may not be null-terminated
	 * in the sockaddr.  We don't want to change the caller's sockaddr,
	 * and there might not be room to put the trailing null anyway, so we
	 * make a local copy that we know we can null terminate safely.
	 */

	bcopy(sdl->sdl_data, ifname, sdl->sdl_nlen);
	ifname[sdl->sdl_nlen] = '\0';
	return ifunit(ifname);
}


/*
 * Interface ioctls.
 */
int
ifioctl(struct socket *so, u_long cmd, caddr_t data, struct ucred *cred)
{
	struct ifnet *ifp;
	struct ifreq *ifr;
	struct ifstat *ifs;
	int error;
	short oif_flags;
	int new_flags;
	size_t namelen, onamelen;
	char new_name[IFNAMSIZ];
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;

	switch (cmd) {

	case SIOCGIFCONF:
	case OSIOCGIFCONF:
		return (ifconf(cmd, data, cred));
	}
	ifr = (struct ifreq *)data;

	switch (cmd) {
	case SIOCIFCREATE:
	case SIOCIFCREATE2:
		if ((error = priv_check_cred(cred, PRIV_ROOT, 0)) != 0)
			return (error);
		return (if_clone_create(ifr->ifr_name, sizeof(ifr->ifr_name),
		    	cmd == SIOCIFCREATE2 ? ifr->ifr_data : NULL));
	case SIOCIFDESTROY:
		if ((error = priv_check_cred(cred, PRIV_ROOT, 0)) != 0)
			return (error);
		return (if_clone_destroy(ifr->ifr_name));

	case SIOCIFGCLONERS:
		return (if_clone_list((struct if_clonereq *)data));
	}

	ifp = ifunit(ifr->ifr_name);
	if (ifp == 0)
		return (ENXIO);
	switch (cmd) {

	case SIOCGIFINDEX:
		ifr->ifr_index = ifp->if_index;
		break;

	case SIOCGIFFLAGS:
		ifr->ifr_flags = ifp->if_flags;
		ifr->ifr_flagshigh = ifp->if_flags >> 16;
		break;

	case SIOCGIFCAP:
		ifr->ifr_reqcap = ifp->if_capabilities;
		ifr->ifr_curcap = ifp->if_capenable;
		break;

	case SIOCGIFMETRIC:
		ifr->ifr_metric = ifp->if_metric;
		break;

	case SIOCGIFMTU:
		ifr->ifr_mtu = ifp->if_mtu;
		break;

	case SIOCGIFDATA:
		error = copyout((caddr_t)&ifp->if_data, ifr->ifr_data,
		    sizeof(ifp->if_data));
		break;


	case SIOCGIFPHYS:
		ifr->ifr_phys = ifp->if_physical;
		break;

	case SIOCGIFPOLLCPU:
#ifdef DEVICE_POLLING
		ifr->ifr_pollcpu = ifp->if_poll_cpuid;
#else
		ifr->ifr_pollcpu = -1;
#endif
		break;

	case SIOCSIFPOLLCPU:
#ifdef DEVICE_POLLING
		if ((ifp->if_flags & IFF_POLLING) == 0)
			ether_pollcpu_register(ifp, ifr->ifr_pollcpu);
#endif
		break;

	case SIOCSIFFLAGS:
		error = priv_check_cred(cred, PRIV_ROOT, 0);
		if (error)
			return (error);
		new_flags = (ifr->ifr_flags & 0xffff) |
		    (ifr->ifr_flagshigh << 16);
		if (ifp->if_flags & IFF_SMART) {
			/* Smart drivers twiddle their own routes */
		} else if (ifp->if_flags & IFF_UP &&
		    (new_flags & IFF_UP) == 0) {
			crit_enter();
			if_down(ifp);
			crit_exit();
		} else if (new_flags & IFF_UP &&
		    (ifp->if_flags & IFF_UP) == 0) {
			crit_enter();
			if_up(ifp);
			crit_exit();
		}

#ifdef DEVICE_POLLING
		if ((new_flags ^ ifp->if_flags) & IFF_POLLING) {
			if (new_flags & IFF_POLLING) {
				ether_poll_register(ifp);
			} else {
				ether_poll_deregister(ifp);
			}
		}
#endif
#ifdef IFPOLL_ENABLE
		if ((new_flags ^ ifp->if_flags) & IFF_NPOLLING) {
			if (new_flags & IFF_NPOLLING)
				ifpoll_register(ifp);
			else
				ifpoll_deregister(ifp);
		}
#endif

		ifp->if_flags = (ifp->if_flags & IFF_CANTCHANGE) |
			(new_flags &~ IFF_CANTCHANGE);
		if (new_flags & IFF_PPROMISC) {
			/* Permanently promiscuous mode requested */
			ifp->if_flags |= IFF_PROMISC;
		} else if (ifp->if_pcount == 0) {
			ifp->if_flags &= ~IFF_PROMISC;
		}
		if (ifp->if_ioctl) {
			ifnet_serialize_all(ifp);
			ifp->if_ioctl(ifp, cmd, data, cred);
			ifnet_deserialize_all(ifp);
		}
		getmicrotime(&ifp->if_lastchange);
		break;

	case SIOCSIFCAP:
		error = priv_check_cred(cred, PRIV_ROOT, 0);
		if (error)
			return (error);
		if (ifr->ifr_reqcap & ~ifp->if_capabilities)
			return (EINVAL);
		ifnet_serialize_all(ifp);
		ifp->if_ioctl(ifp, cmd, data, cred);
		ifnet_deserialize_all(ifp);
		break;

	case SIOCSIFNAME:
		error = priv_check_cred(cred, PRIV_ROOT, 0);
		if (error != 0)
			return (error);
		error = copyinstr(ifr->ifr_data, new_name, IFNAMSIZ, NULL);
		if (error != 0)
			return (error);
		if (new_name[0] == '\0')
			return (EINVAL);
		if (ifunit(new_name) != NULL)
			return (EEXIST);

		EVENTHANDLER_INVOKE(ifnet_detach_event, ifp);

		/* Announce the departure of the interface. */
		rt_ifannouncemsg(ifp, IFAN_DEPARTURE);

		strlcpy(ifp->if_xname, new_name, sizeof(ifp->if_xname));
		ifa = TAILQ_FIRST(&ifp->if_addrheads[mycpuid])->ifa;
		/* XXX IFA_LOCK(ifa); */
		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		namelen = strlen(new_name);
		onamelen = sdl->sdl_nlen;
		/*
		 * Move the address if needed.  This is safe because we
		 * allocate space for a name of length IFNAMSIZ when we
		 * create this in if_attach().
		 */
		if (namelen != onamelen) {
			bcopy(sdl->sdl_data + onamelen,
			    sdl->sdl_data + namelen, sdl->sdl_alen);
		}
		bcopy(new_name, sdl->sdl_data, namelen);
		sdl->sdl_nlen = namelen;
		sdl = (struct sockaddr_dl *)ifa->ifa_netmask;
		bzero(sdl->sdl_data, onamelen);
		while (namelen != 0)
			sdl->sdl_data[--namelen] = 0xff;
		/* XXX IFA_UNLOCK(ifa) */

		EVENTHANDLER_INVOKE(ifnet_attach_event, ifp);

		/* Announce the return of the interface. */
		rt_ifannouncemsg(ifp, IFAN_ARRIVAL);
		break;

	case SIOCSIFMETRIC:
		error = priv_check_cred(cred, PRIV_ROOT, 0);
		if (error)
			return (error);
		ifp->if_metric = ifr->ifr_metric;
		getmicrotime(&ifp->if_lastchange);
		break;

	case SIOCSIFPHYS:
		error = priv_check_cred(cred, PRIV_ROOT, 0);
		if (error)
			return error;
		if (!ifp->if_ioctl)
		        return EOPNOTSUPP;
		ifnet_serialize_all(ifp);
		error = ifp->if_ioctl(ifp, cmd, data, cred);
		ifnet_deserialize_all(ifp);
		if (error == 0)
			getmicrotime(&ifp->if_lastchange);
		return (error);

	case SIOCSIFMTU:
	{
		u_long oldmtu = ifp->if_mtu;

		error = priv_check_cred(cred, PRIV_ROOT, 0);
		if (error)
			return (error);
		if (ifp->if_ioctl == NULL)
			return (EOPNOTSUPP);
		if (ifr->ifr_mtu < IF_MINMTU || ifr->ifr_mtu > IF_MAXMTU)
			return (EINVAL);
		ifnet_serialize_all(ifp);
		error = ifp->if_ioctl(ifp, cmd, data, cred);
		ifnet_deserialize_all(ifp);
		if (error == 0) {
			getmicrotime(&ifp->if_lastchange);
			rt_ifmsg(ifp);
		}
		/*
		 * If the link MTU changed, do network layer specific procedure.
		 */
		if (ifp->if_mtu != oldmtu) {
#ifdef INET6
			nd6_setmtu(ifp);
#endif
		}
		return (error);
	}

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = priv_check_cred(cred, PRIV_ROOT, 0);
		if (error)
			return (error);

		/* Don't allow group membership on non-multicast interfaces. */
		if ((ifp->if_flags & IFF_MULTICAST) == 0)
			return EOPNOTSUPP;

		/* Don't let users screw up protocols' entries. */
		if (ifr->ifr_addr.sa_family != AF_LINK)
			return EINVAL;

		if (cmd == SIOCADDMULTI) {
			struct ifmultiaddr *ifma;
			error = if_addmulti(ifp, &ifr->ifr_addr, &ifma);
		} else {
			error = if_delmulti(ifp, &ifr->ifr_addr);
		}
		if (error == 0)
			getmicrotime(&ifp->if_lastchange);
		return error;

	case SIOCSIFPHYADDR:
	case SIOCDIFPHYADDR:
#ifdef INET6
	case SIOCSIFPHYADDR_IN6:
#endif
	case SIOCSLIFPHYADDR:
        case SIOCSIFMEDIA:
	case SIOCSIFGENERIC:
		error = priv_check_cred(cred, PRIV_ROOT, 0);
		if (error)
			return (error);
		if (ifp->if_ioctl == 0)
			return (EOPNOTSUPP);
		ifnet_serialize_all(ifp);
		error = ifp->if_ioctl(ifp, cmd, data, cred);
		ifnet_deserialize_all(ifp);
		if (error == 0)
			getmicrotime(&ifp->if_lastchange);
		return error;

	case SIOCGIFSTATUS:
		ifs = (struct ifstat *)data;
		ifs->ascii[0] = '\0';

	case SIOCGIFPSRCADDR:
	case SIOCGIFPDSTADDR:
	case SIOCGLIFPHYADDR:
	case SIOCGIFMEDIA:
	case SIOCGIFGENERIC:
		if (ifp->if_ioctl == NULL)
			return (EOPNOTSUPP);
		ifnet_serialize_all(ifp);
		error = ifp->if_ioctl(ifp, cmd, data, cred);
		ifnet_deserialize_all(ifp);
		return (error);

	case SIOCSIFLLADDR:
		error = priv_check_cred(cred, PRIV_ROOT, 0);
		if (error)
			return (error);
		error = if_setlladdr(ifp,
		    ifr->ifr_addr.sa_data, ifr->ifr_addr.sa_len);
		EVENTHANDLER_INVOKE(iflladdr_event, ifp);
		return (error);

	default:
		oif_flags = ifp->if_flags;
		if (so->so_proto == 0)
			return (EOPNOTSUPP);
#ifndef COMPAT_43
		error = so_pru_control_direct(so, cmd, data, ifp);
#else
	    {
		int ocmd = cmd;

		switch (cmd) {

		case SIOCSIFDSTADDR:
		case SIOCSIFADDR:
		case SIOCSIFBRDADDR:
		case SIOCSIFNETMASK:
#if BYTE_ORDER != BIG_ENDIAN
			if (ifr->ifr_addr.sa_family == 0 &&
			    ifr->ifr_addr.sa_len < 16) {
				ifr->ifr_addr.sa_family = ifr->ifr_addr.sa_len;
				ifr->ifr_addr.sa_len = 16;
			}
#else
			if (ifr->ifr_addr.sa_len == 0)
				ifr->ifr_addr.sa_len = 16;
#endif
			break;

		case OSIOCGIFADDR:
			cmd = SIOCGIFADDR;
			break;

		case OSIOCGIFDSTADDR:
			cmd = SIOCGIFDSTADDR;
			break;

		case OSIOCGIFBRDADDR:
			cmd = SIOCGIFBRDADDR;
			break;

		case OSIOCGIFNETMASK:
			cmd = SIOCGIFNETMASK;
		}

		error = so_pru_control_direct(so, cmd, data, ifp);

		switch (ocmd) {
		case OSIOCGIFADDR:
		case OSIOCGIFDSTADDR:
		case OSIOCGIFBRDADDR:
		case OSIOCGIFNETMASK:
			*(u_short *)&ifr->ifr_addr = ifr->ifr_addr.sa_family;
			break;
		}
	    }
#endif /* COMPAT_43 */

		if ((oif_flags ^ ifp->if_flags) & IFF_UP) {
#ifdef INET6
			DELAY(100);/* XXX: temporary workaround for fxp issue*/
			if (ifp->if_flags & IFF_UP) {
				crit_enter();
				in6_if_up(ifp);
				crit_exit();
			}
#endif
		}
		return (error);

	}
	return (0);
}

/*
 * Set/clear promiscuous mode on interface ifp based on the truth value
 * of pswitch.  The calls are reference counted so that only the first
 * "on" request actually has an effect, as does the final "off" request.
 * Results are undefined if the "off" and "on" requests are not matched.
 */
int
ifpromisc(struct ifnet *ifp, int pswitch)
{
	struct ifreq ifr;
	int error;
	int oldflags;

	oldflags = ifp->if_flags;
	if (ifp->if_flags & IFF_PPROMISC) {
		/* Do nothing if device is in permanently promiscuous mode */
		ifp->if_pcount += pswitch ? 1 : -1;
		return (0);
	}
	if (pswitch) {
		/*
		 * If the device is not configured up, we cannot put it in
		 * promiscuous mode.
		 */
		if ((ifp->if_flags & IFF_UP) == 0)
			return (ENETDOWN);
		if (ifp->if_pcount++ != 0)
			return (0);
		ifp->if_flags |= IFF_PROMISC;
		log(LOG_INFO, "%s: promiscuous mode enabled\n",
		    ifp->if_xname);
	} else {
		if (--ifp->if_pcount > 0)
			return (0);
		ifp->if_flags &= ~IFF_PROMISC;
		log(LOG_INFO, "%s: promiscuous mode disabled\n",
		    ifp->if_xname);
	}
	ifr.ifr_flags = ifp->if_flags;
	ifr.ifr_flagshigh = ifp->if_flags >> 16;
	ifnet_serialize_all(ifp);
	error = ifp->if_ioctl(ifp, SIOCSIFFLAGS, (caddr_t)&ifr, NULL);
	ifnet_deserialize_all(ifp);
	if (error == 0)
		rt_ifmsg(ifp);
	else
		ifp->if_flags = oldflags;
	return error;
}

/*
 * Return interface configuration
 * of system.  List may be used
 * in later ioctl's (above) to get
 * other information.
 */
static int
ifconf(u_long cmd, caddr_t data, struct ucred *cred)
{
	struct ifconf *ifc = (struct ifconf *)data;
	struct ifnet *ifp;
	struct sockaddr *sa;
	struct ifreq ifr, *ifrp;
	int space = ifc->ifc_len, error = 0;

	ifrp = ifc->ifc_req;
	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		struct ifaddr_container *ifac;
		int addrs;

		if (space <= sizeof ifr)
			break;

		/*
		 * Zero the stack declared structure first to prevent
		 * memory disclosure.
		 */
		bzero(&ifr, sizeof(ifr));
		if (strlcpy(ifr.ifr_name, ifp->if_xname, sizeof(ifr.ifr_name))
		    >= sizeof(ifr.ifr_name)) {
			error = ENAMETOOLONG;
			break;
		}

		addrs = 0;
		TAILQ_FOREACH(ifac, &ifp->if_addrheads[mycpuid], ifa_link) {
			struct ifaddr *ifa = ifac->ifa;

			if (space <= sizeof ifr)
				break;
			sa = ifa->ifa_addr;
			if (cred->cr_prison &&
			    prison_if(cred, sa))
				continue;
			addrs++;
#ifdef COMPAT_43
			if (cmd == OSIOCGIFCONF) {
				struct osockaddr *osa =
					 (struct osockaddr *)&ifr.ifr_addr;
				ifr.ifr_addr = *sa;
				osa->sa_family = sa->sa_family;
				error = copyout(&ifr, ifrp, sizeof ifr);
				ifrp++;
			} else
#endif
			if (sa->sa_len <= sizeof(*sa)) {
				ifr.ifr_addr = *sa;
				error = copyout(&ifr, ifrp, sizeof ifr);
				ifrp++;
			} else {
				if (space < (sizeof ifr) + sa->sa_len -
					    sizeof(*sa))
					break;
				space -= sa->sa_len - sizeof(*sa);
				error = copyout(&ifr, ifrp,
						sizeof ifr.ifr_name);
				if (error == 0)
					error = copyout(sa, &ifrp->ifr_addr,
							sa->sa_len);
				ifrp = (struct ifreq *)
					(sa->sa_len + (caddr_t)&ifrp->ifr_addr);
			}
			if (error)
				break;
			space -= sizeof ifr;
		}
		if (error)
			break;
		if (!addrs) {
			bzero(&ifr.ifr_addr, sizeof ifr.ifr_addr);
			error = copyout(&ifr, ifrp, sizeof ifr);
			if (error)
				break;
			space -= sizeof ifr;
			ifrp++;
		}
	}
	ifc->ifc_len -= space;
	return (error);
}

/*
 * Just like if_promisc(), but for all-multicast-reception mode.
 */
int
if_allmulti(struct ifnet *ifp, int onswitch)
{
	int error = 0;
	struct ifreq ifr;

	crit_enter();

	if (onswitch) {
		if (ifp->if_amcount++ == 0) {
			ifp->if_flags |= IFF_ALLMULTI;
			ifr.ifr_flags = ifp->if_flags;
			ifr.ifr_flagshigh = ifp->if_flags >> 16;
			ifnet_serialize_all(ifp);
			error = ifp->if_ioctl(ifp, SIOCSIFFLAGS, (caddr_t)&ifr,
					      NULL);
			ifnet_deserialize_all(ifp);
		}
	} else {
		if (ifp->if_amcount > 1) {
			ifp->if_amcount--;
		} else {
			ifp->if_amcount = 0;
			ifp->if_flags &= ~IFF_ALLMULTI;
			ifr.ifr_flags = ifp->if_flags;
			ifr.ifr_flagshigh = ifp->if_flags >> 16;
			ifnet_serialize_all(ifp);
			error = ifp->if_ioctl(ifp, SIOCSIFFLAGS, (caddr_t)&ifr,
					      NULL);
			ifnet_deserialize_all(ifp);
		}
	}

	crit_exit();

	if (error == 0)
		rt_ifmsg(ifp);
	return error;
}

/*
 * Add a multicast listenership to the interface in question.
 * The link layer provides a routine which converts
 */
int
if_addmulti(
	struct ifnet *ifp,	/* interface to manipulate */
	struct sockaddr *sa,	/* address to add */
	struct ifmultiaddr **retifma)
{
	struct sockaddr *llsa, *dupsa;
	int error;
	struct ifmultiaddr *ifma;

	/*
	 * If the matching multicast address already exists
	 * then don't add a new one, just add a reference
	 */
	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (sa_equal(sa, ifma->ifma_addr)) {
			ifma->ifma_refcount++;
			if (retifma)
				*retifma = ifma;
			return 0;
		}
	}

	/*
	 * Give the link layer a chance to accept/reject it, and also
	 * find out which AF_LINK address this maps to, if it isn't one
	 * already.
	 */
	if (ifp->if_resolvemulti) {
		ifnet_serialize_all(ifp);
		error = ifp->if_resolvemulti(ifp, &llsa, sa);
		ifnet_deserialize_all(ifp);
		if (error) 
			return error;
	} else {
		llsa = 0;
	}

	MALLOC(ifma, struct ifmultiaddr *, sizeof *ifma, M_IFMADDR, M_WAITOK);
	MALLOC(dupsa, struct sockaddr *, sa->sa_len, M_IFMADDR, M_WAITOK);
	bcopy(sa, dupsa, sa->sa_len);

	ifma->ifma_addr = dupsa;
	ifma->ifma_lladdr = llsa;
	ifma->ifma_ifp = ifp;
	ifma->ifma_refcount = 1;
	ifma->ifma_protospec = 0;
	rt_newmaddrmsg(RTM_NEWMADDR, ifma);

	/*
	 * Some network interfaces can scan the address list at
	 * interrupt time; lock them out.
	 */
	crit_enter();
	TAILQ_INSERT_HEAD(&ifp->if_multiaddrs, ifma, ifma_link);
	crit_exit();
	if (retifma)
		*retifma = ifma;

	if (llsa != 0) {
		TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			if (sa_equal(ifma->ifma_addr, llsa))
				break;
		}
		if (ifma) {
			ifma->ifma_refcount++;
		} else {
			MALLOC(ifma, struct ifmultiaddr *, sizeof *ifma,
			       M_IFMADDR, M_WAITOK);
			MALLOC(dupsa, struct sockaddr *, llsa->sa_len,
			       M_IFMADDR, M_WAITOK);
			bcopy(llsa, dupsa, llsa->sa_len);
			ifma->ifma_addr = dupsa;
			ifma->ifma_ifp = ifp;
			ifma->ifma_refcount = 1;
			crit_enter();
			TAILQ_INSERT_HEAD(&ifp->if_multiaddrs, ifma, ifma_link);
			crit_exit();
		}
	}
	/*
	 * We are certain we have added something, so call down to the
	 * interface to let them know about it.
	 */
	crit_enter();
	ifnet_serialize_all(ifp);
	if (ifp->if_ioctl)
		ifp->if_ioctl(ifp, SIOCADDMULTI, 0, NULL);
	ifnet_deserialize_all(ifp);
	crit_exit();

	return 0;
}

/*
 * Remove a reference to a multicast address on this interface.  Yell
 * if the request does not match an existing membership.
 */
int
if_delmulti(struct ifnet *ifp, struct sockaddr *sa)
{
	struct ifmultiaddr *ifma;

	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link)
		if (sa_equal(sa, ifma->ifma_addr))
			break;
	if (ifma == 0)
		return ENOENT;

	if (ifma->ifma_refcount > 1) {
		ifma->ifma_refcount--;
		return 0;
	}

	rt_newmaddrmsg(RTM_DELMADDR, ifma);
	sa = ifma->ifma_lladdr;
	crit_enter();
	TAILQ_REMOVE(&ifp->if_multiaddrs, ifma, ifma_link);
	/*
	 * Make sure the interface driver is notified
	 * in the case of a link layer mcast group being left.
	 */
	if (ifma->ifma_addr->sa_family == AF_LINK && sa == 0) {
		ifnet_serialize_all(ifp);
		ifp->if_ioctl(ifp, SIOCDELMULTI, 0, NULL);
		ifnet_deserialize_all(ifp);
	}
	crit_exit();
	kfree(ifma->ifma_addr, M_IFMADDR);
	kfree(ifma, M_IFMADDR);
	if (sa == 0)
		return 0;

	/*
	 * Now look for the link-layer address which corresponds to
	 * this network address.  It had been squirreled away in
	 * ifma->ifma_lladdr for this purpose (so we don't have
	 * to call ifp->if_resolvemulti() again), and we saved that
	 * value in sa above.  If some nasty deleted the
	 * link-layer address out from underneath us, we can deal because
	 * the address we stored was is not the same as the one which was
	 * in the record for the link-layer address.  (So we don't complain
	 * in that case.)
	 */
	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link)
		if (sa_equal(sa, ifma->ifma_addr))
			break;
	if (ifma == 0)
		return 0;

	if (ifma->ifma_refcount > 1) {
		ifma->ifma_refcount--;
		return 0;
	}

	crit_enter();
	ifnet_serialize_all(ifp);
	TAILQ_REMOVE(&ifp->if_multiaddrs, ifma, ifma_link);
	ifp->if_ioctl(ifp, SIOCDELMULTI, 0, NULL);
	ifnet_deserialize_all(ifp);
	crit_exit();
	kfree(ifma->ifma_addr, M_IFMADDR);
	kfree(sa, M_IFMADDR);
	kfree(ifma, M_IFMADDR);

	return 0;
}

/*
 * Delete all multicast group membership for an interface.
 * Should be used to quickly flush all multicast filters.
 */
void
if_delallmulti(struct ifnet *ifp)
{
	struct ifmultiaddr *ifma;
	struct ifmultiaddr *next;

	TAILQ_FOREACH_MUTABLE(ifma, &ifp->if_multiaddrs, ifma_link, next)
		if_delmulti(ifp, ifma->ifma_addr);
}


/*
 * Set the link layer address on an interface.
 *
 * At this time we only support certain types of interfaces,
 * and we don't allow the length of the address to change.
 */
int
if_setlladdr(struct ifnet *ifp, const u_char *lladdr, int len)
{
	struct sockaddr_dl *sdl;
	struct ifreq ifr;

	sdl = IF_LLSOCKADDR(ifp);
	if (sdl == NULL)
		return (EINVAL);
	if (len != sdl->sdl_alen)	/* don't allow length to change */
		return (EINVAL);
	switch (ifp->if_type) {
	case IFT_ETHER:			/* these types use struct arpcom */
	case IFT_XETHER:
	case IFT_L2VLAN:
		bcopy(lladdr, ((struct arpcom *)ifp->if_softc)->ac_enaddr, len);
		bcopy(lladdr, LLADDR(sdl), len);
		break;
	default:
		return (ENODEV);
	}
	/*
	 * If the interface is already up, we need
	 * to re-init it in order to reprogram its
	 * address filter.
	 */
	ifnet_serialize_all(ifp);
	if ((ifp->if_flags & IFF_UP) != 0) {
		struct ifaddr_container *ifac;

		ifp->if_flags &= ~IFF_UP;
		ifr.ifr_flags = ifp->if_flags;
		ifr.ifr_flagshigh = ifp->if_flags >> 16;
		ifp->if_ioctl(ifp, SIOCSIFFLAGS, (caddr_t)&ifr,
			      NULL);
		ifp->if_flags |= IFF_UP;
		ifr.ifr_flags = ifp->if_flags;
		ifr.ifr_flagshigh = ifp->if_flags >> 16;
		ifp->if_ioctl(ifp, SIOCSIFFLAGS, (caddr_t)&ifr,
				 NULL);
#ifdef INET
		/*
		 * Also send gratuitous ARPs to notify other nodes about
		 * the address change.
		 */
		TAILQ_FOREACH(ifac, &ifp->if_addrheads[mycpuid], ifa_link) {
			struct ifaddr *ifa = ifac->ifa;

			if (ifa->ifa_addr != NULL &&
			    ifa->ifa_addr->sa_family == AF_INET)
				arp_ifinit(ifp, ifa);
		}
#endif
	}
	ifnet_deserialize_all(ifp);
	return (0);
}

struct ifmultiaddr *
ifmaof_ifpforaddr(struct sockaddr *sa, struct ifnet *ifp)
{
	struct ifmultiaddr *ifma;

	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link)
		if (sa_equal(ifma->ifma_addr, sa))
			break;

	return ifma;
}

/*
 * This function locates the first real ethernet MAC from a network
 * card and loads it into node, returning 0 on success or ENOENT if
 * no suitable interfaces were found.  It is used by the uuid code to
 * generate a unique 6-byte number.
 */
int
if_getanyethermac(uint16_t *node, int minlen)
{
	struct ifnet *ifp;
	struct sockaddr_dl *sdl;

	TAILQ_FOREACH(ifp, &ifnet, if_link) {
		if (ifp->if_type != IFT_ETHER)
			continue;
		sdl = IF_LLSOCKADDR(ifp);
		if (sdl->sdl_alen < minlen)
			continue;
		bcopy(((struct arpcom *)ifp->if_softc)->ac_enaddr, node,
		      minlen);
		return(0);
	}
	return (ENOENT);
}

/*
 * The name argument must be a pointer to storage which will last as
 * long as the interface does.  For physical devices, the result of
 * device_get_name(dev) is a good choice and for pseudo-devices a
 * static string works well.
 */
void
if_initname(struct ifnet *ifp, const char *name, int unit)
{
	ifp->if_dname = name;
	ifp->if_dunit = unit;
	if (unit != IF_DUNIT_NONE)
		ksnprintf(ifp->if_xname, IFNAMSIZ, "%s%d", name, unit);
	else
		strlcpy(ifp->if_xname, name, IFNAMSIZ);
}

int
if_printf(struct ifnet *ifp, const char *fmt, ...)
{
	__va_list ap;
	int retval;

	retval = kprintf("%s: ", ifp->if_xname);
	__va_start(ap, fmt);
	retval += kvprintf(fmt, ap);
	__va_end(ap);
	return (retval);
}

struct ifnet *
if_alloc(uint8_t type)
{
        struct ifnet *ifp;
	size_t size;

	/*
	 * XXX temporary hack until arpcom is setup in if_l2com
	 */
	if (type == IFT_ETHER)
		size = sizeof(struct arpcom);
	else
		size = sizeof(struct ifnet);

	ifp = kmalloc(size, M_IFNET, M_WAITOK|M_ZERO);

	ifp->if_type = type;

	if (if_com_alloc[type] != NULL) {
		ifp->if_l2com = if_com_alloc[type](type, ifp);
		if (ifp->if_l2com == NULL) {
			kfree(ifp, M_IFNET);
			return (NULL);
		}
	}
	return (ifp);
}

void
if_free(struct ifnet *ifp)
{
	kfree(ifp, M_IFNET);
}

void
ifq_set_classic(struct ifaltq *ifq)
{
	ifq->altq_enqueue = ifq_classic_enqueue;
	ifq->altq_dequeue = ifq_classic_dequeue;
	ifq->altq_request = ifq_classic_request;
}

int
ifq_classic_enqueue(struct ifaltq *ifq, struct mbuf *m,
		    struct altq_pktattr *pa __unused)
{
	logifq(enqueue, ifq);
	if (IF_QFULL(ifq)) {
		m_freem(m);
		return(ENOBUFS);
	} else {
		IF_ENQUEUE(ifq, m);
		return(0);
	}	
}

struct mbuf *
ifq_classic_dequeue(struct ifaltq *ifq, struct mbuf *mpolled, int op)
{
	struct mbuf *m;

	switch (op) {
	case ALTDQ_POLL:
		IF_POLL(ifq, m);
		break;
	case ALTDQ_REMOVE:
		logifq(dequeue, ifq);
		IF_DEQUEUE(ifq, m);
		break;
	default:
		panic("unsupported ALTQ dequeue op: %d", op);
	}
	KKASSERT(mpolled == NULL || mpolled == m);
	return(m);
}

int
ifq_classic_request(struct ifaltq *ifq, int req, void *arg)
{
	switch (req) {
	case ALTRQ_PURGE:
		IF_DRAIN(ifq);
		break;
	default:
		panic("unsupported ALTQ request: %d", req);
	}
	return(0);
}

int
ifq_dispatch(struct ifnet *ifp, struct mbuf *m, struct altq_pktattr *pa)
{
	struct ifaltq *ifq = &ifp->if_snd;
	int running = 0, error, start = 0;

	ASSERT_IFNET_NOT_SERIALIZED_TX(ifp);

	ALTQ_LOCK(ifq);
	error = ifq_enqueue_locked(ifq, m, pa);
	if (error) {
		ALTQ_UNLOCK(ifq);
		return error;
	}
	if (!ifq->altq_started) {
		/*
		 * Hold the interlock of ifnet.if_start
		 */
		ifq->altq_started = 1;
		start = 1;
	}
	ALTQ_UNLOCK(ifq);

	ifp->if_obytes += m->m_pkthdr.len;
	if (m->m_flags & M_MCAST)
		ifp->if_omcasts++;

	if (!start) {
		logifstart(avoid, ifp);
		return 0;
	}

	if (ifq_dispatch_schedonly) {
		/*
		 * Always schedule ifnet.if_start on ifnet's CPU,
		 * short circuit the rest of this function.
		 */
		logifstart(sched, ifp);
		if_start_schedule(ifp);
		return 0;
	}

	/*
	 * Try to do direct ifnet.if_start first, if there is
	 * contention on ifnet's serializer, ifnet.if_start will
	 * be scheduled on ifnet's CPU.
	 */
	if (!ifnet_tryserialize_tx(ifp)) {
		/*
		 * ifnet serializer contention happened,
		 * ifnet.if_start is scheduled on ifnet's
		 * CPU, and we keep going.
		 */
		logifstart(contend_sched, ifp);
		if_start_schedule(ifp);
		return 0;
	}

	if ((ifp->if_flags & IFF_OACTIVE) == 0) {
		logifstart(run, ifp);
		ifp->if_start(ifp);
		if ((ifp->if_flags &
		     (IFF_OACTIVE | IFF_RUNNING)) == IFF_RUNNING)
			running = 1;
	}

	ifnet_deserialize_tx(ifp);

	if (ifq_dispatch_schednochk || if_start_need_schedule(ifq, running)) {
		/*
		 * More data need to be transmitted, ifnet.if_start is
		 * scheduled on ifnet's CPU, and we keep going.
		 * NOTE: ifnet.if_start interlock is not released.
		 */
		logifstart(sched, ifp);
		if_start_schedule(ifp);
	}
	return 0;
}

void *
ifa_create(int size, int flags)
{
	struct ifaddr *ifa;
	int i;

	KASSERT(size >= sizeof(*ifa), ("ifaddr size too small\n"));

	ifa = kmalloc(size, M_IFADDR, flags | M_ZERO);
	if (ifa == NULL)
		return NULL;

	ifa->ifa_containers = kmalloc(ncpus * sizeof(struct ifaddr_container),
				      M_IFADDR, M_WAITOK | M_ZERO);
	ifa->ifa_ncnt = ncpus;
	for (i = 0; i < ncpus; ++i) {
		struct ifaddr_container *ifac = &ifa->ifa_containers[i];

		ifac->ifa_magic = IFA_CONTAINER_MAGIC;
		ifac->ifa = ifa;
		ifac->ifa_refcnt = 1;
	}
#ifdef IFADDR_DEBUG
	kprintf("alloc ifa %p %d\n", ifa, size);
#endif
	return ifa;
}

void
ifac_free(struct ifaddr_container *ifac, int cpu_id)
{
	struct ifaddr *ifa = ifac->ifa;

	KKASSERT(ifac->ifa_magic == IFA_CONTAINER_MAGIC);
	KKASSERT(ifac->ifa_refcnt == 0);
	KASSERT(ifac->ifa_listmask == 0,
		("ifa is still on %#x lists\n", ifac->ifa_listmask));

	ifac->ifa_magic = IFA_CONTAINER_DEAD;

#ifdef IFADDR_DEBUG_VERBOSE
	kprintf("try free ifa %p cpu_id %d\n", ifac->ifa, cpu_id);
#endif

	KASSERT(ifa->ifa_ncnt > 0 && ifa->ifa_ncnt <= ncpus,
		("invalid # of ifac, %d\n", ifa->ifa_ncnt));
	if (atomic_fetchadd_int(&ifa->ifa_ncnt, -1) == 1) {
#ifdef IFADDR_DEBUG
		kprintf("free ifa %p\n", ifa);
#endif
		kfree(ifa->ifa_containers, M_IFADDR);
		kfree(ifa, M_IFADDR);
	}
}

static void
ifa_iflink_dispatch(netmsg_t nmsg)
{
	struct netmsg_ifaddr *msg = (struct netmsg_ifaddr *)nmsg;
	struct ifaddr *ifa = msg->ifa;
	struct ifnet *ifp = msg->ifp;
	int cpu = mycpuid;
	struct ifaddr_container *ifac;

	crit_enter();

	ifac = &ifa->ifa_containers[cpu];
	ASSERT_IFAC_VALID(ifac);
	KASSERT((ifac->ifa_listmask & IFA_LIST_IFADDRHEAD) == 0,
		("ifaddr is on if_addrheads\n"));

	ifac->ifa_listmask |= IFA_LIST_IFADDRHEAD;
	if (msg->tail)
		TAILQ_INSERT_TAIL(&ifp->if_addrheads[cpu], ifac, ifa_link);
	else
		TAILQ_INSERT_HEAD(&ifp->if_addrheads[cpu], ifac, ifa_link);

	crit_exit();

	ifa_forwardmsg(&nmsg->lmsg, cpu + 1);
}

void
ifa_iflink(struct ifaddr *ifa, struct ifnet *ifp, int tail)
{
	struct netmsg_ifaddr msg;

	netmsg_init(&msg.base, NULL, &curthread->td_msgport,
		    0, ifa_iflink_dispatch);
	msg.ifa = ifa;
	msg.ifp = ifp;
	msg.tail = tail;

	ifa_domsg(&msg.base.lmsg, 0);
}

static void
ifa_ifunlink_dispatch(netmsg_t nmsg)
{
	struct netmsg_ifaddr *msg = (struct netmsg_ifaddr *)nmsg;
	struct ifaddr *ifa = msg->ifa;
	struct ifnet *ifp = msg->ifp;
	int cpu = mycpuid;
	struct ifaddr_container *ifac;

	crit_enter();

	ifac = &ifa->ifa_containers[cpu];
	ASSERT_IFAC_VALID(ifac);
	KASSERT(ifac->ifa_listmask & IFA_LIST_IFADDRHEAD,
		("ifaddr is not on if_addrhead\n"));

	TAILQ_REMOVE(&ifp->if_addrheads[cpu], ifac, ifa_link);
	ifac->ifa_listmask &= ~IFA_LIST_IFADDRHEAD;

	crit_exit();

	ifa_forwardmsg(&nmsg->lmsg, cpu + 1);
}

void
ifa_ifunlink(struct ifaddr *ifa, struct ifnet *ifp)
{
	struct netmsg_ifaddr msg;

	netmsg_init(&msg.base, NULL, &curthread->td_msgport,
		    0, ifa_ifunlink_dispatch);
	msg.ifa = ifa;
	msg.ifp = ifp;

	ifa_domsg(&msg.base.lmsg, 0);
}

static void
ifa_destroy_dispatch(netmsg_t nmsg)
{
	struct netmsg_ifaddr *msg = (struct netmsg_ifaddr *)nmsg;

	IFAFREE(msg->ifa);
	ifa_forwardmsg(&nmsg->lmsg, mycpuid + 1);
}

void
ifa_destroy(struct ifaddr *ifa)
{
	struct netmsg_ifaddr msg;

	netmsg_init(&msg.base, NULL, &curthread->td_msgport,
		    0, ifa_destroy_dispatch);
	msg.ifa = ifa;

	ifa_domsg(&msg.base.lmsg, 0);
}

struct lwkt_port *
ifnet_portfn(int cpu)
{
	return &ifnet_threads[cpu].td_msgport;
}

void
ifnet_forwardmsg(struct lwkt_msg *lmsg, int next_cpu)
{
	KKASSERT(next_cpu > mycpuid && next_cpu <= ncpus);

	if (next_cpu < ncpus)
		lwkt_forwardmsg(ifnet_portfn(next_cpu), lmsg);
	else
		lwkt_replymsg(lmsg, 0);
}

int
ifnet_domsg(struct lwkt_msg *lmsg, int cpu)
{
	KKASSERT(cpu < ncpus);
	return lwkt_domsg(ifnet_portfn(cpu), lmsg, 0);
}

void
ifnet_sendmsg(struct lwkt_msg *lmsg, int cpu)
{
	KKASSERT(cpu < ncpus);
	lwkt_sendmsg(ifnet_portfn(cpu), lmsg);
}

/*
 * Generic netmsg service loop.  Some protocols may roll their own but all
 * must do the basic command dispatch function call done here.
 */
static void
ifnet_service_loop(void *arg __unused)
{
	netmsg_t msg;

	while ((msg = lwkt_waitport(&curthread->td_msgport, 0))) {
		KASSERT(msg->base.nm_dispatch, ("ifnet_service: badmsg"));
		msg->base.nm_dispatch(msg);
	}
}

static void
ifnetinit(void *dummy __unused)
{
	int i;

	for (i = 0; i < ncpus; ++i) {
		struct thread *thr = &ifnet_threads[i];

		lwkt_create(ifnet_service_loop, NULL, NULL,
			    thr, TDF_STOPREQ, i, "ifnet %d", i);
		netmsg_service_port_init(&thr->td_msgport);
		lwkt_schedule(thr);
	}
}

struct ifnet *
ifnet_byindex(unsigned short idx)
{
	if (idx > if_index)
		return NULL;
	return ifindex2ifnet[idx];
}

struct ifaddr *
ifaddr_byindex(unsigned short idx)
{
	struct ifnet *ifp;

	ifp = ifnet_byindex(idx);
	if (!ifp)
		return NULL;
	return TAILQ_FIRST(&ifp->if_addrheads[mycpuid])->ifa;
}

void
if_register_com_alloc(u_char type,
    if_com_alloc_t *a, if_com_free_t *f)
{

        KASSERT(if_com_alloc[type] == NULL,
            ("if_register_com_alloc: %d already registered", type));
        KASSERT(if_com_free[type] == NULL,
            ("if_register_com_alloc: %d free already registered", type));

        if_com_alloc[type] = a;
        if_com_free[type] = f;
}

void
if_deregister_com_alloc(u_char type)
{

        KASSERT(if_com_alloc[type] != NULL,
            ("if_deregister_com_alloc: %d not registered", type));
        KASSERT(if_com_free[type] != NULL,
            ("if_deregister_com_alloc: %d free not registered", type));
        if_com_alloc[type] = NULL;
        if_com_free[type] = NULL;
}
