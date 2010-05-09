/*	$FreeBSD: src/sys/contrib/pf/net/if_pfsync.c,v 1.11 2004/08/14 15:32:40 dwmalone Exp $	*/
/*	$OpenBSD: if_pfsync.c,v 1.26 2004/03/28 18:14:20 mcbride Exp $	*/
/*	$DragonFly: src/sys/net/pf/if_pfsync.c,v 1.8 2008/04/12 17:39:41 dillon Exp $ */

/*
 * Copyright (c) 2004 The DragonFly Project.  All rights reserved.
 *
 * Copyright (c) 2002 Michael Shalayeff
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR HIS RELATIVES BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF MIND, USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sockio.h>
#include <sys/thread2.h>
#include <vm/vm_zone.h>

#include <machine/inttypes.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/bpf.h>

#ifdef	INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#endif

#ifdef INET6
#ifndef INET
#include <netinet/in.h>
#endif
#include <netinet6/nd6.h>
#endif /* INET6 */

#include <net/pf/pfvar.h>
#include <net/pf/if_pfsync.h>

#define	PFSYNCNAME	"pfsync"

#define PFSYNC_MINMTU	\
    (sizeof(struct pfsync_header) + sizeof(struct pf_state))

#ifdef PFSYNCDEBUG
#define DPRINTF(x)    do { if (pfsyncdebug) kprintf x ; } while (0)
int pfsyncdebug;
#else
#define DPRINTF(x)
#endif

int			pfsync_sync_ok;
struct pfsyncstats	pfsyncstats;

static void	pfsync_clone_destroy(struct ifnet *);
static int	pfsync_clone_create(struct if_clone *, int, caddr_t);
void	pfsync_setmtu(struct pfsync_softc *, int);
int	pfsync_insert_net_state(struct pfsync_state *);
int	pfsyncoutput(struct ifnet *, struct mbuf *, struct sockaddr *,
	    struct rtentry *);
int	pfsyncioctl(struct ifnet *, u_long, caddr_t, struct ucred *);
void	pfsyncstart(struct ifnet *);

struct mbuf *pfsync_get_mbuf(struct pfsync_softc *, u_int8_t, void **);
int	pfsync_request_update(struct pfsync_state_upd *, struct in_addr *);
int	pfsync_sendout(struct pfsync_softc *);
void	pfsync_timeout(void *);
void	pfsync_send_bus(struct pfsync_softc *, u_int8_t);
void	pfsync_bulk_update(void *);
void	pfsync_bulkfail(void *);

static MALLOC_DEFINE(M_PFSYNC, PFSYNCNAME, "Packet Filter State Sync. Interface");
static LIST_HEAD(pfsync_list, pfsync_softc) pfsync_list;
struct if_clone pfsync_cloner = IF_CLONE_INITIALIZER("pfsync", pfsync_clone_create,
    pfsync_clone_destroy, 1, 1);

static void
pfsync_clone_destroy(struct ifnet *ifp)
{
	struct pfsync_softc *sc;

	sc = ifp->if_softc;
	callout_stop(&sc->sc_tmo);
	callout_stop(&sc->sc_bulk_tmo);
	callout_stop(&sc->sc_bulkfail_tmo);

	bpfdetach(ifp);
	if_detach(ifp);
	LIST_REMOVE(sc, sc_next);
	kfree(sc, M_PFSYNC);
}

static int
pfsync_clone_create(struct if_clone *ifc, int unit, caddr_t param __unused)
{
	struct pfsync_softc *sc;
	struct ifnet *ifp;

	MALLOC(sc, struct pfsync_softc *, sizeof(*sc), M_PFSYNC,
	    M_WAITOK|M_ZERO);

	pfsync_sync_ok = 1;
	sc->sc_mbuf = NULL;
	sc->sc_mbuf_net = NULL;
	sc->sc_statep.s = NULL;
	sc->sc_statep_net.s = NULL;
	sc->sc_maxupdates = 128;
	sc->sc_sendaddr.s_addr = htonl(INADDR_PFSYNC_GROUP);
	sc->sc_ureq_received = 0;
	sc->sc_ureq_sent = 0;

	ifp = &sc->sc_if;
	if_initname(ifp, ifc->ifc_name, unit);
	ifp->if_ioctl = pfsyncioctl;
	ifp->if_output = pfsyncoutput;
	ifp->if_start = pfsyncstart;
	ifp->if_type = IFT_PFSYNC;
	ifp->if_snd.ifq_maxlen = ifqmaxlen;
	ifp->if_hdrlen = PFSYNC_HDRLEN;
	ifp->if_baudrate = IF_Mbps(100);
	ifp->if_softc = sc;
	pfsync_setmtu(sc, MCLBYTES);
	callout_init(&sc->sc_tmo);
	callout_init(&sc->sc_bulk_tmo);
	callout_init(&sc->sc_bulkfail_tmo);
	if_attach(&sc->sc_if, NULL);

	LIST_INSERT_HEAD(&pfsync_list, sc, sc_next);
	bpfattach(&sc->sc_if, DLT_PFSYNC, PFSYNC_HDRLEN);

	return (0);
}

/*
 * Start output on the pfsync interface.
 */
void
pfsyncstart(struct ifnet *ifp)
{
	crit_enter();
	IF_DROP(&ifp->if_snd);
	IF_DRAIN(&ifp->if_snd);
	crit_exit();
}

int
pfsync_insert_net_state(struct pfsync_state *sp)
{
	struct pf_state	*st = NULL;
	struct pf_rule *r = NULL;
	struct pfi_kif	*kif;

	if (sp->creatorid == 0 && pf_status.debug >= PF_DEBUG_MISC) {
		kprintf("pfsync_insert_net_state: invalid creator id:"
		    " %08" PRIx32 "\n", ntohl(sp->creatorid));
		return (EINVAL);
	}

	kif = pfi_lookup_create(sp->ifname);
	if (kif == NULL) {
		if (pf_status.debug >= PF_DEBUG_MISC)
			kprintf("pfsync_insert_net_state: "
			    "unknown interface: %s\n", sp->ifname);
		/* skip this state */
		return (0);
	}

	/*
	 * Just use the default rule until we have infrastructure to find the
	 * best matching rule.
	 */
	r = &pf_default_rule;

	if (!r->max_states || r->states < r->max_states)
		st = pool_get(&pf_state_pl, PR_NOWAIT);
	if (st == NULL) {
		pfi_maybe_destroy(kif);
		return (ENOMEM);
	}
	bzero(st, sizeof(*st));

	st->rule.ptr = r;
	/* XXX get pointers to nat_rule and anchor */

	/* fill in the rest of the state entry */
	pf_state_host_ntoh(&sp->lan, &st->lan);
	pf_state_host_ntoh(&sp->gwy, &st->gwy);
	pf_state_host_ntoh(&sp->ext, &st->ext);

	pf_state_peer_ntoh(&sp->src, &st->src);
	pf_state_peer_ntoh(&sp->dst, &st->dst);

	bcopy(&sp->rt_addr, &st->rt_addr, sizeof(st->rt_addr));
	st->hash = pf_state_hash(st);
	st->creation = ntohl(sp->creation) + time_second;
	st->expire = ntohl(sp->expire) + time_second;

	st->af = sp->af;
	st->proto = sp->proto;
	st->direction = sp->direction;
	st->log = sp->log;
	st->timeout = sp->timeout;
	st->allow_opts = sp->allow_opts;

	bcopy(sp->id, &st->id, sizeof(st->id));
	st->creatorid = sp->creatorid;
	st->sync_flags = sp->sync_flags | PFSTATE_FROMSYNC;


	if (pf_insert_state(kif, st)) {
		pfi_maybe_destroy(kif);
		pool_put(&pf_state_pl, st);
		return (EINVAL);
	}

	return (0);
}

void
pfsync_input(struct mbuf *m, ...)
{
	struct ip *ip = mtod(m, struct ip *);
	struct pfsync_header *ph;
	struct pfsync_softc *sc = LIST_FIRST(&pfsync_list);
	struct pf_state *st, key;
	struct pfsync_state *sp;
	struct pfsync_state_upd *up;
	struct pfsync_state_del *dp;
	struct pfsync_state_clr *cp;
	struct pfsync_state_upd_req *rup;
	struct pfsync_state_bus *bus;
	struct in_addr src;
	struct mbuf *mp;
	int iplen, action, error, i, count, offp;

	pfsyncstats.pfsyncs_ipackets++;

	/* verify that we have a sync interface configured */
	if (!sc->sc_sync_ifp || !pf_status.running)
		goto done;

	/* verify that the packet came in on the right interface */
	if (sc->sc_sync_ifp != m->m_pkthdr.rcvif) {
		pfsyncstats.pfsyncs_badif++;
		goto done;
	}

	/* verify that the IP TTL is 255.  */
	if (ip->ip_ttl != PFSYNC_DFLTTL) {
		pfsyncstats.pfsyncs_badttl++;
		goto done;
	}

	iplen = ip->ip_hl << 2;

	if (m->m_pkthdr.len < iplen + sizeof(*ph)) {
		pfsyncstats.pfsyncs_hdrops++;
		goto done;
	}

	if (iplen + sizeof(*ph) > m->m_len) {
		if ((m = m_pullup(m, iplen + sizeof(*ph))) == NULL) {
			pfsyncstats.pfsyncs_hdrops++;
			goto done;
		}
		ip = mtod(m, struct ip *);
	}
	ph = (struct pfsync_header *)((char *)ip + iplen);

	/* verify the version */
	if (ph->version != PFSYNC_VERSION) {
		pfsyncstats.pfsyncs_badver++;
		goto done;
	}

	action = ph->action;
	count = ph->count;

	/* make sure it's a valid action code */
	if (action >= PFSYNC_ACT_MAX) {
		pfsyncstats.pfsyncs_badact++;
		goto done;
	}

	/* Cheaper to grab this now than having to mess with mbufs later */
	src = ip->ip_src;

	switch (action) {
	case PFSYNC_ACT_CLR: {
		struct pfi_kif	*kif;
		u_int32_t creatorid;
		if ((mp = m_pulldown(m, iplen + sizeof(*ph),
		    sizeof(*cp), &offp)) == NULL) {
			pfsyncstats.pfsyncs_badlen++;
			return;
		}
		cp = (struct pfsync_state_clr *)(mp->m_data + offp);
		creatorid = cp->creatorid;

		crit_enter();
		if (cp->ifname[0] == '\0') {
			RB_FOREACH(st, pf_state_tree_id, &tree_id) {
				if (st->creatorid == creatorid)
					st->timeout = PFTM_PURGE;
			}
		} else {
			kif = pfi_lookup_if(cp->ifname);
			if (kif == NULL) {
				if (pf_status.debug >= PF_DEBUG_MISC)
					kprintf("pfsync_input: PFSYNC_ACT_CLR "
					    "bad interface: %s\n", cp->ifname);
				crit_exit();
				goto done;
			}
			RB_FOREACH(st, pf_state_tree_lan_ext,
			    &kif->pfik_lan_ext) {
				if (st->creatorid == creatorid)
					st->timeout = PFTM_PURGE;
			}
		}
		pf_purge_expired_states();
		crit_exit();

		break;
	}
	case PFSYNC_ACT_INS:
		if ((mp = m_pulldown(m, iplen + sizeof(*ph),
		    count * sizeof(*sp), &offp)) == NULL) {
			pfsyncstats.pfsyncs_badlen++;
			return;
		}

		crit_enter();
		for (i = 0, sp = (struct pfsync_state *)(mp->m_data + offp);
		    i < count; i++, sp++) {
			/* check for invalid values */
			if (sp->timeout >= PFTM_MAX ||
			    sp->src.state > PF_TCPS_PROXY_DST ||
			    sp->dst.state > PF_TCPS_PROXY_DST ||
			    sp->direction > PF_OUT ||
			    (sp->af != AF_INET && sp->af != AF_INET6)) {
				if (pf_status.debug >= PF_DEBUG_MISC)
					kprintf("pfsync_insert: PFSYNC_ACT_INS: "
					    "invalid value\n");
				pfsyncstats.pfsyncs_badstate++;
				continue;
			}

			if ((error = pfsync_insert_net_state(sp))) {
				if (error == ENOMEM) {
					crit_exit();
					goto done;
				}
				continue;
			}
		}
		crit_exit();
		break;
	case PFSYNC_ACT_UPD:
		if ((mp = m_pulldown(m, iplen + sizeof(*ph),
		    count * sizeof(*sp), &offp)) == NULL) {
			pfsyncstats.pfsyncs_badlen++;
			return;
		}

		crit_enter();
		for (i = 0, sp = (struct pfsync_state *)(mp->m_data + offp);
		    i < count; i++, sp++) {
			/* check for invalid values */
			if (sp->timeout >= PFTM_MAX ||
			    sp->src.state > PF_TCPS_PROXY_DST ||
			    sp->dst.state > PF_TCPS_PROXY_DST) {
				if (pf_status.debug >= PF_DEBUG_MISC)
					kprintf("pfsync_insert: PFSYNC_ACT_UPD: "
					    "invalid value\n");
				pfsyncstats.pfsyncs_badstate++;
				continue;
			}

			bcopy(sp->id, &key.id, sizeof(key.id));
			key.creatorid = sp->creatorid;

			st = pf_find_state_byid(&key);
			if (st == NULL) {
				/* insert the update */
				if (pfsync_insert_net_state(sp))
					pfsyncstats.pfsyncs_badstate++;
				continue;
			}
			pf_state_peer_ntoh(&sp->src, &st->src);
			pf_state_peer_ntoh(&sp->dst, &st->dst);
			st->expire = ntohl(sp->expire) + time_second;
			st->timeout = sp->timeout;

		}
		crit_exit();
		break;
	/*
	 * It's not strictly necessary for us to support the "uncompressed"
	 * delete action, but it's relatively simple and maintains consistency.
	 */
	case PFSYNC_ACT_DEL:
		if ((mp = m_pulldown(m, iplen + sizeof(*ph),
		    count * sizeof(*sp), &offp)) == NULL) {
			pfsyncstats.pfsyncs_badlen++;
			return;
		}

		crit_enter();
		for (i = 0, sp = (struct pfsync_state *)(mp->m_data + offp);
		    i < count; i++, sp++) {
			bcopy(sp->id, &key.id, sizeof(key.id));
			key.creatorid = sp->creatorid;

			st = pf_find_state_byid(&key);
			if (st == NULL) {
				pfsyncstats.pfsyncs_badstate++;
				continue;
			}
			/*
			 * XXX
			 * pf_purge_expired_states() is expensive,
			 * we really want to purge the state directly.
			 */
			st->timeout = PFTM_PURGE;
			st->sync_flags |= PFSTATE_FROMSYNC;
		}
		pf_purge_expired_states();
		crit_exit();
		break;
	case PFSYNC_ACT_UPD_C: {
		int update_requested = 0;

		if ((mp = m_pulldown(m, iplen + sizeof(*ph),
		    count * sizeof(*up), &offp)) == NULL) {
			pfsyncstats.pfsyncs_badlen++;
			return;
		}

		crit_enter();
		for (i = 0, up = (struct pfsync_state_upd *)(mp->m_data + offp);
		    i < count; i++, up++) {
			/* check for invalid values */
			if (up->timeout >= PFTM_MAX ||
			    up->src.state > PF_TCPS_PROXY_DST ||
			    up->dst.state > PF_TCPS_PROXY_DST) {
				if (pf_status.debug >= PF_DEBUG_MISC)
					kprintf("pfsync_insert: "
					    "PFSYNC_ACT_UPD_C: "
					    "invalid value\n");
				pfsyncstats.pfsyncs_badstate++;
				continue;
			}

			bcopy(up->id, &key.id, sizeof(key.id));
			key.creatorid = up->creatorid;

			st = pf_find_state_byid(&key);
			if (st == NULL) {
				/* We don't have this state. Ask for it. */
				pfsync_request_update(up, &src);
				update_requested = 1;
				pfsyncstats.pfsyncs_badstate++;
				continue;
			}
			pf_state_peer_ntoh(&up->src, &st->src);
			pf_state_peer_ntoh(&up->dst, &st->dst);
			st->expire = ntohl(up->expire) + time_second;
			st->timeout = up->timeout;
		}
		if (update_requested)
			pfsync_sendout(sc);
		crit_exit();
		break;
	}
	case PFSYNC_ACT_DEL_C:
		if ((mp = m_pulldown(m, iplen + sizeof(*ph),
		    count * sizeof(*dp), &offp)) == NULL) {
			pfsyncstats.pfsyncs_badlen++;
			return;
		}

		crit_enter();
		for (i = 0, dp = (struct pfsync_state_del *)(mp->m_data + offp);
		    i < count; i++, dp++) {
			bcopy(dp->id, &key.id, sizeof(key.id));
			key.creatorid = dp->creatorid;

			st = pf_find_state_byid(&key);
			if (st == NULL) {
				pfsyncstats.pfsyncs_badstate++;
				continue;
			}
			/*
			 * XXX
			 * pf_purge_expired_states() is expensive,
			 * we really want to purge the state directly.
			 */
			st->timeout = PFTM_PURGE;
			st->sync_flags |= PFSTATE_FROMSYNC;
		}
		pf_purge_expired_states();
		crit_exit();
		break;
	case PFSYNC_ACT_INS_F:
	case PFSYNC_ACT_DEL_F:
		/* not implemented */
		break;
	case PFSYNC_ACT_UREQ:
		if ((mp = m_pulldown(m, iplen + sizeof(*ph),
		    count * sizeof(*rup), &offp)) == NULL) {
			pfsyncstats.pfsyncs_badlen++;
			return;
		}

		crit_enter();
		/* XXX send existing. pfsync_pack_state should handle this. */
		if (sc->sc_mbuf != NULL)
			pfsync_sendout(sc);
		for (i = 0,
		    rup = (struct pfsync_state_upd_req *)(mp->m_data + offp);
		    i < count; i++, rup++) {
			bcopy(rup->id, &key.id, sizeof(key.id));
			key.creatorid = rup->creatorid;

			if (key.id == 0 && key.creatorid == 0) {
				sc->sc_ureq_received = mycpu->gd_time_seconds;
				if (pf_status.debug >= PF_DEBUG_MISC)
					kprintf("pfsync: received "
					    "bulk update request\n");
				pfsync_send_bus(sc, PFSYNC_BUS_START);
				callout_reset(&sc->sc_bulk_tmo, 1 * hz,
				    pfsync_bulk_update,
				    LIST_FIRST(&pfsync_list));
			} else {
				st = pf_find_state_byid(&key);
				if (st == NULL) {
					pfsyncstats.pfsyncs_badstate++;
					continue;
				}
				pfsync_pack_state(PFSYNC_ACT_UPD, st, 0);
			}
		}
		if (sc->sc_mbuf != NULL)
			pfsync_sendout(sc);
		crit_exit();
		break;
	case PFSYNC_ACT_BUS:
		/* If we're not waiting for a bulk update, who cares. */
		if (sc->sc_ureq_sent == 0)
			break;

		if ((mp = m_pulldown(m, iplen + sizeof(*ph),
		    sizeof(*bus), &offp)) == NULL) {
			pfsyncstats.pfsyncs_badlen++;
			return;
		}
		bus = (struct pfsync_state_bus *)(mp->m_data + offp);
		switch (bus->status) {
		case PFSYNC_BUS_START:
			callout_reset(&sc->sc_bulkfail_tmo,
			    pf_pool_limits[PF_LIMIT_STATES].limit /
			    (PFSYNC_BULKPACKETS * sc->sc_maxcount), 
			    pfsync_bulkfail, LIST_FIRST(&pfsync_list));
			if (pf_status.debug >= PF_DEBUG_MISC)
				kprintf("pfsync: received bulk "
				    "update start\n");
			break;
		case PFSYNC_BUS_END:
			if (mycpu->gd_time_seconds - ntohl(bus->endtime) >=
			    sc->sc_ureq_sent) {
				/* that's it, we're happy */
				sc->sc_ureq_sent = 0;
				sc->sc_bulk_tries = 0;
				callout_stop(&sc->sc_bulkfail_tmo);
				pfsync_sync_ok = 1;
				if (pf_status.debug >= PF_DEBUG_MISC)
					kprintf("pfsync: received valid "
					    "bulk update end\n");
			} else {
				if (pf_status.debug >= PF_DEBUG_MISC)
					kprintf("pfsync: received invalid "
					    "bulk update end: bad timestamp\n");
			}
			break;
		}
		break;
	}

done:
	if (m)
		m_freem(m);
}

int
pfsyncoutput(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst,
	struct rtentry *rt)
{
	m_freem(m);
	return (0);
}

/* ARGSUSED */
int
pfsyncioctl(struct ifnet *ifp, u_long cmd, caddr_t data, struct ucred *cr)
{
	struct pfsync_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	struct ip_moptions *imo = &sc->sc_imo;
	struct pfsyncreq pfsyncr;
	struct ifnet    *sifp;
	int error;

	switch (cmd) {
	case SIOCSIFADDR:
	case SIOCAIFADDR:
	case SIOCSIFDSTADDR:
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP)
			ifp->if_flags |= IFF_RUNNING;
		else
			ifp->if_flags &= ~IFF_RUNNING;
		break;
	case SIOCSIFMTU:
		if (ifr->ifr_mtu < PFSYNC_MINMTU)
			return (EINVAL);
		if (ifr->ifr_mtu > MCLBYTES)
			ifr->ifr_mtu = MCLBYTES;
		crit_enter();
		if (ifr->ifr_mtu < ifp->if_mtu)
			pfsync_sendout(sc);
		pfsync_setmtu(sc, ifr->ifr_mtu);
		crit_exit();
		break;
	case SIOCGETPFSYNC:
		bzero(&pfsyncr, sizeof(pfsyncr));
		if (sc->sc_sync_ifp)
			strlcpy(pfsyncr.pfsyncr_syncif,
			    sc->sc_sync_ifp->if_xname, IFNAMSIZ);
		pfsyncr.pfsyncr_maxupdates = sc->sc_maxupdates;
		if ((error = copyout(&pfsyncr, ifr->ifr_data, sizeof(pfsyncr))))
			return (error);
		break;
	case SIOCSETPFSYNC:
		if ((error = priv_check_cred(cr, PRIV_ROOT, NULL_CRED_OKAY)) != 0)
			return (error);
		if ((error = copyin(ifr->ifr_data, &pfsyncr, sizeof(pfsyncr))))
			return (error);

		if (pfsyncr.pfsyncr_maxupdates > 255)
			return (EINVAL);
		sc->sc_maxupdates = pfsyncr.pfsyncr_maxupdates;

		if (pfsyncr.pfsyncr_syncif[0] == 0) {
			sc->sc_sync_ifp = NULL;
			if (sc->sc_mbuf_net != NULL) {
				/* Don't keep stale pfsync packets around. */
				crit_enter();
				m_freem(sc->sc_mbuf_net);
				sc->sc_mbuf_net = NULL;
				sc->sc_statep_net.s = NULL;
				crit_exit();
			}
			break;
		}
		if ((sifp = ifunit(pfsyncr.pfsyncr_syncif)) == NULL)
			return (EINVAL);
		else if (sifp == sc->sc_sync_ifp)
			break;

		crit_enter();
		if (sifp->if_mtu < sc->sc_if.if_mtu ||
		    (sc->sc_sync_ifp != NULL &&
		    sifp->if_mtu < sc->sc_sync_ifp->if_mtu) ||
		    sifp->if_mtu < MCLBYTES - sizeof(struct ip))
			pfsync_sendout(sc);
		sc->sc_sync_ifp = sifp;

		pfsync_setmtu(sc, sc->sc_if.if_mtu);

		if (imo->imo_num_memberships > 0) {
			in_delmulti(imo->imo_membership[--imo->imo_num_memberships]);
			imo->imo_multicast_ifp = NULL;
		}

		if (sc->sc_sync_ifp) {
			struct in_addr addr;

			addr.s_addr = htonl(INADDR_PFSYNC_GROUP);
			/* XXX do we only use one group? Also see above */
			if ((imo->imo_membership[0] =
			    in_addmulti(&addr, sc->sc_sync_ifp)) == NULL) {
				crit_exit();
				return (ENOBUFS);
			}
			imo->imo_num_memberships++;
			imo->imo_multicast_ifp = sc->sc_sync_ifp;
			imo->imo_multicast_ttl = PFSYNC_DFLTTL;
			imo->imo_multicast_loop = 0;

			/* Request a full state table update. */
			sc->sc_ureq_sent = mycpu->gd_time_seconds;
			pfsync_sync_ok = 0;
			if (pf_status.debug >= PF_DEBUG_MISC)
				kprintf("pfsync: requesting bulk update\n");
			callout_reset(&sc->sc_bulkfail_tmo, 5 * hz,
			    pfsync_bulkfail, LIST_FIRST(&pfsync_list));
			pfsync_request_update(NULL, NULL);
			pfsync_sendout(sc);
		}
		crit_exit();

		break;

	default:
		return (ENOTTY);
	}

	return (0);
}

void
pfsync_setmtu(struct pfsync_softc *sc, int mtu_req)
{
	int mtu;

	if (sc->sc_sync_ifp && sc->sc_sync_ifp->if_mtu < mtu_req)
		mtu = sc->sc_sync_ifp->if_mtu;
	else
		mtu = mtu_req;

	sc->sc_maxcount = (mtu - sizeof(struct pfsync_header)) /
	    sizeof(struct pfsync_state);
	if (sc->sc_maxcount > 254)
	    sc->sc_maxcount = 254;
	sc->sc_if.if_mtu = sizeof(struct pfsync_header) +
	    sc->sc_maxcount * sizeof(struct pfsync_state);
}

struct mbuf *
pfsync_get_mbuf(struct pfsync_softc *sc, u_int8_t action, void **sp)
{
	struct pfsync_header *h;
	struct mbuf *m;
	int len;

	MGETHDR(m, MB_DONTWAIT, MT_DATA);
	if (m == NULL) {
		sc->sc_if.if_oerrors++;
		return (NULL);
	}

	switch (action) {
	case PFSYNC_ACT_CLR:
		len = sizeof(struct pfsync_header) +
		    sizeof(struct pfsync_state_clr);
		break;
	case PFSYNC_ACT_UPD_C:
		len = (sc->sc_maxcount * sizeof(struct pfsync_state_upd)) +
		    sizeof(struct pfsync_header);
		break;
	case PFSYNC_ACT_DEL_C:
		len = (sc->sc_maxcount * sizeof(struct pfsync_state_del)) +
		    sizeof(struct pfsync_header);
		break;
	case PFSYNC_ACT_UREQ:
		len = (sc->sc_maxcount * sizeof(struct pfsync_state_upd_req)) +
		    sizeof(struct pfsync_header);
		break;
	case PFSYNC_ACT_BUS:
		len = sizeof(struct pfsync_header) +
		    sizeof(struct pfsync_state_bus);
		break;
	default:
		len = (sc->sc_maxcount * sizeof(struct pfsync_state)) +
		    sizeof(struct pfsync_header);
		break;
	}

	if (len > MHLEN) {
		MCLGET(m, MB_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			sc->sc_if.if_oerrors++;
			return (NULL);
		}
		m->m_data += (MCLBYTES - len) &~ (sizeof(long) - 1);
	} else
		MH_ALIGN(m, len);

	m->m_pkthdr.rcvif = NULL;
	m->m_pkthdr.len = m->m_len = sizeof(struct pfsync_header);
	h = mtod(m, struct pfsync_header *);
	h->version = PFSYNC_VERSION;
	h->af = 0;
	h->count = 0;
	h->action = action;

	*sp = (void *)((char *)h + PFSYNC_HDRLEN);
	callout_reset(&sc->sc_tmo, hz, pfsync_timeout,
	    LIST_FIRST(&pfsync_list));
	return (m);
}

int
pfsync_pack_state(u_int8_t action, struct pf_state *st, int compress)
{
	struct ifnet *ifp = &(LIST_FIRST(&pfsync_list))->sc_if;
	struct pfsync_softc *sc = ifp->if_softc;
	struct pfsync_header *h, *h_net;
	struct pfsync_state *sp = NULL;
	struct pfsync_state_upd *up = NULL;
	struct pfsync_state_del *dp = NULL;
	struct pf_rule *r;
	u_long secs;
	int ret = 0;
	u_int8_t i = 255, newaction = 0;

	/*
	 * If a packet falls in the forest and there's nobody around to
	 * hear, does it make a sound?
	 */
	if (ifp->if_bpf == NULL && sc->sc_sync_ifp == NULL) {
		/* Don't leave any stale pfsync packets hanging around. */
		if (sc->sc_mbuf != NULL) {
			m_freem(sc->sc_mbuf);
			sc->sc_mbuf = NULL;
			sc->sc_statep.s = NULL;
		}
		return (0);
	}

	if (action >= PFSYNC_ACT_MAX)
		return (EINVAL);

	crit_enter();
	if (sc->sc_mbuf == NULL) {
		if ((sc->sc_mbuf = pfsync_get_mbuf(sc, action,
		    (void *)&sc->sc_statep.s)) == NULL) {
			crit_exit();
			return (ENOMEM);
		}
		h = mtod(sc->sc_mbuf, struct pfsync_header *);
	} else {
		h = mtod(sc->sc_mbuf, struct pfsync_header *);
		if (h->action != action) {
			pfsync_sendout(sc);
			if ((sc->sc_mbuf = pfsync_get_mbuf(sc, action,
			    (void *)&sc->sc_statep.s)) == NULL) {
				crit_exit();
				return (ENOMEM);
			}
			h = mtod(sc->sc_mbuf, struct pfsync_header *);
		} else {
			/*
			 * If it's an update, look in the packet to see if
			 * we already have an update for the state.
			 */
			if (action == PFSYNC_ACT_UPD && sc->sc_maxupdates) {
				struct pfsync_state *usp =
				    (void *)((char *)h + PFSYNC_HDRLEN);

				for (i = 0; i < h->count; i++) {
					if (!memcmp(usp->id, &st->id,
					    PFSYNC_ID_LEN) &&
					    usp->creatorid == st->creatorid) {
						sp = usp;
						sp->updates++;
						break;
					}
					usp++;
				}
			}
		}
	}

	secs = time_second;

	st->pfsync_time = mycpu->gd_time_seconds;
	TAILQ_REMOVE(&state_updates, st, u.s.entry_updates);
	TAILQ_INSERT_TAIL(&state_updates, st, u.s.entry_updates);

	if (sp == NULL) {
		/* not a "duplicate" update */
		i = 255;
		sp = sc->sc_statep.s++;
		sc->sc_mbuf->m_pkthdr.len =
		    sc->sc_mbuf->m_len += sizeof(struct pfsync_state);
		h->count++;
		bzero(sp, sizeof(*sp));

		bcopy(&st->id, sp->id, sizeof(sp->id));
		sp->creatorid = st->creatorid;

		strlcpy(sp->ifname, st->u.s.kif->pfik_name, sizeof(sp->ifname));
		pf_state_host_hton(&st->lan, &sp->lan);
		pf_state_host_hton(&st->gwy, &sp->gwy);
		pf_state_host_hton(&st->ext, &sp->ext);

		bcopy(&st->rt_addr, &sp->rt_addr, sizeof(sp->rt_addr));

		sp->creation = htonl(secs - st->creation);
		sp->packets[0] = htonl(st->packets[0]);
		sp->packets[1] = htonl(st->packets[1]);
		sp->bytes[0] = htonl(st->bytes[0]);
		sp->bytes[1] = htonl(st->bytes[1]);
		if ((r = st->rule.ptr) == NULL)
			sp->rule = htonl(-1);
		else
			sp->rule = htonl(r->nr);
		if ((r = st->anchor.ptr) == NULL)
			sp->anchor = htonl(-1);
		else
			sp->anchor = htonl(r->nr);
		sp->af = st->af;
		sp->proto = st->proto;
		sp->direction = st->direction;
		sp->log = st->log;
		sp->allow_opts = st->allow_opts;
		sp->timeout = st->timeout;

		sp->sync_flags = st->sync_flags & PFSTATE_NOSYNC;
	}

	pf_state_peer_hton(&st->src, &sp->src);
	pf_state_peer_hton(&st->dst, &sp->dst);

	if (st->expire <= secs)
		sp->expire = htonl(0);
	else
		sp->expire = htonl(st->expire - secs);

	/* do we need to build "compressed" actions for network transfer? */
	if (sc->sc_sync_ifp && compress) {
		switch (action) {
		case PFSYNC_ACT_UPD:
			newaction = PFSYNC_ACT_UPD_C;
			break;
		case PFSYNC_ACT_DEL:
			newaction = PFSYNC_ACT_DEL_C;
			break;
		default:
			/* by default we just send the uncompressed states */
			break;
		}
	}

	if (newaction) {
		if (sc->sc_mbuf_net == NULL) {
			if ((sc->sc_mbuf_net = pfsync_get_mbuf(sc, newaction,
			    (void *)&sc->sc_statep_net.s)) == NULL) {
				crit_exit();
				return (ENOMEM);
			}
		}
		h_net = mtod(sc->sc_mbuf_net, struct pfsync_header *);

		switch (newaction) {
		case PFSYNC_ACT_UPD_C:
			if (i != 255) {
				up = (void *)((char *)h_net +
				    PFSYNC_HDRLEN + (i * sizeof(*up)));
				up->updates++;
			} else {
				h_net->count++;
				sc->sc_mbuf_net->m_pkthdr.len =
				    sc->sc_mbuf_net->m_len += sizeof(*up);
				up = sc->sc_statep_net.u++;

				bzero(up, sizeof(*up));
				bcopy(&st->id, up->id, sizeof(up->id));
				up->creatorid = st->creatorid;
			}
			up->timeout = st->timeout;
			up->expire = sp->expire;
			up->src = sp->src;
			up->dst = sp->dst;
			break;
		case PFSYNC_ACT_DEL_C:
			sc->sc_mbuf_net->m_pkthdr.len =
			    sc->sc_mbuf_net->m_len += sizeof(*dp);
			dp = sc->sc_statep_net.d++;
			h_net->count++;

			bzero(dp, sizeof(*dp));
			bcopy(&st->id, dp->id, sizeof(dp->id));
			dp->creatorid = st->creatorid;
			break;
		}
	}

	if (h->count == sc->sc_maxcount ||
	    (sc->sc_maxupdates && (sp->updates >= sc->sc_maxupdates)))
		ret = pfsync_sendout(sc);

	crit_exit();
	return (ret);
}

/* This must be called in splnet() */
int
pfsync_request_update(struct pfsync_state_upd *up, struct in_addr *src)
{
	struct ifnet *ifp = &(LIST_FIRST(&pfsync_list))->sc_if;
	struct pfsync_header *h;
	struct pfsync_softc *sc = ifp->if_softc;
	struct pfsync_state_upd_req *rup;
	int ret = 0;

	if (sc->sc_mbuf == NULL) {
		if ((sc->sc_mbuf = pfsync_get_mbuf(sc, PFSYNC_ACT_UREQ,
		    (void *)&sc->sc_statep.s)) == NULL) {
			return (ENOMEM);
		}
		h = mtod(sc->sc_mbuf, struct pfsync_header *);
	} else {
		h = mtod(sc->sc_mbuf, struct pfsync_header *);
		if (h->action != PFSYNC_ACT_UREQ) {
			pfsync_sendout(sc);
			if ((sc->sc_mbuf = pfsync_get_mbuf(sc, PFSYNC_ACT_UREQ,
			    (void *)&sc->sc_statep.s)) == NULL) {
				return (ENOMEM);
			}
			h = mtod(sc->sc_mbuf, struct pfsync_header *);
		}
	}

	if (src != NULL)
		sc->sc_sendaddr = *src;
	sc->sc_mbuf->m_pkthdr.len = sc->sc_mbuf->m_len += sizeof(*rup);
	h->count++;
	rup = sc->sc_statep.r++;
	bzero(rup, sizeof(*rup));
	if (up != NULL) {
		bcopy(up->id, rup->id, sizeof(rup->id));
		rup->creatorid = up->creatorid;
	}

	if (h->count == sc->sc_maxcount)
		ret = pfsync_sendout(sc);

	return (ret);
}

int
pfsync_clear_states(u_int32_t creatorid, char *ifname)
{
	struct ifnet *ifp = &(LIST_FIRST(&pfsync_list))->sc_if;
	struct pfsync_softc *sc = ifp->if_softc;
	struct pfsync_state_clr *cp;
	int ret;

	crit_enter();
	if (sc->sc_mbuf != NULL)
		pfsync_sendout(sc);
	if ((sc->sc_mbuf = pfsync_get_mbuf(sc, PFSYNC_ACT_CLR,
	    (void *)&sc->sc_statep.c)) == NULL) {
		crit_exit();
		return (ENOMEM);
	}
	sc->sc_mbuf->m_pkthdr.len = sc->sc_mbuf->m_len += sizeof(*cp);
	cp = sc->sc_statep.c;
	cp->creatorid = creatorid;
	if (ifname != NULL)
		strlcpy(cp->ifname, ifname, IFNAMSIZ);

	ret = (pfsync_sendout(sc));
	crit_exit();
	return (ret);
}

void
pfsync_timeout(void *v)
{
	struct pfsync_softc *sc = v;

	crit_enter();
	pfsync_sendout(sc);
	crit_exit();
}

void
pfsync_send_bus(struct pfsync_softc *sc, u_int8_t status)
{
	struct pfsync_state_bus *bus;

	if (sc->sc_mbuf != NULL)
		pfsync_sendout(sc);

	if (pfsync_sync_ok &&
	    (sc->sc_mbuf = pfsync_get_mbuf(sc, PFSYNC_ACT_BUS,
	    (void *)&sc->sc_statep.b)) != NULL) {
		sc->sc_mbuf->m_pkthdr.len = sc->sc_mbuf->m_len += sizeof(*bus);
		bus = sc->sc_statep.b;
		bus->creatorid = pf_status.hostid;
		bus->status = status;
		bus->endtime = htonl(mycpu->gd_time_seconds - sc->sc_ureq_received);
		pfsync_sendout(sc);
	}
}

void
pfsync_bulk_update(void *v)
{
	struct pfsync_softc *sc = v;
	int i = 0;
	struct pf_state *state;

	crit_enter();
	if (sc->sc_mbuf != NULL)
		pfsync_sendout(sc);

	/*
	 * Grab at most PFSYNC_BULKPACKETS worth of states which have not
	 * been sent since the latest request was made.
	 */
	while ((state = TAILQ_FIRST(&state_updates)) != NULL &&
	    ++i < (sc->sc_maxcount * PFSYNC_BULKPACKETS)) {
		if (state->pfsync_time > sc->sc_ureq_received) {
			/* we're done */
			pfsync_send_bus(sc, PFSYNC_BUS_END);
			sc->sc_ureq_received = 0;
			callout_stop(&sc->sc_bulk_tmo);
			if (pf_status.debug >= PF_DEBUG_MISC)
				kprintf("pfsync: bulk update complete\n");
			break;
		} else {
			/* send an update and move to end of list */
			if (!state->sync_flags)
				pfsync_pack_state(PFSYNC_ACT_UPD, state, 0);
			state->pfsync_time = mycpu->gd_time_seconds;
			TAILQ_REMOVE(&state_updates, state, u.s.entry_updates);
			TAILQ_INSERT_TAIL(&state_updates, state,
			    u.s.entry_updates);

			/* look again for more in a bit */
			callout_reset(&sc->sc_bulk_tmo, 1, pfsync_timeout,
			    LIST_FIRST(&pfsync_list));
		}
	}
	if (sc->sc_mbuf != NULL)
		pfsync_sendout(sc);
	crit_exit();
}

void
pfsync_bulkfail(void *v)
{
	struct pfsync_softc *sc = v;

	if (sc->sc_bulk_tries++ < PFSYNC_MAX_BULKTRIES) {
		/* Try again in a bit */
		callout_reset(&sc->sc_bulkfail_tmo, 5 * hz, pfsync_bulkfail,
		    LIST_FIRST(&pfsync_list));
		pfsync_request_update(NULL, NULL);
		pfsync_sendout(sc);
	} else {
		/* Pretend like the transfer was ok */
		sc->sc_ureq_sent = 0;
		sc->sc_bulk_tries = 0;
		pfsync_sync_ok = 1;
		if (pf_status.debug >= PF_DEBUG_MISC)
			kprintf("pfsync: failed to receive "
			    "bulk update status\n");
		callout_stop(&sc->sc_bulkfail_tmo);
	}
}

int
pfsync_sendout(struct pfsync_softc *sc)
{
	struct ifnet *ifp = &sc->sc_if;
	struct mbuf *m;

	callout_stop(&sc->sc_tmo);

	if (sc->sc_mbuf == NULL)
		return (0);
	m = sc->sc_mbuf;
	sc->sc_mbuf = NULL;
	sc->sc_statep.s = NULL;

	KASSERT(m != NULL, ("pfsync_sendout: null mbuf"));
	BPF_MTAP(ifp, m);

	if (sc->sc_mbuf_net) {
		m_freem(m);
		m = sc->sc_mbuf_net;
		sc->sc_mbuf_net = NULL;
		sc->sc_statep_net.s = NULL;
	}

	if (sc->sc_sync_ifp) {
		struct ip *ip;
		struct ifaddr *ifa;
		struct sockaddr sa;

		M_PREPEND(m, sizeof(struct ip), MB_DONTWAIT);
		if (m == NULL) {
			pfsyncstats.pfsyncs_onomem++;
			return (0);
		}
		ip = mtod(m, struct ip *);
		ip->ip_v = IPVERSION;
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_tos = IPTOS_LOWDELAY;
		ip->ip_len = m->m_pkthdr.len;
#ifdef RANDOM_IP_ID
		ip->ip_id = ip_randomid();
#else
		ip->ip_id = ntohs(ip_id++);
#endif
		ip->ip_off = IP_DF;
		ip->ip_ttl = PFSYNC_DFLTTL;
		ip->ip_p = IPPROTO_PFSYNC;
		ip->ip_sum = 0;

		bzero(&sa, sizeof(sa));
		sa.sa_family = AF_INET;
		ifa = ifaof_ifpforaddr(&sa, sc->sc_sync_ifp);
		if (ifa == NULL)
			return (0);
		ip->ip_src.s_addr = ifatoia(ifa)->ia_addr.sin_addr.s_addr;

		if (sc->sc_sendaddr.s_addr == htonl(INADDR_PFSYNC_GROUP))
			m->m_flags |= M_MCAST;
		ip->ip_dst = sc->sc_sendaddr;
		sc->sc_sendaddr.s_addr = htonl(INADDR_PFSYNC_GROUP);

		pfsyncstats.pfsyncs_opackets++;

		if (ip_output(m, NULL, NULL, IP_RAWOUTPUT, &sc->sc_imo, NULL))
			pfsyncstats.pfsyncs_oerrors++;
	} else
		m_freem(m);

	return (0);
}

static int
pfsync_modevent(module_t mod, int type, void *data)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		LIST_INIT(&pfsync_list);
		if_clone_attach(&pfsync_cloner);
		break;

	case MOD_UNLOAD:
		if_clone_detach(&pfsync_cloner);
		while (!LIST_EMPTY(&pfsync_list))
			pfsync_clone_destroy(
				&LIST_FIRST(&pfsync_list)->sc_if);
		break;

	default:
		error = EINVAL;
		break;
	}

	return error;
}

static moduledata_t pfsync_mod = {
	"pfsync",
	pfsync_modevent,
	0
};

#define PFSYNC_MODVER 1

DECLARE_MODULE(pfsync, pfsync_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(pfsync, PFSYNC_MODVER);
