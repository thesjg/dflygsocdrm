/*
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 * 
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/net/if_vlan.c,v 1.15.2.13 2003/02/14 22:25:58 fenner Exp $
 * $DragonFly: src/sys/net/vlan/if_vlan_ether.c,v 1.3 2008/05/16 13:19:12 sephe Exp $
 */

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/serialize.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ifq_var.h>
#include <net/netmsg.h>

#include <net/vlan/if_vlan_var.h>
#include <net/vlan/if_vlan_ether.h>

void
vlan_start_dispatch(netmsg_t msg)
{
	struct netmsg_packet *nmp = &msg->packet;
	struct mbuf *m;
	struct ifnet *ifp;
	struct altq_pktattr pktattr;

	m = nmp->nm_packet;
	ifp = msg->lmsg.u.ms_resultp;

	M_ASSERTPKTHDR(m);
	KASSERT(m->m_flags & M_VLANTAG, ("mbuf has not been vlan tagged!\n"));

	ifnet_serialize_tx(ifp);

	/*
	 * Make sure that the interface is still UP and RUNNING,
	 * since interface state may have been changed when the
	 * mbuf is pending on the msgport.
	 */
	if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) !=
	    (IFF_UP | IFF_RUNNING)) {
		m_freem(m);
		goto back;
	}

	/*
	 * If ALTQ is enabled on the parent interface, do
	 * classification; the queueing discipline might
	 * not require classification, but might require
	 * the address family/header pointer in the pktattr.
	 */
	if (ifq_is_enabled(&ifp->if_snd))
		altq_etherclassify(&ifp->if_snd, m, &pktattr);

	/*
	 * If underlying interface can do VLAN tag insertion itself,
	 * just pass the packet along.
	 */
	if ((ifp->if_capenable & IFCAP_VLAN_HWTAGGING) == 0) {
		uint16_t vlantag = m->m_pkthdr.ether_vlantag;
		struct ether_vlan_header *evl;

		M_PREPEND(m, EVL_ENCAPLEN, MB_DONTWAIT);
		if (m == NULL) {
			if_printf(ifp, "vlan%u M_PREPEND failed", vlantag);
			goto back;
		}
		/* M_PREPEND takes care of m_len, m_pkthdr.len for us */

		m = m_pullup(m, ETHER_HDR_LEN + EVL_ENCAPLEN);
		if (m == NULL) {
			if_printf(ifp, "vlan%u m_pullup failed", vlantag);
			goto back;
		}

		/*
		 * Transform the Ethernet header into an Ethernet header
		 * with 802.1Q encapsulation.
		 */
		bcopy(mtod(m, char *) + EVL_ENCAPLEN, mtod(m, char *),
		      sizeof(struct ether_header));
		evl = mtod(m, struct ether_vlan_header *);
		evl->evl_proto = evl->evl_encap_proto;
		evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
		evl->evl_tag = htons(vlantag);
#ifdef DEBUG
		kprintf("vlan_start: %*D\n", sizeof *evl,
			(unsigned char *)evl, ":");
#endif
		/* Hardware does not need to setup vlan tagging */
		m->m_flags &= ~M_VLANTAG;
	}
	ifq_handoff(ifp, m, &pktattr);
back:
	ifnet_deserialize_tx(ifp);
}

void
vlan_ether_ptap(struct bpf_if *bp, struct mbuf *m, uint16_t vlantag)
{
	const struct ether_header *eh;
	struct ether_vlan_header evh;

	KASSERT(m->m_len >= ETHER_HDR_LEN,
		("ether header is not contiguous!\n"));

	eh = mtod(m, const struct ether_header *);
	m_adj(m, ETHER_HDR_LEN);

	bcopy(eh, &evh, 2 * ETHER_ADDR_LEN);
	evh.evl_encap_proto = htons(ETHERTYPE_VLAN);
	evh.evl_tag = htons(vlantag);
	evh.evl_proto = eh->ether_type;
	bpf_ptap(bp, m, &evh, ETHER_HDR_LEN + EVL_ENCAPLEN);

	/* XXX assumes data was left intact */
	M_PREPEND(m, ETHER_HDR_LEN, MB_WAIT);
}

void
vlan_ether_decap(struct mbuf **m0)
{
	struct mbuf *m = *m0;
	struct ether_vlan_header *evh;

	KKASSERT((m->m_flags & M_VLANTAG) == 0);

	if (m->m_len < sizeof(*evh)) {
		/* Error in the caller */
		m_freem(m);
		*m0 = NULL;
		return;
	}
	evh = mtod(m, struct ether_vlan_header *);

	m->m_pkthdr.ether_vlantag = ntohs(evh->evl_tag);
	m->m_flags |= M_VLANTAG;

	bcopy((uint8_t *)evh, (uint8_t *)evh + EVL_ENCAPLEN,
	      2 * ETHER_ADDR_LEN);
	m_adj(m, EVL_ENCAPLEN);
	*m0 = m;
}
