/*-
 * Copyright (c) 2003
 *	Bill Paul <wpaul@windriver.com>.  All rights reserved.
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
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/dev/if_ndis/if_ndisvar.h,v 1.39 2009/05/02 15:14:18 thompsa Exp $
 */

#define NDIS_DEFAULT_NODENAME	"FreeBSD NDIS node"
#define NDIS_NODENAME_LEN	32

/* For setting/getting OIDs from userspace. */

struct ndis_oid_data {
	uint32_t		oid;
	uint32_t		len;
#ifdef notdef
	uint8_t			data[1];
#endif
};

struct ndis_pci_type {
	uint16_t		ndis_vid;
	uint16_t		ndis_did;
	uint32_t		ndis_subsys;
	char			*ndis_name;
};

struct ndis_pccard_type {
	const char		*ndis_vid;
	const char		*ndis_did;
	char			*ndis_name;
};

struct ndis_usb_type {
	uint16_t		ndis_vid;
	uint16_t		ndis_did;
	char			*ndis_name;
};

struct ndis_shmem {
	list_entry		ndis_list;
	bus_dma_tag_t		ndis_stag;
	bus_dmamap_t		ndis_smap;
	void			*ndis_saddr;
	ndis_physaddr		ndis_paddr;
};

struct ndis_cfglist {
	ndis_cfg		ndis_cfg;
	struct sysctl_oid	*ndis_oid;
        TAILQ_ENTRY(ndis_cfglist)	link;
};

/*
 * Helper struct to make parsing information
 * elements easier.
 */
struct ndis_ie {
	uint8_t		ni_oui[3];
	uint8_t		ni_val;
};

TAILQ_HEAD(nch, ndis_cfglist);

#define NDIS_INITIALIZED(sc)	(sc->ndis_block->nmb_devicectx != NULL)

#define NDIS_TXPKTS 64
#define NDIS_INC(x)		\
	(x)->ndis_txidx = ((x)->ndis_txidx + 1) % (x)->ndis_maxpkts


#define NDIS_EVENTS 4
#define NDIS_EVTINC(x)	(x) = ((x) + 1) % NDIS_EVENTS

struct ndis_evt {
	uint32_t		ne_sts;
	uint32_t		ne_len;
	char			*ne_buf;
};

struct ndis_vap {
	struct ieee80211vap	vap;

	int			(*newstate)(struct ieee80211vap *,
				    enum ieee80211_state, int);
};
#define	NDIS_VAP(vap)	((struct ndis_vap *)(vap))

#define	NDISUSB_CONFIG_NO			1
#define	NDISUSB_IFACE_INDEX			0
#define	NDISUSB_INTR_TIMEOUT			1000
#define	NDISUSB_TX_TIMEOUT			10000
struct ndisusb_xfer {
	usbd_xfer_handle	nx_xfer;
	usbd_private_handle	nx_priv;
	usbd_status		nx_status;
	list_entry		nx_xferlist;
};

struct ndis_softc {
	struct ifnet		*ifp;
	struct ifmedia		ifmedia;	/* media info */
	u_long			ndis_hwassist;
	uint32_t		ndis_v4tx;
	uint32_t		ndis_v4rx;
	bus_space_handle_t	ndis_bhandle;
	bus_space_tag_t		ndis_btag;
	void			*ndis_intrhand;
	struct resource		*ndis_irq;
	struct resource		*ndis_res;
	struct resource		*ndis_res_io;
	int			ndis_io_rid;
	struct resource		*ndis_res_mem;
	int			ndis_mem_rid;
	struct resource		*ndis_res_altmem;
	int			ndis_altmem_rid;
	struct resource		*ndis_res_am;	/* attribute mem (pccard) */
	int			ndis_am_rid;
	struct resource		*ndis_res_cm;	/* common mem (pccard) */
	struct resource_list	ndis_rl;
	int			ndis_rescnt;
	struct lock		ndis_lock;
	uint8_t			ndis_irql;
	device_t		ndis_dev;
	int			ndis_unit;
	ndis_miniport_block	*ndis_block;
	ndis_miniport_characteristics	*ndis_chars;
	interface_type		ndis_type;
	struct callout		ndis_scan_callout;
	struct callout		ndis_stat_callout;
	int			ndis_maxpkts;
	ndis_oid		*ndis_oids;
	int			ndis_oidcnt;
	int			ndis_txidx;
	int			ndis_txpending;
	ndis_packet		**ndis_txarray;
	ndis_handle		ndis_txpool;
	int			ndis_sc;
	ndis_cfg		*ndis_regvals;
	struct nch		ndis_cfglist_head;
	int			ndis_80211;
	int			ndis_link;
	uint32_t		ndis_sts;
	uint32_t		ndis_filter;
	int			ndis_if_flags;
	int			ndis_skip;

#if __FreeBSD_version < 502113
	struct sysctl_ctx_list	ndis_ctx;
	struct sysctl_oid	*ndis_tree;
#endif
	int			ndis_devidx;
	interface_type		ndis_iftype;
	driver_object		*ndis_dobj;
	io_workitem		*ndis_tickitem;
	io_workitem		*ndis_startitem;
	io_workitem		*ndis_resetitem;
	io_workitem		*ndis_inputitem;
	kdpc			ndis_rxdpc;
	bus_dma_tag_t		ndis_parent_tag;
	list_entry		ndis_shlist;
	bus_dma_tag_t		ndis_mtag;
	bus_dma_tag_t		ndis_ttag;
	bus_dmamap_t		*ndis_mmaps;
	bus_dmamap_t		*ndis_tmaps;
	int			ndis_mmapcnt;
	struct ndis_evt		ndis_evt[NDIS_EVENTS];
	int			ndis_evtpidx;
	int			ndis_evtcidx;
	struct ifqueue		ndis_rxqueue;
	kspin_lock		ndis_rxlock;

	int			(*ndis_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);
	int			ndis_tx_timer;
	int			ndis_hang_timer;

	io_workitem		*ndisusb_xferitem;
	list_entry		ndisusb_xferlist;
	kspin_lock		ndisusb_xferlock;
#define	NDISUSB_ENDPT_BOUT	0
#define	NDISUSB_ENDPT_BIN	1
#define	NDISUSB_ENDPT_IIN	2
#define	NDISUSB_ENDPT_IOUT	3
#define	NDISUSB_ENDPT_MAX	4
	usbd_pipe_handle	ndisusb_ep[NDISUSB_ENDPT_MAX];
	char			*ndisusb_iin_buf;
	int			ndisusb_status;
#define NDISUSB_STATUS_DETACH	0x1
};

#define	NDISMTX_LOCK(_sc)	lockmgr(&(_sc)->ndis_lock, LK_EXCLUSIVE)
#define	NDISMTX_UNLOCK(_sc)	lockmgr(&(_sc)->ndis_lock, LK_RELEASE)
#define	NDISUSB_LOCK(_sc)	get_mplock()
#define	NDISUSB_UNLOCK(_sc)	rel_mplock()
#define	NDIS_LOCK(_sc) do {						\
	if ((_sc)->ndis_iftype == PNPBus)				\
		NDISUSB_LOCK(_sc);					\
	NDISMTX_LOCK(_sc);						\
} while (0)
#define	NDIS_UNLOCK(_sc) do {						\
	if ((_sc)->ndis_iftype == PNPBus)				\
		NDISUSB_UNLOCK(_sc);					\
	NDISMTX_UNLOCK(_sc);						\
} while (0)
