/*
 * Copyright (c) 2001-2008, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  3. Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _IF_EMX_H_
#define _IF_EMX_H_

/* Tunables */

/*
 * EMX_TXD: Maximum number of Transmit Descriptors
 * Valid Range: 256-4096 for others
 * Default Value: 512
 *   This value is the number of transmit descriptors allocated by the driver.
 *   Increasing this value allows the driver to queue more transmits. Each
 *   descriptor is 16 bytes.
 *   Since TDLEN should be multiple of 128bytes, the number of transmit
 *   desscriptors should meet the following condition.
 *      (num_tx_desc * sizeof(struct e1000_tx_desc)) % 128 == 0
 */
#define EMX_MIN_TXD			256
#define EMX_MAX_TXD			4096
#define EMX_DEFAULT_TXD			512

/*
 * EMX_RXD - Maximum number of receive Descriptors
 * Valid Range: 256-4096 for others
 * Default Value: 512
 *   This value is the number of receive descriptors allocated by the driver.
 *   Increasing this value allows the driver to buffer more incoming packets.
 *   Each descriptor is 16 bytes.  A receive buffer is also allocated for each
 *   descriptor. The maximum MTU size is 16110.
 *   Since TDLEN should be multiple of 128bytes, the number of transmit
 *   desscriptors should meet the following condition.
 *      (num_tx_desc * sizeof(struct e1000_tx_desc)) % 128 == 0
 */
#define EMX_MIN_RXD			256
#define EMX_MAX_RXD			4096
#define EMX_DEFAULT_RXD			512

/*
 * Receive Interrupt Delay Timer (Packet Timer)
 *
 * NOTE:
 * RDTR and RADV are deprecated; use ITR instead.  They are only used to
 * workaround hardware bug on certain 82573 based NICs.
 */
#define EMX_RDTR_82573			32

/*
 * Receive Interrupt Absolute Delay Timer (Not valid for 82542/82543/82544)
 *
 * NOTE:
 * RDTR and RADV are deprecated; use ITR instead.  They are only used to
 * workaround hardware bug on certain 82573 based NICs.
 */
#define EMX_RADV_82573			64

/*
 * This parameter controls the duration of transmit watchdog timer.
 */
#define EMX_TX_TIMEOUT			5

/* One for TX csum offloading desc, the other 2 are reserved */
#define EMX_TX_RESERVED			3

/* Large enough for 16K jumbo frame */
#define EMX_TX_SPARE			8

#define EMX_TX_OACTIVE_MAX		64

/* Interrupt throttle rate */
#define EMX_DEFAULT_ITR			10000

/*
 * This parameter controls whether or not autonegotation is enabled.
 *              0 - Disable autonegotiation
 *              1 - Enable  autonegotiation
 */
#define EMX_DO_AUTO_NEG			1

/* Tunables -- End */

#define EMX_AUTONEG_ADV_DEFAULT		(ADVERTISE_10_HALF | \
					 ADVERTISE_10_FULL | \
					 ADVERTISE_100_HALF | \
					 ADVERTISE_100_FULL | \
					 ADVERTISE_1000_FULL)

#define EMX_AUTO_ALL_MODES		0

/* PHY master/slave setting */
#define EMX_MASTER_SLAVE		e1000_ms_hw_default

/*
 * Micellaneous constants
 */
#define EMX_VENDOR_ID			0x8086

#define EMX_BAR_MEM			PCIR_BAR(0)

#define EMX_JUMBO_PBA			0x00000028
#define EMX_DEFAULT_PBA			0x00000030
#define EMX_SMARTSPEED_DOWNSHIFT	3
#define EMX_SMARTSPEED_MAX		15
#define EMX_MAX_INTR			10

#define EMX_MCAST_ADDR_MAX		128
#define EMX_FC_PAUSE_TIME		1000
#define EMX_EEPROM_APME			0x400;

/*
 * TDBA/RDBA should be aligned on 16 byte boundary. But TDLEN/RDLEN should be
 * multiple of 128 bytes. So we align TDBA/RDBA on 128 byte boundary. This will
 * also optimize cache line size effect. H/W supports up to cache line size 128.
 */
#define EMX_DBA_ALIGN			128

/*
 * Speed mode bit in TARC0/TARC1.
 * 82571EB/82572EI only, used to improve small packet transmit performance.
 */
#define EMX_TARC_SPEED_MODE		(1 << 21)

#define EMX_MAX_SCATTER			64
#define EMX_TSO_SIZE			(65535 + \
					 sizeof(struct ether_vlan_header))
#define EMX_MAX_SEGSIZE			4096
#define EMX_MSIX_MASK			0x01F00000 /* For 82574 use */

#define EMX_CSUM_FEATURES		(CSUM_IP | CSUM_TCP | CSUM_UDP)
#define EMX_IPVHL_SIZE			1 /* sizeof(ip.ip_vhl) */
#define EMX_TXCSUM_MINHL		(ETHER_HDR_LEN + EVL_ENCAPLEN + \
					 EMX_IPVHL_SIZE)

/*
 * 82574 has a nonstandard address for EIAC
 * and since its only used in MSIX, and in
 * the em driver only 82574 uses MSIX we can
 * solve it just using this define.
 */
#define EMX_EIAC			0x000DC

#define EMX_NRSSRK			10
#define EMX_RSSRK_SIZE			4
#define EMX_RSSRK_VAL(key, i)		(key[(i) * EMX_RSSRK_SIZE] | \
					 key[(i) * EMX_RSSRK_SIZE + 1] << 8 | \
					 key[(i) * EMX_RSSRK_SIZE + 2] << 16 | \
					 key[(i) * EMX_RSSRK_SIZE + 3] << 24)

#define EMX_NRETA			32
#define EMX_RETA_SIZE			4
#define EMX_RETA_RINGIDX_SHIFT		7

#define EMX_NRX_RING			2
#define EMX_NSERIALIZE			4

typedef union e1000_rx_desc_extended	emx_rxdesc_t;

#define rxd_bufaddr	read.buffer_addr	/* 64bits */
#define rxd_length	wb.upper.length		/* 16bits */
#define rxd_vlan	wb.upper.vlan		/* 16bits */
#define rxd_staterr	wb.upper.status_error	/* 32bits */
#define rxd_mrq		wb.lower.mrq		/* 32bits */
#define rxd_rss		wb.lower.hi_dword.rss	/* 32bits */

#define EMX_RXDMRQ_RSSTYPE_MASK	0xf
#define EMX_RXDMRQ_NO_HASH	0
#define EMX_RXDMRQ_IPV4_TCP	1
#define EMX_RXDMRQ_IPV4		2
#define EMX_RXDMRQ_IPV6_TCP	3
#define EMX_RXDMRQ_IPV6		5

struct emx_rxdata {
	struct lwkt_serialize	rx_serialize;

	/*
	 * Receive definitions
	 *
	 * we have an array of num_rx_desc rx_desc (handled by the
	 * controller), and paired with an array of rx_buffers
	 * (at rx_buffer_area).
	 * The next pair to check on receive is at offset next_rx_desc_to_check
	 */
	emx_rxdesc_t		*rx_desc;
	uint32_t		next_rx_desc_to_check;
	int			num_rx_desc;
	struct emx_rxbuf	*rx_buf;
	bus_dma_tag_t		rxtag;
	bus_dmamap_t		rx_sparemap;

	/*
	 * First/last mbuf pointers, for
	 * collecting multisegment RX packets.
	 */
	struct mbuf		*fmp;
	struct mbuf		*lmp;

	/* RX statistics */
	unsigned long		rx_pkts;
	unsigned long		mbuf_cluster_failed;

	bus_dma_tag_t		rx_desc_dtag;
	bus_dmamap_t		rx_desc_dmap;
	bus_addr_t		rx_desc_paddr;
} __cachealign;

struct emx_softc {
	struct arpcom		arpcom;
	struct e1000_hw		hw;

	/* DragonFly operating-system-specific structures. */
	struct e1000_osdep	osdep;
	device_t		dev;

	bus_dma_tag_t		parent_dtag;

	bus_dma_tag_t		tx_desc_dtag;
	bus_dmamap_t		tx_desc_dmap;
	bus_addr_t		tx_desc_paddr;

	struct resource		*memory;
	int			memory_rid;

	struct resource		*intr_res;
	void			*intr_tag;
	int			intr_rid;
	int			intr_type;

	struct ifmedia		media;
	struct callout		timer;
	int			if_flags;
	int			max_frame_size;
	int			min_frame_size;

	/* Management and WOL features */
	int			wol;
	int			has_manage;
	int			has_amt;
	int			control_hw;

	/* Multicast array memory */
	uint8_t			*mta;

	/* Info about the board itself */
	uint8_t			link_active;
	uint16_t		link_speed;
	uint16_t		link_duplex;
	uint32_t		smartspeed;
	int			int_throttle_ceil;

	struct lwkt_serialize	main_serialize;
	struct lwkt_serialize	tx_serialize;
	struct lwkt_serialize	*serializes[EMX_NSERIALIZE];

	/*
	 * Transmit definitions
	 *
	 * We have an array of num_tx_desc descriptors (handled
	 * by the controller) paired with an array of tx_buffers
	 * (at tx_buffer_area).
	 * The index of the next available descriptor is next_avail_tx_desc.
	 * The number of remaining tx_desc is num_tx_desc_avail.
	 */
	struct e1000_tx_desc	*tx_desc_base;
	struct emx_txbuf	*tx_buf;
	uint32_t		next_avail_tx_desc;
	uint32_t		next_tx_to_clean;
	int			num_tx_desc_avail;
	int			num_tx_desc;
	bus_dma_tag_t		txtag;		/* dma tag for tx */
	int			spare_tx_desc;
	int			oact_tx_desc;

	/* Saved csum offloading context information */
	int			csum_flags;
	int			csum_ehlen;
	int			csum_iphlen;
	uint32_t		csum_txd_upper;
	uint32_t		csum_txd_lower;

	/*
	 * Variables used to reduce TX interrupt rate and
	 * number of device's TX ring write requests.
	 *
	 * tx_nsegs:
	 * Number of TX descriptors setup so far.
	 *
	 * tx_int_nsegs:
	 * Once tx_nsegs > tx_int_nsegs, RS bit will be set
	 * in the last TX descriptor of the packet, and
	 * tx_nsegs will be reset to 0.  So TX interrupt and
	 * TX ring write request should be generated roughly
	 * every tx_int_nsegs TX descriptors.
	 *
	 * tx_dd[]:
	 * Index of the TX descriptors which have RS bit set,
	 * i.e. DD bit will be set on this TX descriptor after
	 * the data of the TX descriptor are transfered to
	 * hardware's internal packet buffer.  Only the TX
	 * descriptors listed in tx_dd[] will be checked upon
	 * TX interrupt.  This array is used as circular ring.
	 *
	 * tx_dd_tail, tx_dd_head:
	 * Tail and head index of valid elements in tx_dd[].
	 * tx_dd_tail == tx_dd_head means there is no valid
	 * elements in tx_dd[].  tx_dd_tail points to the position
	 * which is one beyond the last valid element in tx_dd[].
	 * tx_dd_head points to the first valid element in
	 * tx_dd[].
	 */
	int			tx_int_nsegs;
	int			tx_nsegs;
	int			tx_dd_tail;
	int			tx_dd_head;
#define EMX_TXDD_MAX	64
#define EMX_TXDD_SAFE	48 /* 48 <= val < EMX_TXDD_MAX */
	int			tx_dd[EMX_TXDD_MAX];

	int			rss_debug;
	int			rx_ring_cnt;
	struct emx_rxdata	rx_data[EMX_NRX_RING];

	/* Misc stats maintained by the driver */
	unsigned long		dropped_pkts;
	unsigned long		mbuf_alloc_failed;
	unsigned long		no_tx_desc_avail1;
	unsigned long		no_tx_desc_avail2;
	unsigned long		no_tx_map_avail;
	unsigned long		no_tx_dma_setup;
	unsigned long		watchdog_events;
	unsigned long		rx_overruns;
	unsigned long		rx_irq;
	unsigned long		tx_irq;
	unsigned long		link_irq;
	unsigned long		tx_csum_try_pullup;
	unsigned long		tx_csum_pullup1;
	unsigned long		tx_csum_pullup1_failed;
	unsigned long		tx_csum_pullup2;
	unsigned long		tx_csum_pullup2_failed;
	unsigned long		tx_csum_drop1;
	unsigned long		tx_csum_drop2;

	/* sysctl tree glue */
	struct sysctl_ctx_list	sysctl_ctx;
	struct sysctl_oid	*sysctl_tree;

	struct e1000_hw_stats	stats;
};

struct emx_txbuf {
	struct mbuf	*m_head;
	bus_dmamap_t	map;
};

struct emx_rxbuf {
	struct mbuf	*m_head;
	bus_dmamap_t	map;
	bus_addr_t	paddr;
};

#define EMX_IS_OACTIVE(sc)	((sc)->num_tx_desc_avail <= (sc)->oact_tx_desc)

#define EMX_INC_TXDD_IDX(idx) \
do { \
	if (++(idx) == EMX_TXDD_MAX) \
		(idx) = 0; \
} while (0)

#endif /* !_IF_EMX_H_ */
