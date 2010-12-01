/*	$FreeBSD: src/sys/dev/iwi/if_iwivar.h,v 1.21 2009/05/21 15:30:59 sam Exp $	*/

/*-
 * Copyright (c) 2004, 2005
 *      Damien Bergamini <damien.bergamini@free.fr>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

struct iwi_rx_radiotap_header {
	struct ieee80211_radiotap_header wr_ihdr;
	uint8_t		wr_flags;
	uint8_t		wr_rate;
	uint16_t	wr_chan_freq;
	uint16_t	wr_chan_flags;
	int8_t		wr_antsignal;
	int8_t		wr_antnoise;
	uint8_t		wr_antenna;
};

#define IWI_RX_RADIOTAP_PRESENT						\
	((1 << IEEE80211_RADIOTAP_FLAGS) |				\
	 (1 << IEEE80211_RADIOTAP_RATE) |				\
	 (1 << IEEE80211_RADIOTAP_CHANNEL) |				\
	 (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL) |			\
	 (1 << IEEE80211_RADIOTAP_DBM_ANTNOISE) |			\
	 (1 << IEEE80211_RADIOTAP_ANTENNA))

struct iwi_tx_radiotap_header {
	struct ieee80211_radiotap_header wt_ihdr;
	uint8_t		wt_flags;
	uint16_t	wt_chan_freq;
	uint16_t	wt_chan_flags;
};

#define IWI_TX_RADIOTAP_PRESENT						\
	((1 << IEEE80211_RADIOTAP_FLAGS) |				\
	 (1 << IEEE80211_RADIOTAP_CHANNEL))

struct iwi_cmd_ring {
	bus_dma_tag_t		desc_dmat;
	bus_dmamap_t		desc_map;
	bus_addr_t		physaddr;
	struct iwi_cmd_desc	*desc;
	int			count;
	int			queued;
	int			cur;
	int			next;
};

struct iwi_tx_data {
	bus_dmamap_t		map;
	struct mbuf		*m;
	struct ieee80211_node	*ni;
};

struct iwi_tx_ring {
	bus_dma_tag_t		desc_dmat;
	bus_dma_tag_t		data_dmat;
	bus_dmamap_t		desc_map;
	bus_addr_t		physaddr;
	bus_addr_t		csr_ridx;
	bus_addr_t		csr_widx;
	struct iwi_tx_desc	*desc;
	struct iwi_tx_data	*data;
	int			count;
	int			queued;
	int			cur;
	int			next;
};

struct iwi_rx_data {
	bus_dmamap_t	map;
	bus_addr_t	physaddr;
	uint32_t	reg;
	struct mbuf	*m;
};

struct iwi_rx_ring {
	bus_dma_tag_t		data_dmat;
	struct iwi_rx_data	*data;
	int			count;
	int			cur;
};

struct iwi_node {
	struct ieee80211_node	in_node;
	int			in_station;
#define IWI_MAX_IBSSNODE	32
};

struct iwi_fw {
	const struct firmware	*fp;		/* image handle */
	const char		*data;		/* firmware image data */
	size_t			size;		/* firmware image size */
	const char		*name;		/* associated image name */
};

struct iwi_vap {
	struct ieee80211vap	iwi_vap;

	int			(*iwi_newstate)(struct ieee80211vap *,
				    enum ieee80211_state, int);
};
#define	IWI_VAP(vap)	((struct iwi_vap *)(vap))

struct iwi_softc {
	struct ifnet		*sc_ifp;
	void			(*sc_node_free)(struct ieee80211_node *);
	device_t		sc_dev;

	struct lock		sc_lock;
	uint8_t			sc_mcast[IEEE80211_ADDR_LEN];
	struct devfs_bitmap		sc_unr;

	uint32_t		flags;
#define IWI_FLAG_FW_INITED	(1 << 0)
#define	IWI_FLAG_BUSY		(1 << 3)	/* busy sending a command */
#define	IWI_FLAG_ASSOCIATED	(1 << 4)	/* currently associated  */
#define IWI_FLAG_CHANNEL_SCAN	(1 << 5)
	uint32_t		fw_state;
#define IWI_FW_IDLE		0
#define IWI_FW_LOADING		1
#define IWI_FW_ASSOCIATING	2
#define IWI_FW_DISASSOCIATING	3
#define IWI_FW_SCANNING		4
	struct iwi_cmd_ring	cmdq;
	struct iwi_tx_ring	txq[WME_NUM_AC];
	struct iwi_rx_ring	rxq;

	struct resource		*irq;
	struct resource		*mem;
	bus_space_tag_t		sc_st;
	bus_space_handle_t	sc_sh;
	void 			*sc_ih;
	int			mem_rid;
	int			irq_rid;

	/*
	 * The card needs external firmware images to work, which is made of a
	 * bootloader, microcode and firmware proper. In version 3.00 and
	 * above, all pieces are contained in a single image, preceded by a
	 * struct iwi_firmware_hdr indicating the size of the 3 pieces.
	 * Old firmware < 3.0 has separate boot and ucode, so we need to
	 * load all of them explicitly.
	 * To avoid issues related to fragmentation, we keep the block of
	 * dma-ble memory around until detach time, and reallocate it when
	 * it becomes too small. fw_dma_size is the size currently allocated.
	 */
	int			fw_dma_size;
	uint32_t		fw_flags;	/* allocation status */
#define	IWI_FW_HAVE_DMAT	0x01
#define	IWI_FW_HAVE_MAP		0x02
#define	IWI_FW_HAVE_PHY		0x04
	bus_dma_tag_t		fw_dmat;
	bus_dmamap_t		fw_map;
	bus_addr_t		fw_physaddr;
	void			*fw_virtaddr;
	enum ieee80211_opmode	fw_mode;	/* mode of current firmware */
	struct iwi_fw		fw_boot;	/* boot firmware */
	struct iwi_fw		fw_uc;		/* microcode */
	struct iwi_fw		fw_fw;		/* operating mode support */

	int			curchan;	/* current h/w channel # */
	int			antenna;
	int			bluetooth;
	struct iwi_associate	assoc;
	struct iwi_wme_params	wme[3];
	u_int			sc_scangen;

	struct task		sc_radiontask;	/* radio on processing */
	struct task		sc_radiofftask;	/* radio off processing */
	struct task		sc_restarttask;	/* restart adapter processing */
	struct task		sc_disassoctask;
	struct task		sc_wmetask;	/* set wme parameters */

	unsigned int		sc_softled : 1,	/* enable LED gpio status */
				sc_ledstate: 1,	/* LED on/off state */
				sc_blinking: 1;	/* LED blink operation active */
	u_int			sc_nictype;	/* NIC type from EEPROM */
	u_int			sc_ledpin;	/* mask for activity LED */
	u_int			sc_ledidle;	/* idle polling interval */
	int			sc_ledevent;	/* time of last LED event */
	u_int8_t		sc_rxrate;	/* current rx rate for LED */
	u_int8_t		sc_rxrix;
	u_int8_t		sc_txrate;	/* current tx rate for LED */
	u_int8_t		sc_txrix;
	u_int16_t		sc_ledoff;	/* off time for current blink */
	struct callout		sc_ledtimer_callout;	/* led off timer */
	struct callout		sc_wdtimer_callout;	/* watchdog timer */
	struct callout		sc_rftimer_callout;	/* rfkill timer */

	int			sc_tx_timer;
	int			sc_state_timer;	/* firmware state timer */
	int			sc_busy_timer;	/* firmware cmd timer */

	struct iwi_rx_radiotap_header sc_rxtap;
	struct iwi_tx_radiotap_header sc_txtap;

	struct sysctl_ctx_list  sc_sysctl_ctx;
	struct sysctl_oid       *sc_sysctl_tree;
};

#define	IWI_STATE_BEGIN(_sc, _state)	do {			\
	KASSERT(_sc->fw_state == IWI_FW_IDLE,			\
	    ("iwi firmware not idle, state %s", iwi_fw_states[_sc->fw_state]));\
	_sc->fw_state = _state;					\
	_sc->sc_state_timer = 5;				\
	DPRINTF(("enter %s state\n", iwi_fw_states[_state]));	\
} while (0)

#define	IWI_STATE_END(_sc, _state)	do {			\
	if (_sc->fw_state == _state)				\
		DPRINTF(("exit %s state\n", iwi_fw_states[_state])); \
	 else							\
		DPRINTF(("expected %s state, got %s\n",	\
		    iwi_fw_states[_state], iwi_fw_states[_sc->fw_state])); \
	_sc->fw_state = IWI_FW_IDLE;				\
	wakeup(_sc);						\
	_sc->sc_state_timer = 0;				\
} while (0)
