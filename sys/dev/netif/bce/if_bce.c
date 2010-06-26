/*-
 * Copyright (c) 2006-2007 Broadcom Corporation
 *	David Christensen <davidch@broadcom.com>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Broadcom Corporation nor the name of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written consent.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS'
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/dev/bce/if_bce.c,v 1.31 2007/05/16 23:34:11 davidch Exp $
 * $DragonFly: src/sys/dev/netif/bce/if_bce.c,v 1.21 2008/11/19 13:57:49 sephe Exp $
 */

/*
 * The following controllers are supported by this driver:
 *   BCM5706C A2, A3
 *   BCM5708C B1, B2
 *
 * The following controllers are not supported by this driver:
 *   BCM5706C A0, A1
 *   BCM5706S A0, A1, A2, A3
 *   BCM5708C A0, B0
 *   BCM5708S A0, B0, B1, B2
 */

#include "opt_bce.h"
#include "opt_polling.h"

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/interrupt.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#ifdef BCE_DEBUG
#include <sys/random.h>
#endif
#include <sys/rman.h>
#include <sys/serialize.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/ifq_var.h>
#include <net/vlan/if_vlan_var.h>
#include <net/vlan/if_vlan_ether.h>

#include <dev/netif/mii_layer/mii.h>
#include <dev/netif/mii_layer/miivar.h>

#include <bus/pci/pcireg.h>
#include <bus/pci/pcivar.h>

#include "miibus_if.h"

#include <dev/netif/bce/if_bcereg.h>
#include <dev/netif/bce/if_bcefw.h>

/****************************************************************************/
/* BCE Debug Options                                                        */
/****************************************************************************/
#ifdef BCE_DEBUG

static uint32_t	bce_debug = BCE_WARN;

/*
 *          0 = Never             
 *          1 = 1 in 2,147,483,648
 *        256 = 1 in     8,388,608
 *       2048 = 1 in     1,048,576
 *      65536 = 1 in        32,768
 *    1048576 = 1 in         2,048
 *  268435456 = 1 in             8
 *  536870912 = 1 in             4
 * 1073741824 = 1 in             2
 *
 * bce_debug_l2fhdr_status_check:
 *     How often the l2_fhdr frame error check will fail.
 *
 * bce_debug_unexpected_attention:
 *     How often the unexpected attention check will fail.
 *
 * bce_debug_mbuf_allocation_failure:
 *     How often to simulate an mbuf allocation failure.
 *
 * bce_debug_dma_map_addr_failure:
 *     How often to simulate a DMA mapping failure.
 *
 * bce_debug_bootcode_running_failure:
 *     How often to simulate a bootcode failure.
 */
static int	bce_debug_l2fhdr_status_check = 0;
static int	bce_debug_unexpected_attention = 0;
static int	bce_debug_mbuf_allocation_failure = 0;
static int	bce_debug_dma_map_addr_failure = 0;
static int	bce_debug_bootcode_running_failure = 0;

#endif	/* BCE_DEBUG */


/****************************************************************************/
/* PCI Device ID Table                                                      */
/*                                                                          */
/* Used by bce_probe() to identify the devices supported by this driver.    */
/****************************************************************************/
#define BCE_DEVDESC_MAX		64

static struct bce_type bce_devs[] = {
	/* BCM5706C Controllers and OEM boards. */
	{ BRCM_VENDORID, BRCM_DEVICEID_BCM5706,  HP_VENDORID, 0x3101,
		"HP NC370T Multifunction Gigabit Server Adapter" },
	{ BRCM_VENDORID, BRCM_DEVICEID_BCM5706,  HP_VENDORID, 0x3106,
		"HP NC370i Multifunction Gigabit Server Adapter" },
	{ BRCM_VENDORID, BRCM_DEVICEID_BCM5706,  PCI_ANY_ID,  PCI_ANY_ID,
		"Broadcom NetXtreme II BCM5706 1000Base-T" },

	/* BCM5706S controllers and OEM boards. */
	{ BRCM_VENDORID, BRCM_DEVICEID_BCM5706S, HP_VENDORID, 0x3102,
		"HP NC370F Multifunction Gigabit Server Adapter" },
	{ BRCM_VENDORID, BRCM_DEVICEID_BCM5706S, PCI_ANY_ID,  PCI_ANY_ID,
		"Broadcom NetXtreme II BCM5706 1000Base-SX" },

	/* BCM5708C controllers and OEM boards. */
	{ BRCM_VENDORID, BRCM_DEVICEID_BCM5708,  PCI_ANY_ID,  PCI_ANY_ID,
		"Broadcom NetXtreme II BCM5708 1000Base-T" },

	/* BCM5708S controllers and OEM boards. */
	{ BRCM_VENDORID, BRCM_DEVICEID_BCM5708S,  PCI_ANY_ID,  PCI_ANY_ID,
		"Broadcom NetXtreme II BCM5708S 1000Base-T" },
	{ 0, 0, 0, 0, NULL }
};


/****************************************************************************/
/* Supported Flash NVRAM device data.                                       */
/****************************************************************************/
static const struct flash_spec flash_table[] =
{
	/* Slow EEPROM */
	{0x00000000, 0x40830380, 0x009f0081, 0xa184a053, 0xaf000400,
	 1, SEEPROM_PAGE_BITS, SEEPROM_PAGE_SIZE,
	 SEEPROM_BYTE_ADDR_MASK, SEEPROM_TOTAL_SIZE,
	 "EEPROM - slow"},
	/* Expansion entry 0001 */
	{0x08000002, 0x4b808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 0001"},
	/* Saifun SA25F010 (non-buffered flash) */
	/* strap, cfg1, & write1 need updates */
	{0x04000001, 0x47808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE*2,
	 "Non-buffered flash (128kB)"},
	/* Saifun SA25F020 (non-buffered flash) */
	/* strap, cfg1, & write1 need updates */
	{0x0c000003, 0x4f808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE*4,
	 "Non-buffered flash (256kB)"},
	/* Expansion entry 0100 */
	{0x11000000, 0x53808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 0100"},
	/* Entry 0101: ST M45PE10 (non-buffered flash, TetonII B0) */
	{0x19000002, 0x5b808201, 0x000500db, 0x03840253, 0xaf020406,
	 0, ST_MICRO_FLASH_PAGE_BITS, ST_MICRO_FLASH_PAGE_SIZE,
	 ST_MICRO_FLASH_BYTE_ADDR_MASK, ST_MICRO_FLASH_BASE_TOTAL_SIZE*2,
	 "Entry 0101: ST M45PE10 (128kB non-bufferred)"},
	/* Entry 0110: ST M45PE20 (non-buffered flash)*/
	{0x15000001, 0x57808201, 0x000500db, 0x03840253, 0xaf020406,
	 0, ST_MICRO_FLASH_PAGE_BITS, ST_MICRO_FLASH_PAGE_SIZE,
	 ST_MICRO_FLASH_BYTE_ADDR_MASK, ST_MICRO_FLASH_BASE_TOTAL_SIZE*4,
	 "Entry 0110: ST M45PE20 (256kB non-bufferred)"},
	/* Saifun SA25F005 (non-buffered flash) */
	/* strap, cfg1, & write1 need updates */
	{0x1d000003, 0x5f808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, SAIFUN_FLASH_BASE_TOTAL_SIZE,
	 "Non-buffered flash (64kB)"},
	/* Fast EEPROM */
	{0x22000000, 0x62808380, 0x009f0081, 0xa184a053, 0xaf000400,
	 1, SEEPROM_PAGE_BITS, SEEPROM_PAGE_SIZE,
	 SEEPROM_BYTE_ADDR_MASK, SEEPROM_TOTAL_SIZE,
	 "EEPROM - fast"},
	/* Expansion entry 1001 */
	{0x2a000002, 0x6b808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1001"},
	/* Expansion entry 1010 */
	{0x26000001, 0x67808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1010"},
	/* ATMEL AT45DB011B (buffered flash) */
	{0x2e000003, 0x6e808273, 0x00570081, 0x68848353, 0xaf000400,
	 1, BUFFERED_FLASH_PAGE_BITS, BUFFERED_FLASH_PAGE_SIZE,
	 BUFFERED_FLASH_BYTE_ADDR_MASK, BUFFERED_FLASH_TOTAL_SIZE,
	 "Buffered flash (128kB)"},
	/* Expansion entry 1100 */
	{0x33000000, 0x73808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1100"},
	/* Expansion entry 1101 */
	{0x3b000002, 0x7b808201, 0x00050081, 0x03840253, 0xaf020406,
	 0, SAIFUN_FLASH_PAGE_BITS, SAIFUN_FLASH_PAGE_SIZE,
	 SAIFUN_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1101"},
	/* Ateml Expansion entry 1110 */
	{0x37000001, 0x76808273, 0x00570081, 0x68848353, 0xaf000400,
	 1, BUFFERED_FLASH_PAGE_BITS, BUFFERED_FLASH_PAGE_SIZE,
	 BUFFERED_FLASH_BYTE_ADDR_MASK, 0,
	 "Entry 1110 (Atmel)"},
	/* ATMEL AT45DB021B (buffered flash) */
	{0x3f000003, 0x7e808273, 0x00570081, 0x68848353, 0xaf000400,
	 1, BUFFERED_FLASH_PAGE_BITS, BUFFERED_FLASH_PAGE_SIZE,
	 BUFFERED_FLASH_BYTE_ADDR_MASK, BUFFERED_FLASH_TOTAL_SIZE*2,
	 "Buffered flash (256kB)"},
};


/****************************************************************************/
/* DragonFly device entry points.                                           */
/****************************************************************************/
static int	bce_probe(device_t);
static int	bce_attach(device_t);
static int	bce_detach(device_t);
static void	bce_shutdown(device_t);

/****************************************************************************/
/* BCE Debug Data Structure Dump Routines                                   */
/****************************************************************************/
#ifdef BCE_DEBUG
static void	bce_dump_mbuf(struct bce_softc *, struct mbuf *);
static void	bce_dump_tx_mbuf_chain(struct bce_softc *, int, int);
static void	bce_dump_rx_mbuf_chain(struct bce_softc *, int, int);
static void	bce_dump_txbd(struct bce_softc *, int, struct tx_bd *);
static void	bce_dump_rxbd(struct bce_softc *, int, struct rx_bd *);
static void	bce_dump_l2fhdr(struct bce_softc *, int,
				struct l2_fhdr *) __unused;
static void	bce_dump_tx_chain(struct bce_softc *, int, int);
static void	bce_dump_rx_chain(struct bce_softc *, int, int);
static void	bce_dump_status_block(struct bce_softc *);
static void	bce_dump_driver_state(struct bce_softc *);
static void	bce_dump_stats_block(struct bce_softc *) __unused;
static void	bce_dump_hw_state(struct bce_softc *);
static void	bce_dump_txp_state(struct bce_softc *);
static void	bce_dump_rxp_state(struct bce_softc *) __unused;
static void	bce_dump_tpat_state(struct bce_softc *) __unused;
static void	bce_freeze_controller(struct bce_softc *) __unused;
static void	bce_unfreeze_controller(struct bce_softc *) __unused;
static void	bce_breakpoint(struct bce_softc *);
#endif	/* BCE_DEBUG */


/****************************************************************************/
/* BCE Register/Memory Access Routines                                      */
/****************************************************************************/
static uint32_t	bce_reg_rd_ind(struct bce_softc *, uint32_t);
static void	bce_reg_wr_ind(struct bce_softc *, uint32_t, uint32_t);
static void	bce_ctx_wr(struct bce_softc *, uint32_t, uint32_t, uint32_t);
static int	bce_miibus_read_reg(device_t, int, int);
static int	bce_miibus_write_reg(device_t, int, int, int);
static void	bce_miibus_statchg(device_t);


/****************************************************************************/
/* BCE NVRAM Access Routines                                                */
/****************************************************************************/
static int	bce_acquire_nvram_lock(struct bce_softc *);
static int	bce_release_nvram_lock(struct bce_softc *);
static void	bce_enable_nvram_access(struct bce_softc *);
static void	bce_disable_nvram_access(struct bce_softc *);
static int	bce_nvram_read_dword(struct bce_softc *, uint32_t, uint8_t *,
				     uint32_t);
static int	bce_init_nvram(struct bce_softc *);
static int	bce_nvram_read(struct bce_softc *, uint32_t, uint8_t *, int);
static int	bce_nvram_test(struct bce_softc *);
#ifdef BCE_NVRAM_WRITE_SUPPORT
static int	bce_enable_nvram_write(struct bce_softc *);
static void	bce_disable_nvram_write(struct bce_softc *);
static int	bce_nvram_erase_page(struct bce_softc *, uint32_t);
static int	bce_nvram_write_dword(struct bce_softc *, uint32_t, uint8_t *,
				      uint32_t);
static int	bce_nvram_write(struct bce_softc *, uint32_t, uint8_t *,
				int) __unused;
#endif

/****************************************************************************/
/* BCE DMA Allocate/Free Routines                                           */
/****************************************************************************/
static int	bce_dma_alloc(struct bce_softc *);
static void	bce_dma_free(struct bce_softc *);
static void	bce_dma_map_addr(void *, bus_dma_segment_t *, int, int);

/****************************************************************************/
/* BCE Firmware Synchronization and Load                                    */
/****************************************************************************/
static int	bce_fw_sync(struct bce_softc *, uint32_t);
static void	bce_load_rv2p_fw(struct bce_softc *, uint32_t *,
				 uint32_t, uint32_t);
static void	bce_load_cpu_fw(struct bce_softc *, struct cpu_reg *,
				struct fw_info *);
static void	bce_init_cpus(struct bce_softc *);

static void	bce_stop(struct bce_softc *);
static int	bce_reset(struct bce_softc *, uint32_t);
static int	bce_chipinit(struct bce_softc *);
static int	bce_blockinit(struct bce_softc *);
static int	bce_newbuf_std(struct bce_softc *, uint16_t *, uint16_t *,
			       uint32_t *, int);
static void	bce_setup_rxdesc_std(struct bce_softc *, uint16_t, uint32_t *);

static int	bce_init_tx_chain(struct bce_softc *);
static int	bce_init_rx_chain(struct bce_softc *);
static void	bce_free_rx_chain(struct bce_softc *);
static void	bce_free_tx_chain(struct bce_softc *);

static int	bce_encap(struct bce_softc *, struct mbuf **);
static void	bce_start(struct ifnet *);
static int	bce_ioctl(struct ifnet *, u_long, caddr_t, struct ucred *);
static void	bce_watchdog(struct ifnet *);
static int	bce_ifmedia_upd(struct ifnet *);
static void	bce_ifmedia_sts(struct ifnet *, struct ifmediareq *);
static void	bce_init(void *);
static void	bce_mgmt_init(struct bce_softc *);

static void	bce_init_ctx(struct bce_softc *);
static void	bce_get_mac_addr(struct bce_softc *);
static void	bce_set_mac_addr(struct bce_softc *);
static void	bce_phy_intr(struct bce_softc *);
static void	bce_rx_intr(struct bce_softc *, int);
static void	bce_tx_intr(struct bce_softc *);
static void	bce_disable_intr(struct bce_softc *);
static void	bce_enable_intr(struct bce_softc *);

#ifdef DEVICE_POLLING
static void	bce_poll(struct ifnet *, enum poll_cmd, int);
#endif
static void	bce_intr(void *);
static void	bce_set_rx_mode(struct bce_softc *);
static void	bce_stats_update(struct bce_softc *);
static void	bce_tick(void *);
static void	bce_tick_serialized(struct bce_softc *);
static void	bce_add_sysctls(struct bce_softc *);

static void	bce_coal_change(struct bce_softc *);
static int	bce_sysctl_tx_bds_int(SYSCTL_HANDLER_ARGS);
static int	bce_sysctl_tx_bds(SYSCTL_HANDLER_ARGS);
static int	bce_sysctl_tx_ticks_int(SYSCTL_HANDLER_ARGS);
static int	bce_sysctl_tx_ticks(SYSCTL_HANDLER_ARGS);
static int	bce_sysctl_rx_bds_int(SYSCTL_HANDLER_ARGS);
static int	bce_sysctl_rx_bds(SYSCTL_HANDLER_ARGS);
static int	bce_sysctl_rx_ticks_int(SYSCTL_HANDLER_ARGS);
static int	bce_sysctl_rx_ticks(SYSCTL_HANDLER_ARGS);
static int	bce_sysctl_coal_change(SYSCTL_HANDLER_ARGS,
				       uint32_t *, uint32_t);

/*
 * NOTE:
 * Don't set bce_tx_ticks_int/bce_tx_ticks to 1023.  Linux's bnx2
 * takes 1023 as the TX ticks limit.  However, using 1023 will
 * cause 5708(B2) to generate extra interrupts (~2000/s) even when
 * there is _no_ network activity on the NIC.
 */
static uint32_t	bce_tx_bds_int = 255;		/* bcm: 20 */
static uint32_t	bce_tx_bds = 255;		/* bcm: 20 */
static uint32_t	bce_tx_ticks_int = 1022;	/* bcm: 80 */
static uint32_t	bce_tx_ticks = 1022;		/* bcm: 80 */
static uint32_t	bce_rx_bds_int = 128;		/* bcm: 6 */
static uint32_t	bce_rx_bds = 128;		/* bcm: 6 */
static uint32_t	bce_rx_ticks_int = 125;		/* bcm: 18 */
static uint32_t	bce_rx_ticks = 125;		/* bcm: 18 */

TUNABLE_INT("hw.bce.tx_bds_int", &bce_tx_bds_int);
TUNABLE_INT("hw.bce.tx_bds", &bce_tx_bds);
TUNABLE_INT("hw.bce.tx_ticks_int", &bce_tx_ticks_int);
TUNABLE_INT("hw.bce.tx_ticks", &bce_tx_ticks);
TUNABLE_INT("hw.bce.rx_bds_int", &bce_rx_bds_int);
TUNABLE_INT("hw.bce.rx_bds", &bce_rx_bds);
TUNABLE_INT("hw.bce.rx_ticks_int", &bce_rx_ticks_int);
TUNABLE_INT("hw.bce.rx_ticks", &bce_rx_ticks);

/****************************************************************************/
/* DragonFly device dispatch table.                                         */
/****************************************************************************/
static device_method_t bce_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		bce_probe),
	DEVMETHOD(device_attach,	bce_attach),
	DEVMETHOD(device_detach,	bce_detach),
	DEVMETHOD(device_shutdown,	bce_shutdown),

	/* bus interface */
	DEVMETHOD(bus_print_child,	bus_generic_print_child),
	DEVMETHOD(bus_driver_added,	bus_generic_driver_added),

	/* MII interface */
	DEVMETHOD(miibus_readreg,	bce_miibus_read_reg),
	DEVMETHOD(miibus_writereg,	bce_miibus_write_reg),
	DEVMETHOD(miibus_statchg,	bce_miibus_statchg),

	{ 0, 0 }
};

static driver_t bce_driver = {
	"bce",
	bce_methods,
	sizeof(struct bce_softc)
};

static devclass_t bce_devclass;


DECLARE_DUMMY_MODULE(if_xl);
MODULE_DEPEND(bce, miibus, 1, 1, 1);
DRIVER_MODULE(if_bce, pci, bce_driver, bce_devclass, 0, 0);
DRIVER_MODULE(miibus, bce, miibus_driver, miibus_devclass, 0, 0);


/****************************************************************************/
/* Device probe function.                                                   */
/*                                                                          */
/* Compares the device to the driver's list of supported devices and        */
/* reports back to the OS whether this is the right driver for the device.  */
/*                                                                          */
/* Returns:                                                                 */
/*   BUS_PROBE_DEFAULT on success, positive value on failure.               */
/****************************************************************************/
static int
bce_probe(device_t dev)
{
	struct bce_type *t;
	uint16_t vid, did, svid, sdid;

	/* Get the data for the device to be probed. */
	vid  = pci_get_vendor(dev);
	did  = pci_get_device(dev);
	svid = pci_get_subvendor(dev);
	sdid = pci_get_subdevice(dev);

	/* Look through the list of known devices for a match. */
	for (t = bce_devs; t->bce_name != NULL; ++t) {
		if (vid == t->bce_vid && did == t->bce_did && 
		    (svid == t->bce_svid || t->bce_svid == PCI_ANY_ID) &&
		    (sdid == t->bce_sdid || t->bce_sdid == PCI_ANY_ID)) {
		    	uint32_t revid = pci_read_config(dev, PCIR_REVID, 4);
			char *descbuf;

			descbuf = kmalloc(BCE_DEVDESC_MAX, M_TEMP, M_WAITOK);

			/* Print out the device identity. */
			ksnprintf(descbuf, BCE_DEVDESC_MAX, "%s (%c%d)",
				  t->bce_name,
				  ((revid & 0xf0) >> 4) + 'A', revid & 0xf);

			device_set_desc_copy(dev, descbuf);
			kfree(descbuf, M_TEMP);
			return 0;
		}
	}
	return ENXIO;
}


/****************************************************************************/
/* Device attach function.                                                  */
/*                                                                          */
/* Allocates device resources, performs secondary chip identification,      */
/* resets and initializes the hardware, and initializes driver instance     */
/* variables.                                                               */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success, positive value on failure.                               */
/****************************************************************************/
static int
bce_attach(device_t dev)
{
	struct bce_softc *sc = device_get_softc(dev);
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint32_t val;
	int rid, rc = 0;
#ifdef notyet
	int count;
#endif

	sc->bce_dev = dev;
	if_initname(ifp, device_get_name(dev), device_get_unit(dev));

	pci_enable_busmaster(dev);

	/* Allocate PCI memory resources. */
	rid = PCIR_BAR(0);
	sc->bce_res_mem = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid,
						 RF_ACTIVE | PCI_RF_DENSE);
	if (sc->bce_res_mem == NULL) {
		device_printf(dev, "PCI memory allocation failed\n");
		return ENXIO;
	}
	sc->bce_btag = rman_get_bustag(sc->bce_res_mem);
	sc->bce_bhandle = rman_get_bushandle(sc->bce_res_mem);

	/* Allocate PCI IRQ resources. */
#ifdef notyet
	count = pci_msi_count(dev);
	if (count == 1 && pci_alloc_msi(dev, &count) == 0) {
		rid = 1;
		sc->bce_flags |= BCE_USING_MSI_FLAG;
	} else
#endif
	rid = 0;
	sc->bce_res_irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
						 RF_SHAREABLE | RF_ACTIVE);
	if (sc->bce_res_irq == NULL) {
		device_printf(dev, "PCI map interrupt failed\n");
		rc = ENXIO;
		goto fail;
	}

	/*
	 * Configure byte swap and enable indirect register access.
	 * Rely on CPU to do target byte swapping on big endian systems.
	 * Access to registers outside of PCI configurtion space are not
	 * valid until this is done.
	 */
	pci_write_config(dev, BCE_PCICFG_MISC_CONFIG,
			 BCE_PCICFG_MISC_CONFIG_REG_WINDOW_ENA |
			 BCE_PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP, 4);

	/* Save ASIC revsion info. */
	sc->bce_chipid =  REG_RD(sc, BCE_MISC_ID);

	/* Weed out any non-production controller revisions. */
	switch(BCE_CHIP_ID(sc)) {
	case BCE_CHIP_ID_5706_A0:
	case BCE_CHIP_ID_5706_A1:
	case BCE_CHIP_ID_5708_A0:
	case BCE_CHIP_ID_5708_B0:
		device_printf(dev, "Unsupported chip id 0x%08x!\n",
			      BCE_CHIP_ID(sc));
		rc = ENODEV;
		goto fail;
	}

	/* 
	 * The embedded PCIe to PCI-X bridge (EPB) 
	 * in the 5708 cannot address memory above 
	 * 40 bits (E7_5708CB1_23043 & E6_5708SB1_23043). 
	 */
	if (BCE_CHIP_NUM(sc) == BCE_CHIP_NUM_5708)
		sc->max_bus_addr = BCE_BUS_SPACE_MAXADDR;
	else
		sc->max_bus_addr = BUS_SPACE_MAXADDR;

	/*
	 * Find the base address for shared memory access.
	 * Newer versions of bootcode use a signature and offset
	 * while older versions use a fixed address.
	 */
	val = REG_RD_IND(sc, BCE_SHM_HDR_SIGNATURE);
	if ((val & BCE_SHM_HDR_SIGNATURE_SIG_MASK) == BCE_SHM_HDR_SIGNATURE_SIG)
		sc->bce_shmem_base = REG_RD_IND(sc, BCE_SHM_HDR_ADDR_0);
	else
		sc->bce_shmem_base = HOST_VIEW_SHMEM_BASE;

	DBPRINT(sc, BCE_INFO, "bce_shmem_base = 0x%08X\n", sc->bce_shmem_base);

	/* Get PCI bus information (speed and type). */
	val = REG_RD(sc, BCE_PCICFG_MISC_STATUS);
	if (val & BCE_PCICFG_MISC_STATUS_PCIX_DET) {
		uint32_t clkreg;

		sc->bce_flags |= BCE_PCIX_FLAG;

		clkreg = REG_RD(sc, BCE_PCICFG_PCI_CLOCK_CONTROL_BITS) &
			 BCE_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET;
		switch (clkreg) {
		case BCE_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_133MHZ:
			sc->bus_speed_mhz = 133;
			break;

		case BCE_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_95MHZ:
			sc->bus_speed_mhz = 100;
			break;

		case BCE_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_66MHZ:
		case BCE_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_80MHZ:
			sc->bus_speed_mhz = 66;
			break;

		case BCE_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_48MHZ:
		case BCE_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_55MHZ:
			sc->bus_speed_mhz = 50;
			break;

		case BCE_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_LOW:
		case BCE_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_32MHZ:
		case BCE_PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_38MHZ:
			sc->bus_speed_mhz = 33;
			break;
		}
	} else {
		if (val & BCE_PCICFG_MISC_STATUS_M66EN)
			sc->bus_speed_mhz = 66;
		else
			sc->bus_speed_mhz = 33;
	}

	if (val & BCE_PCICFG_MISC_STATUS_32BIT_DET)
		sc->bce_flags |= BCE_PCI_32BIT_FLAG;

	device_printf(dev, "ASIC ID 0x%08X; Revision (%c%d); PCI%s %s %dMHz\n",
		      sc->bce_chipid,
		      ((BCE_CHIP_ID(sc) & 0xf000) >> 12) + 'A',
		      (BCE_CHIP_ID(sc) & 0x0ff0) >> 4,
		      (sc->bce_flags & BCE_PCIX_FLAG) ? "-X" : "",
		      (sc->bce_flags & BCE_PCI_32BIT_FLAG) ?
		      "32-bit" : "64-bit", sc->bus_speed_mhz);

	/* Reset the controller. */
	rc = bce_reset(sc, BCE_DRV_MSG_CODE_RESET);
	if (rc != 0)
		goto fail;

	/* Initialize the controller. */
	rc = bce_chipinit(sc);
	if (rc != 0) {
		device_printf(dev, "Controller initialization failed!\n");
		goto fail;
	}

	/* Perform NVRAM test. */
	rc = bce_nvram_test(sc);
	if (rc != 0) {
		device_printf(dev, "NVRAM test failed!\n");
		goto fail;
	}

	/* Fetch the permanent Ethernet MAC address. */
	bce_get_mac_addr(sc);

	/*
	 * Trip points control how many BDs
	 * should be ready before generating an
	 * interrupt while ticks control how long
	 * a BD can sit in the chain before
	 * generating an interrupt.  Set the default 
	 * values for the RX and TX rings.
	 */

#ifdef BCE_DRBUG
	/* Force more frequent interrupts. */
	sc->bce_tx_quick_cons_trip_int = 1;
	sc->bce_tx_quick_cons_trip     = 1;
	sc->bce_tx_ticks_int           = 0;
	sc->bce_tx_ticks               = 0;

	sc->bce_rx_quick_cons_trip_int = 1;
	sc->bce_rx_quick_cons_trip     = 1;
	sc->bce_rx_ticks_int           = 0;
	sc->bce_rx_ticks               = 0;
#else
	sc->bce_tx_quick_cons_trip_int = bce_tx_bds_int;
	sc->bce_tx_quick_cons_trip     = bce_tx_bds;
	sc->bce_tx_ticks_int           = bce_tx_ticks_int;
	sc->bce_tx_ticks               = bce_tx_ticks;

	sc->bce_rx_quick_cons_trip_int = bce_rx_bds_int;
	sc->bce_rx_quick_cons_trip     = bce_rx_bds;
	sc->bce_rx_ticks_int           = bce_rx_ticks_int;
	sc->bce_rx_ticks               = bce_rx_ticks;
#endif

	/* Update statistics once every second. */
	sc->bce_stats_ticks = 1000000 & 0xffff00;

	/*
	 * The copper based NetXtreme II controllers
	 * use an integrated PHY at address 1 while
	 * the SerDes controllers use a PHY at
	 * address 2.
	 */
	sc->bce_phy_addr = 1;

	if (BCE_CHIP_BOND_ID(sc) & BCE_CHIP_BOND_ID_SERDES_BIT) {
		sc->bce_phy_flags |= BCE_PHY_SERDES_FLAG;
		sc->bce_flags |= BCE_NO_WOL_FLAG;
		if (BCE_CHIP_NUM(sc) == BCE_CHIP_NUM_5708) {
			sc->bce_phy_addr = 2;
			val = REG_RD_IND(sc, sc->bce_shmem_base +
					 BCE_SHARED_HW_CFG_CONFIG);
			if (val & BCE_SHARED_HW_CFG_PHY_2_5G)
				sc->bce_phy_flags |= BCE_PHY_2_5G_CAPABLE_FLAG;
		}
	}

	/* Allocate DMA memory resources. */
	rc = bce_dma_alloc(sc);
	if (rc != 0) {
		device_printf(dev, "DMA resource allocation failed!\n");
		goto fail;
	}

	/* Initialize the ifnet interface. */
	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = bce_ioctl;
	ifp->if_start = bce_start;
	ifp->if_init = bce_init;
	ifp->if_watchdog = bce_watchdog;
#ifdef DEVICE_POLLING
	ifp->if_poll = bce_poll;
#endif
	ifp->if_mtu = ETHERMTU;
	ifp->if_hwassist = BCE_IF_HWASSIST;
	ifp->if_capabilities = BCE_IF_CAPABILITIES;
	ifp->if_capenable = ifp->if_capabilities;
	ifq_set_maxlen(&ifp->if_snd, USABLE_TX_BD);
	ifq_set_ready(&ifp->if_snd);

	if (sc->bce_phy_flags & BCE_PHY_2_5G_CAPABLE_FLAG)
		ifp->if_baudrate = IF_Gbps(2.5);
	else
		ifp->if_baudrate = IF_Gbps(1);

	/* Assume a standard 1500 byte MTU size for mbuf allocations. */
	sc->mbuf_alloc_size  = MCLBYTES;

	/* Look for our PHY. */
	rc = mii_phy_probe(dev, &sc->bce_miibus,
			   bce_ifmedia_upd, bce_ifmedia_sts);
	if (rc != 0) {
		device_printf(dev, "PHY probe failed!\n");
		goto fail;
	}

	/* Attach to the Ethernet interface list. */
	ether_ifattach(ifp, sc->eaddr, NULL);

	callout_init(&sc->bce_stat_ch);

	/* Hookup IRQ last. */
	rc = bus_setup_intr(dev, sc->bce_res_irq, INTR_MPSAFE, bce_intr, sc,
			    &sc->bce_intrhand, ifp->if_serializer);
	if (rc != 0) {
		device_printf(dev, "Failed to setup IRQ!\n");
		ether_ifdetach(ifp);
		goto fail;
	}

	ifp->if_cpuid = ithread_cpuid(rman_get_start(sc->bce_res_irq));
	KKASSERT(ifp->if_cpuid >= 0 && ifp->if_cpuid < ncpus);

	/* Print some important debugging info. */
	DBRUN(BCE_INFO, bce_dump_driver_state(sc));

	/* Add the supported sysctls to the kernel. */
	bce_add_sysctls(sc);

	/* Get the firmware running so IPMI still works */
	bce_mgmt_init(sc);

	return 0;
fail:
	bce_detach(dev);
	return(rc);
}


/****************************************************************************/
/* Device detach function.                                                  */
/*                                                                          */
/* Stops the controller, resets the controller, and releases resources.     */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success, positive value on failure.                               */
/****************************************************************************/
static int
bce_detach(device_t dev)
{
	struct bce_softc *sc = device_get_softc(dev);

	if (device_is_attached(dev)) {
		struct ifnet *ifp = &sc->arpcom.ac_if;

		/* Stop and reset the controller. */
		lwkt_serialize_enter(ifp->if_serializer);
		bce_stop(sc);
		bce_reset(sc, BCE_DRV_MSG_CODE_RESET);
		bus_teardown_intr(dev, sc->bce_res_irq, sc->bce_intrhand);
		lwkt_serialize_exit(ifp->if_serializer);

		ether_ifdetach(ifp);
	}

	/* If we have a child device on the MII bus remove it too. */
	if (sc->bce_miibus)
		device_delete_child(dev, sc->bce_miibus);
	bus_generic_detach(dev);

	if (sc->bce_res_irq != NULL) {
		bus_release_resource(dev, SYS_RES_IRQ,
			sc->bce_flags & BCE_USING_MSI_FLAG ? 1 : 0,
			sc->bce_res_irq);
	}

#ifdef notyet
	if (sc->bce_flags & BCE_USING_MSI_FLAG)
		pci_release_msi(dev);
#endif

	if (sc->bce_res_mem != NULL) {
		bus_release_resource(dev, SYS_RES_MEMORY, PCIR_BAR(0),
				     sc->bce_res_mem);
	}

	bce_dma_free(sc);

	if (sc->bce_sysctl_tree != NULL)
		sysctl_ctx_free(&sc->bce_sysctl_ctx);

	return 0;
}


/****************************************************************************/
/* Device shutdown function.                                                */
/*                                                                          */
/* Stops and resets the controller.                                         */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing                                                                */
/****************************************************************************/
static void
bce_shutdown(device_t dev)
{
	struct bce_softc *sc = device_get_softc(dev);
	struct ifnet *ifp = &sc->arpcom.ac_if;

	lwkt_serialize_enter(ifp->if_serializer);
	bce_stop(sc);
	bce_reset(sc, BCE_DRV_MSG_CODE_RESET);
	lwkt_serialize_exit(ifp->if_serializer);
}


/****************************************************************************/
/* Indirect register read.                                                  */
/*                                                                          */
/* Reads NetXtreme II registers using an index/data register pair in PCI    */
/* configuration space.  Using this mechanism avoids issues with posted     */
/* reads but is much slower than memory-mapped I/O.                         */
/*                                                                          */
/* Returns:                                                                 */
/*   The value of the register.                                             */
/****************************************************************************/
static uint32_t
bce_reg_rd_ind(struct bce_softc *sc, uint32_t offset)
{
	device_t dev = sc->bce_dev;

	pci_write_config(dev, BCE_PCICFG_REG_WINDOW_ADDRESS, offset, 4);
#ifdef BCE_DEBUG
	{
		uint32_t val;
		val = pci_read_config(dev, BCE_PCICFG_REG_WINDOW, 4);
		DBPRINT(sc, BCE_EXCESSIVE,
			"%s(); offset = 0x%08X, val = 0x%08X\n",
			__func__, offset, val);
		return val;
	}
#else
	return pci_read_config(dev, BCE_PCICFG_REG_WINDOW, 4);
#endif
}


/****************************************************************************/
/* Indirect register write.                                                 */
/*                                                                          */
/* Writes NetXtreme II registers using an index/data register pair in PCI   */
/* configuration space.  Using this mechanism avoids issues with posted     */
/* writes but is muchh slower than memory-mapped I/O.                       */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_reg_wr_ind(struct bce_softc *sc, uint32_t offset, uint32_t val)
{
	device_t dev = sc->bce_dev;

	DBPRINT(sc, BCE_EXCESSIVE, "%s(); offset = 0x%08X, val = 0x%08X\n",
		__func__, offset, val);

	pci_write_config(dev, BCE_PCICFG_REG_WINDOW_ADDRESS, offset, 4);
	pci_write_config(dev, BCE_PCICFG_REG_WINDOW, val, 4);
}


/****************************************************************************/
/* Context memory write.                                                    */
/*                                                                          */
/* The NetXtreme II controller uses context memory to track connection      */
/* information for L2 and higher network protocols.                         */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_ctx_wr(struct bce_softc *sc, uint32_t cid_addr, uint32_t offset,
	   uint32_t val)
{
	DBPRINT(sc, BCE_EXCESSIVE, "%s(); cid_addr = 0x%08X, offset = 0x%08X, "
		"val = 0x%08X\n", __func__, cid_addr, offset, val);

	offset += cid_addr;
	REG_WR(sc, BCE_CTX_DATA_ADR, offset);
	REG_WR(sc, BCE_CTX_DATA, val);
}


/****************************************************************************/
/* PHY register read.                                                       */
/*                                                                          */
/* Implements register reads on the MII bus.                                */
/*                                                                          */
/* Returns:                                                                 */
/*   The value of the register.                                             */
/****************************************************************************/
static int
bce_miibus_read_reg(device_t dev, int phy, int reg)
{
	struct bce_softc *sc = device_get_softc(dev);
	uint32_t val;
	int i;

	/* Make sure we are accessing the correct PHY address. */
	if (phy != sc->bce_phy_addr) {
		DBPRINT(sc, BCE_VERBOSE,
			"Invalid PHY address %d for PHY read!\n", phy);
		return 0;
	}

	if (sc->bce_phy_flags & BCE_PHY_INT_MODE_AUTO_POLLING_FLAG) {
		val = REG_RD(sc, BCE_EMAC_MDIO_MODE);
		val &= ~BCE_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(sc, BCE_EMAC_MDIO_MODE, val);
		REG_RD(sc, BCE_EMAC_MDIO_MODE);

		DELAY(40);
	}

	val = BCE_MIPHY(phy) | BCE_MIREG(reg) |
	      BCE_EMAC_MDIO_COMM_COMMAND_READ | BCE_EMAC_MDIO_COMM_DISEXT |
	      BCE_EMAC_MDIO_COMM_START_BUSY;
	REG_WR(sc, BCE_EMAC_MDIO_COMM, val);

	for (i = 0; i < BCE_PHY_TIMEOUT; i++) {
		DELAY(10);

		val = REG_RD(sc, BCE_EMAC_MDIO_COMM);
		if (!(val & BCE_EMAC_MDIO_COMM_START_BUSY)) {
			DELAY(5);

			val = REG_RD(sc, BCE_EMAC_MDIO_COMM);
			val &= BCE_EMAC_MDIO_COMM_DATA;
			break;
		}
	}

	if (val & BCE_EMAC_MDIO_COMM_START_BUSY) {
		if_printf(&sc->arpcom.ac_if,
			  "Error: PHY read timeout! phy = %d, reg = 0x%04X\n",
			  phy, reg);
		val = 0x0;
	} else {
		val = REG_RD(sc, BCE_EMAC_MDIO_COMM);
	}

	DBPRINT(sc, BCE_EXCESSIVE,
		"%s(): phy = %d, reg = 0x%04X, val = 0x%04X\n",
		__func__, phy, (uint16_t)reg & 0xffff, (uint16_t) val & 0xffff);

	if (sc->bce_phy_flags & BCE_PHY_INT_MODE_AUTO_POLLING_FLAG) {
		val = REG_RD(sc, BCE_EMAC_MDIO_MODE);
		val |= BCE_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(sc, BCE_EMAC_MDIO_MODE, val);
		REG_RD(sc, BCE_EMAC_MDIO_MODE);

		DELAY(40);
	}
	return (val & 0xffff);
}


/****************************************************************************/
/* PHY register write.                                                      */
/*                                                                          */
/* Implements register writes on the MII bus.                               */
/*                                                                          */
/* Returns:                                                                 */
/*   The value of the register.                                             */
/****************************************************************************/
static int
bce_miibus_write_reg(device_t dev, int phy, int reg, int val)
{
	struct bce_softc *sc = device_get_softc(dev);
	uint32_t val1;
	int i;

	/* Make sure we are accessing the correct PHY address. */
	if (phy != sc->bce_phy_addr) {
		DBPRINT(sc, BCE_WARN,
			"Invalid PHY address %d for PHY write!\n", phy);
		return(0);
	}

	DBPRINT(sc, BCE_EXCESSIVE,
		"%s(): phy = %d, reg = 0x%04X, val = 0x%04X\n",
		__func__, phy, (uint16_t)(reg & 0xffff),
		(uint16_t)(val & 0xffff));

	if (sc->bce_phy_flags & BCE_PHY_INT_MODE_AUTO_POLLING_FLAG) {
		val1 = REG_RD(sc, BCE_EMAC_MDIO_MODE);
		val1 &= ~BCE_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(sc, BCE_EMAC_MDIO_MODE, val1);
		REG_RD(sc, BCE_EMAC_MDIO_MODE);

		DELAY(40);
	}

	val1 = BCE_MIPHY(phy) | BCE_MIREG(reg) | val |
		BCE_EMAC_MDIO_COMM_COMMAND_WRITE |
		BCE_EMAC_MDIO_COMM_START_BUSY | BCE_EMAC_MDIO_COMM_DISEXT;
	REG_WR(sc, BCE_EMAC_MDIO_COMM, val1);

	for (i = 0; i < BCE_PHY_TIMEOUT; i++) {
		DELAY(10);

		val1 = REG_RD(sc, BCE_EMAC_MDIO_COMM);
		if (!(val1 & BCE_EMAC_MDIO_COMM_START_BUSY)) {
			DELAY(5);
			break;
		}
	}

	if (val1 & BCE_EMAC_MDIO_COMM_START_BUSY)
		if_printf(&sc->arpcom.ac_if, "PHY write timeout!\n");

	if (sc->bce_phy_flags & BCE_PHY_INT_MODE_AUTO_POLLING_FLAG) {
		val1 = REG_RD(sc, BCE_EMAC_MDIO_MODE);
		val1 |= BCE_EMAC_MDIO_MODE_AUTO_POLL;

		REG_WR(sc, BCE_EMAC_MDIO_MODE, val1);
		REG_RD(sc, BCE_EMAC_MDIO_MODE);

		DELAY(40);
	}
	return 0;
}


/****************************************************************************/
/* MII bus status change.                                                   */
/*                                                                          */
/* Called by the MII bus driver when the PHY establishes link to set the    */
/* MAC interface registers.                                                 */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_miibus_statchg(device_t dev)
{
	struct bce_softc *sc = device_get_softc(dev);
	struct mii_data *mii = device_get_softc(sc->bce_miibus);

	DBPRINT(sc, BCE_INFO, "mii_media_active = 0x%08X\n",
		mii->mii_media_active);

#ifdef BCE_DEBUG
	/* Decode the interface media flags. */
	if_printf(&sc->arpcom.ac_if, "Media: ( ");
	switch(IFM_TYPE(mii->mii_media_active)) {
	case IFM_ETHER:
		kprintf("Ethernet )");
		break;
	default:
		kprintf("Unknown )");
		break;
	}

	kprintf(" Media Options: ( ");
	switch(IFM_SUBTYPE(mii->mii_media_active)) {
	case IFM_AUTO:
		kprintf("Autoselect )");
		break;
	case IFM_MANUAL:
		kprintf("Manual )");
		break;
	case IFM_NONE:
		kprintf("None )");
		break;
	case IFM_10_T:
		kprintf("10Base-T )");
		break;
	case IFM_100_TX:
		kprintf("100Base-TX )");
		break;
	case IFM_1000_SX:
		kprintf("1000Base-SX )");
		break;
	case IFM_1000_T:
		kprintf("1000Base-T )");
		break;
	default:
		kprintf("Other )");
		break;
	}

	kprintf(" Global Options: (");
	if (mii->mii_media_active & IFM_FDX)
		kprintf(" FullDuplex");
	if (mii->mii_media_active & IFM_HDX)
		kprintf(" HalfDuplex");
	if (mii->mii_media_active & IFM_LOOP)
		kprintf(" Loopback");
	if (mii->mii_media_active & IFM_FLAG0)
		kprintf(" Flag0");
	if (mii->mii_media_active & IFM_FLAG1)
		kprintf(" Flag1");
	if (mii->mii_media_active & IFM_FLAG2)
		kprintf(" Flag2");
	kprintf(" )\n");
#endif

	BCE_CLRBIT(sc, BCE_EMAC_MODE, BCE_EMAC_MODE_PORT);

	/*
	 * Set MII or GMII interface based on the speed negotiated
	 * by the PHY.
	 */
	if (IFM_SUBTYPE(mii->mii_media_active) == IFM_1000_T || 
	    IFM_SUBTYPE(mii->mii_media_active) == IFM_1000_SX) {
		DBPRINT(sc, BCE_INFO, "Setting GMII interface.\n");
		BCE_SETBIT(sc, BCE_EMAC_MODE, BCE_EMAC_MODE_PORT_GMII);
	} else {
		DBPRINT(sc, BCE_INFO, "Setting MII interface.\n");
		BCE_SETBIT(sc, BCE_EMAC_MODE, BCE_EMAC_MODE_PORT_MII);
	}

	/*
	 * Set half or full duplex based on the duplicity negotiated
	 * by the PHY.
	 */
	if ((mii->mii_media_active & IFM_GMASK) == IFM_FDX) {
		DBPRINT(sc, BCE_INFO, "Setting Full-Duplex interface.\n");
		BCE_CLRBIT(sc, BCE_EMAC_MODE, BCE_EMAC_MODE_HALF_DUPLEX);
	} else {
		DBPRINT(sc, BCE_INFO, "Setting Half-Duplex interface.\n");
		BCE_SETBIT(sc, BCE_EMAC_MODE, BCE_EMAC_MODE_HALF_DUPLEX);
	}
}


/****************************************************************************/
/* Acquire NVRAM lock.                                                      */
/*                                                                          */
/* Before the NVRAM can be accessed the caller must acquire an NVRAM lock.  */
/* Locks 0 and 2 are reserved, lock 1 is used by firmware and lock 2 is     */
/* for use by the driver.                                                   */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success, positive value on failure.                               */
/****************************************************************************/
static int
bce_acquire_nvram_lock(struct bce_softc *sc)
{
	uint32_t val;
	int j;

	DBPRINT(sc, BCE_VERBOSE, "Acquiring NVRAM lock.\n");

	/* Request access to the flash interface. */
	REG_WR(sc, BCE_NVM_SW_ARB, BCE_NVM_SW_ARB_ARB_REQ_SET2);
	for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
		val = REG_RD(sc, BCE_NVM_SW_ARB);
		if (val & BCE_NVM_SW_ARB_ARB_ARB2)
			break;

		DELAY(5);
	}

	if (j >= NVRAM_TIMEOUT_COUNT) {
		DBPRINT(sc, BCE_WARN, "Timeout acquiring NVRAM lock!\n");
		return EBUSY;
	}
	return 0;
}


/****************************************************************************/
/* Release NVRAM lock.                                                      */
/*                                                                          */
/* When the caller is finished accessing NVRAM the lock must be released.   */
/* Locks 0 and 2 are reserved, lock 1 is used by firmware and lock 2 is     */
/* for use by the driver.                                                   */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success, positive value on failure.                               */
/****************************************************************************/
static int
bce_release_nvram_lock(struct bce_softc *sc)
{
	int j;
	uint32_t val;

	DBPRINT(sc, BCE_VERBOSE, "Releasing NVRAM lock.\n");

	/*
	 * Relinquish nvram interface.
	 */
	REG_WR(sc, BCE_NVM_SW_ARB, BCE_NVM_SW_ARB_ARB_REQ_CLR2);

	for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
		val = REG_RD(sc, BCE_NVM_SW_ARB);
		if (!(val & BCE_NVM_SW_ARB_ARB_ARB2))
			break;

		DELAY(5);
	}

	if (j >= NVRAM_TIMEOUT_COUNT) {
		DBPRINT(sc, BCE_WARN, "Timeout reeasing NVRAM lock!\n");
		return EBUSY;
	}
	return 0;
}


#ifdef BCE_NVRAM_WRITE_SUPPORT
/****************************************************************************/
/* Enable NVRAM write access.                                               */
/*                                                                          */
/* Before writing to NVRAM the caller must enable NVRAM writes.             */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success, positive value on failure.                               */
/****************************************************************************/
static int
bce_enable_nvram_write(struct bce_softc *sc)
{
	uint32_t val;

	DBPRINT(sc, BCE_VERBOSE, "Enabling NVRAM write.\n");

	val = REG_RD(sc, BCE_MISC_CFG);
	REG_WR(sc, BCE_MISC_CFG, val | BCE_MISC_CFG_NVM_WR_EN_PCI);

	if (!sc->bce_flash_info->buffered) {
		int j;

		REG_WR(sc, BCE_NVM_COMMAND, BCE_NVM_COMMAND_DONE);
		REG_WR(sc, BCE_NVM_COMMAND,
		       BCE_NVM_COMMAND_WREN | BCE_NVM_COMMAND_DOIT);

		for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
			DELAY(5);

			val = REG_RD(sc, BCE_NVM_COMMAND);
			if (val & BCE_NVM_COMMAND_DONE)
				break;
		}

		if (j >= NVRAM_TIMEOUT_COUNT) {
			DBPRINT(sc, BCE_WARN, "Timeout writing NVRAM!\n");
			return EBUSY;
		}
	}
	return 0;
}


/****************************************************************************/
/* Disable NVRAM write access.                                              */
/*                                                                          */
/* When the caller is finished writing to NVRAM write access must be        */
/* disabled.                                                                */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_disable_nvram_write(struct bce_softc *sc)
{
	uint32_t val;

	DBPRINT(sc, BCE_VERBOSE, "Disabling NVRAM write.\n");

	val = REG_RD(sc, BCE_MISC_CFG);
	REG_WR(sc, BCE_MISC_CFG, val & ~BCE_MISC_CFG_NVM_WR_EN);
}
#endif	/* BCE_NVRAM_WRITE_SUPPORT */


/****************************************************************************/
/* Enable NVRAM access.                                                     */
/*                                                                          */
/* Before accessing NVRAM for read or write operations the caller must      */
/* enabled NVRAM access.                                                    */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_enable_nvram_access(struct bce_softc *sc)
{
	uint32_t val;

	DBPRINT(sc, BCE_VERBOSE, "Enabling NVRAM access.\n");

	val = REG_RD(sc, BCE_NVM_ACCESS_ENABLE);
	/* Enable both bits, even on read. */
	REG_WR(sc, BCE_NVM_ACCESS_ENABLE,
	       val | BCE_NVM_ACCESS_ENABLE_EN | BCE_NVM_ACCESS_ENABLE_WR_EN);
}


/****************************************************************************/
/* Disable NVRAM access.                                                    */
/*                                                                          */
/* When the caller is finished accessing NVRAM access must be disabled.     */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_disable_nvram_access(struct bce_softc *sc)
{
	uint32_t val;

	DBPRINT(sc, BCE_VERBOSE, "Disabling NVRAM access.\n");

	val = REG_RD(sc, BCE_NVM_ACCESS_ENABLE);

	/* Disable both bits, even after read. */
	REG_WR(sc, BCE_NVM_ACCESS_ENABLE,
	       val & ~(BCE_NVM_ACCESS_ENABLE_EN | BCE_NVM_ACCESS_ENABLE_WR_EN));
}


#ifdef BCE_NVRAM_WRITE_SUPPORT
/****************************************************************************/
/* Erase NVRAM page before writing.                                         */
/*                                                                          */
/* Non-buffered flash parts require that a page be erased before it is      */
/* written.                                                                 */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success, positive value on failure.                               */
/****************************************************************************/
static int
bce_nvram_erase_page(struct bce_softc *sc, uint32_t offset)
{
	uint32_t cmd;
	int j;

	/* Buffered flash doesn't require an erase. */
	if (sc->bce_flash_info->buffered)
		return 0;

	DBPRINT(sc, BCE_VERBOSE, "Erasing NVRAM page.\n");

	/* Build an erase command. */
	cmd = BCE_NVM_COMMAND_ERASE | BCE_NVM_COMMAND_WR |
	      BCE_NVM_COMMAND_DOIT;

	/*
	 * Clear the DONE bit separately, set the NVRAM adress to erase,
	 * and issue the erase command.
	 */
	REG_WR(sc, BCE_NVM_COMMAND, BCE_NVM_COMMAND_DONE);
	REG_WR(sc, BCE_NVM_ADDR, offset & BCE_NVM_ADDR_NVM_ADDR_VALUE);
	REG_WR(sc, BCE_NVM_COMMAND, cmd);

	/* Wait for completion. */
	for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
		uint32_t val;

		DELAY(5);

		val = REG_RD(sc, BCE_NVM_COMMAND);
		if (val & BCE_NVM_COMMAND_DONE)
			break;
	}

	if (j >= NVRAM_TIMEOUT_COUNT) {
		DBPRINT(sc, BCE_WARN, "Timeout erasing NVRAM.\n");
		return EBUSY;
	}
	return 0;
}
#endif /* BCE_NVRAM_WRITE_SUPPORT */


/****************************************************************************/
/* Read a dword (32 bits) from NVRAM.                                       */
/*                                                                          */
/* Read a 32 bit word from NVRAM.  The caller is assumed to have already    */
/* obtained the NVRAM lock and enabled the controller for NVRAM access.     */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success and the 32 bit value read, positive value on failure.     */
/****************************************************************************/
static int
bce_nvram_read_dword(struct bce_softc *sc, uint32_t offset, uint8_t *ret_val,
		     uint32_t cmd_flags)
{
	uint32_t cmd;
	int i, rc = 0;

	/* Build the command word. */
	cmd = BCE_NVM_COMMAND_DOIT | cmd_flags;

	/* Calculate the offset for buffered flash. */
	if (sc->bce_flash_info->buffered) {
		offset = ((offset / sc->bce_flash_info->page_size) <<
			  sc->bce_flash_info->page_bits) +
			 (offset % sc->bce_flash_info->page_size);
	}

	/*
	 * Clear the DONE bit separately, set the address to read,
	 * and issue the read.
	 */
	REG_WR(sc, BCE_NVM_COMMAND, BCE_NVM_COMMAND_DONE);
	REG_WR(sc, BCE_NVM_ADDR, offset & BCE_NVM_ADDR_NVM_ADDR_VALUE);
	REG_WR(sc, BCE_NVM_COMMAND, cmd);

	/* Wait for completion. */
	for (i = 0; i < NVRAM_TIMEOUT_COUNT; i++) {
		uint32_t val;

		DELAY(5);

		val = REG_RD(sc, BCE_NVM_COMMAND);
		if (val & BCE_NVM_COMMAND_DONE) {
			val = REG_RD(sc, BCE_NVM_READ);

			val = be32toh(val);
			memcpy(ret_val, &val, 4);
			break;
		}
	}

	/* Check for errors. */
	if (i >= NVRAM_TIMEOUT_COUNT) {
		if_printf(&sc->arpcom.ac_if,
			  "Timeout error reading NVRAM at offset 0x%08X!\n",
			  offset);
		rc = EBUSY;
	}
	return rc;
}


#ifdef BCE_NVRAM_WRITE_SUPPORT
/****************************************************************************/
/* Write a dword (32 bits) to NVRAM.                                        */
/*                                                                          */
/* Write a 32 bit word to NVRAM.  The caller is assumed to have already     */
/* obtained the NVRAM lock, enabled the controller for NVRAM access, and    */
/* enabled NVRAM write access.                                              */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success, positive value on failure.                               */
/****************************************************************************/
static int
bce_nvram_write_dword(struct bce_softc *sc, uint32_t offset, uint8_t *val,
		      uint32_t cmd_flags)
{
	uint32_t cmd, val32;
	int j;

	/* Build the command word. */
	cmd = BCE_NVM_COMMAND_DOIT | BCE_NVM_COMMAND_WR | cmd_flags;

	/* Calculate the offset for buffered flash. */
	if (sc->bce_flash_info->buffered) {
		offset = ((offset / sc->bce_flash_info->page_size) <<
			  sc->bce_flash_info->page_bits) +
			 (offset % sc->bce_flash_info->page_size);
	}

	/*
	 * Clear the DONE bit separately, convert NVRAM data to big-endian,
	 * set the NVRAM address to write, and issue the write command
	 */
	REG_WR(sc, BCE_NVM_COMMAND, BCE_NVM_COMMAND_DONE);
	memcpy(&val32, val, 4);
	val32 = htobe32(val32);
	REG_WR(sc, BCE_NVM_WRITE, val32);
	REG_WR(sc, BCE_NVM_ADDR, offset & BCE_NVM_ADDR_NVM_ADDR_VALUE);
	REG_WR(sc, BCE_NVM_COMMAND, cmd);

	/* Wait for completion. */
	for (j = 0; j < NVRAM_TIMEOUT_COUNT; j++) {
		DELAY(5);

		if (REG_RD(sc, BCE_NVM_COMMAND) & BCE_NVM_COMMAND_DONE)
			break;
	}
	if (j >= NVRAM_TIMEOUT_COUNT) {
		if_printf(&sc->arpcom.ac_if,
			  "Timeout error writing NVRAM at offset 0x%08X\n",
			  offset);
		return EBUSY;
	}
	return 0;
}
#endif /* BCE_NVRAM_WRITE_SUPPORT */


/****************************************************************************/
/* Initialize NVRAM access.                                                 */
/*                                                                          */
/* Identify the NVRAM device in use and prepare the NVRAM interface to      */
/* access that device.                                                      */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success, positive value on failure.                               */
/****************************************************************************/
static int
bce_init_nvram(struct bce_softc *sc)
{
	uint32_t val;
	int j, entry_count, rc = 0;
	const struct flash_spec *flash;

	DBPRINT(sc, BCE_VERBOSE_RESET, "Entering %s()\n", __func__);

	/* Determine the selected interface. */
	val = REG_RD(sc, BCE_NVM_CFG1);

	entry_count = sizeof(flash_table) / sizeof(struct flash_spec);

	/*
	 * Flash reconfiguration is required to support additional
	 * NVRAM devices not directly supported in hardware.
	 * Check if the flash interface was reconfigured
	 * by the bootcode.
	 */

	if (val & 0x40000000) {
		/* Flash interface reconfigured by bootcode. */

		DBPRINT(sc, BCE_INFO_LOAD, 
			"%s(): Flash WAS reconfigured.\n", __func__);

		for (j = 0, flash = flash_table; j < entry_count;
		     j++, flash++) {
			if ((val & FLASH_BACKUP_STRAP_MASK) ==
			    (flash->config1 & FLASH_BACKUP_STRAP_MASK)) {
				sc->bce_flash_info = flash;
				break;
			}
		}
	} else {
		/* Flash interface not yet reconfigured. */
		uint32_t mask;

		DBPRINT(sc, BCE_INFO_LOAD, 
			"%s(): Flash was NOT reconfigured.\n", __func__);

		if (val & (1 << 23))
			mask = FLASH_BACKUP_STRAP_MASK;
		else
			mask = FLASH_STRAP_MASK;

		/* Look for the matching NVRAM device configuration data. */
		for (j = 0, flash = flash_table; j < entry_count;
		     j++, flash++) {
			/* Check if the device matches any of the known devices. */
			if ((val & mask) == (flash->strapping & mask)) {
				/* Found a device match. */
				sc->bce_flash_info = flash;

				/* Request access to the flash interface. */
				rc = bce_acquire_nvram_lock(sc);
				if (rc != 0)
					return rc;

				/* Reconfigure the flash interface. */
				bce_enable_nvram_access(sc);
				REG_WR(sc, BCE_NVM_CFG1, flash->config1);
				REG_WR(sc, BCE_NVM_CFG2, flash->config2);
				REG_WR(sc, BCE_NVM_CFG3, flash->config3);
				REG_WR(sc, BCE_NVM_WRITE1, flash->write1);
				bce_disable_nvram_access(sc);
				bce_release_nvram_lock(sc);
				break;
			}
		}
	}

	/* Check if a matching device was found. */
	if (j == entry_count) {
		sc->bce_flash_info = NULL;
		if_printf(&sc->arpcom.ac_if, "Unknown Flash NVRAM found!\n");
		rc = ENODEV;
	}

	/* Write the flash config data to the shared memory interface. */
	val = REG_RD_IND(sc, sc->bce_shmem_base + BCE_SHARED_HW_CFG_CONFIG2) &
	      BCE_SHARED_HW_CFG2_NVM_SIZE_MASK;
	if (val)
		sc->bce_flash_size = val;
	else
		sc->bce_flash_size = sc->bce_flash_info->total_size;

	DBPRINT(sc, BCE_INFO_LOAD, "%s() flash->total_size = 0x%08X\n",
		__func__, sc->bce_flash_info->total_size);

	DBPRINT(sc, BCE_VERBOSE_RESET, "Exiting %s()\n", __func__);

	return rc;
}


/****************************************************************************/
/* Read an arbitrary range of data from NVRAM.                              */
/*                                                                          */
/* Prepares the NVRAM interface for access and reads the requested data     */
/* into the supplied buffer.                                                */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success and the data read, positive value on failure.             */
/****************************************************************************/
static int
bce_nvram_read(struct bce_softc *sc, uint32_t offset, uint8_t *ret_buf,
	       int buf_size)
{
	uint32_t cmd_flags, offset32, len32, extra;
	int rc = 0;

	if (buf_size == 0)
		return 0;

	/* Request access to the flash interface. */
	rc = bce_acquire_nvram_lock(sc);
	if (rc != 0)
		return rc;

	/* Enable access to flash interface */
	bce_enable_nvram_access(sc);

	len32 = buf_size;
	offset32 = offset;
	extra = 0;

	cmd_flags = 0;

	/* XXX should we release nvram lock if read_dword() fails? */
	if (offset32 & 3) {
		uint8_t buf[4];
		uint32_t pre_len;

		offset32 &= ~3;
		pre_len = 4 - (offset & 3);

		if (pre_len >= len32) {
			pre_len = len32;
			cmd_flags = BCE_NVM_COMMAND_FIRST | BCE_NVM_COMMAND_LAST;
		} else {
			cmd_flags = BCE_NVM_COMMAND_FIRST;
		}

		rc = bce_nvram_read_dword(sc, offset32, buf, cmd_flags);
		if (rc)
			return rc;

		memcpy(ret_buf, buf + (offset & 3), pre_len);

		offset32 += 4;
		ret_buf += pre_len;
		len32 -= pre_len;
	}

	if (len32 & 3) {
		extra = 4 - (len32 & 3);
		len32 = (len32 + 4) & ~3;
	}

	if (len32 == 4) {
		uint8_t buf[4];

		if (cmd_flags)
			cmd_flags = BCE_NVM_COMMAND_LAST;
		else
			cmd_flags = BCE_NVM_COMMAND_FIRST |
				    BCE_NVM_COMMAND_LAST;

		rc = bce_nvram_read_dword(sc, offset32, buf, cmd_flags);

		memcpy(ret_buf, buf, 4 - extra);
	} else if (len32 > 0) {
		uint8_t buf[4];

		/* Read the first word. */
		if (cmd_flags)
			cmd_flags = 0;
		else
			cmd_flags = BCE_NVM_COMMAND_FIRST;

		rc = bce_nvram_read_dword(sc, offset32, ret_buf, cmd_flags);

		/* Advance to the next dword. */
		offset32 += 4;
		ret_buf += 4;
		len32 -= 4;

		while (len32 > 4 && rc == 0) {
			rc = bce_nvram_read_dword(sc, offset32, ret_buf, 0);

			/* Advance to the next dword. */
			offset32 += 4;
			ret_buf += 4;
			len32 -= 4;
		}

		if (rc)
			return rc;

		cmd_flags = BCE_NVM_COMMAND_LAST;
		rc = bce_nvram_read_dword(sc, offset32, buf, cmd_flags);

		memcpy(ret_buf, buf, 4 - extra);
	}

	/* Disable access to flash interface and release the lock. */
	bce_disable_nvram_access(sc);
	bce_release_nvram_lock(sc);

	return rc;
}


#ifdef BCE_NVRAM_WRITE_SUPPORT
/****************************************************************************/
/* Write an arbitrary range of data from NVRAM.                             */
/*                                                                          */
/* Prepares the NVRAM interface for write access and writes the requested   */
/* data from the supplied buffer.  The caller is responsible for            */
/* calculating any appropriate CRCs.                                        */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success, positive value on failure.                               */
/****************************************************************************/
static int
bce_nvram_write(struct bce_softc *sc, uint32_t offset, uint8_t *data_buf,
		int buf_size)
{
	uint32_t written, offset32, len32;
	uint8_t *buf, start[4], end[4];
	int rc = 0;
	int align_start, align_end;

	buf = data_buf;
	offset32 = offset;
	len32 = buf_size;
	align_end = 0;
	align_start = (offset32 & 3);

	if (align_start) {
		offset32 &= ~3;
		len32 += align_start;
		rc = bce_nvram_read(sc, offset32, start, 4);
		if (rc)
			return rc;
	}

	if (len32 & 3) {
	       	if (len32 > 4 || !align_start) {
			align_end = 4 - (len32 & 3);
			len32 += align_end;
			rc = bce_nvram_read(sc, offset32 + len32 - 4, end, 4);
			if (rc)
				return rc;
		}
	}

	if (align_start || align_end) {
		buf = kmalloc(len32, M_DEVBUF, M_NOWAIT);
		if (buf == NULL)
			return ENOMEM;
		if (align_start)
			memcpy(buf, start, 4);
		if (align_end)
			memcpy(buf + len32 - 4, end, 4);
		memcpy(buf + align_start, data_buf, buf_size);
	}

	written = 0;
	while (written < len32 && rc == 0) {
		uint32_t page_start, page_end, data_start, data_end;
		uint32_t addr, cmd_flags;
		int i;
		uint8_t flash_buffer[264];

		/* Find the page_start addr */
		page_start = offset32 + written;
		page_start -= (page_start % sc->bce_flash_info->page_size);
		/* Find the page_end addr */
		page_end = page_start + sc->bce_flash_info->page_size;
		/* Find the data_start addr */
		data_start = (written == 0) ? offset32 : page_start;
		/* Find the data_end addr */
		data_end = (page_end > offset32 + len32) ? (offset32 + len32)
							 : page_end;

		/* Request access to the flash interface. */
		rc = bce_acquire_nvram_lock(sc);
		if (rc != 0)
			goto nvram_write_end;

		/* Enable access to flash interface */
		bce_enable_nvram_access(sc);

		cmd_flags = BCE_NVM_COMMAND_FIRST;
		if (sc->bce_flash_info->buffered == 0) {
			int j;

			/*
			 * Read the whole page into the buffer
			 * (non-buffer flash only)
			 */
			for (j = 0; j < sc->bce_flash_info->page_size; j += 4) {
				if (j == (sc->bce_flash_info->page_size - 4))
					cmd_flags |= BCE_NVM_COMMAND_LAST;

				rc = bce_nvram_read_dword(sc, page_start + j,
							  &flash_buffer[j],
							  cmd_flags);
				if (rc)
					goto nvram_write_end;

				cmd_flags = 0;
			}
		}

		/* Enable writes to flash interface (unlock write-protect) */
		rc = bce_enable_nvram_write(sc);
		if (rc != 0)
			goto nvram_write_end;

		/* Erase the page */
		rc = bce_nvram_erase_page(sc, page_start);
		if (rc != 0)
			goto nvram_write_end;

		/* Re-enable the write again for the actual write */
		bce_enable_nvram_write(sc);

		/* Loop to write back the buffer data from page_start to
		 * data_start */
		i = 0;
		if (sc->bce_flash_info->buffered == 0) {
			for (addr = page_start; addr < data_start;
			     addr += 4, i += 4) {
				rc = bce_nvram_write_dword(sc, addr,
							   &flash_buffer[i],
							   cmd_flags);
				if (rc != 0)
					goto nvram_write_end;

				cmd_flags = 0;
			}
		}

		/* Loop to write the new data from data_start to data_end */
		for (addr = data_start; addr < data_end; addr += 4, i++) {
			if (addr == page_end - 4 ||
			    (sc->bce_flash_info->buffered &&
			     addr == data_end - 4))
				cmd_flags |= BCE_NVM_COMMAND_LAST;

			rc = bce_nvram_write_dword(sc, addr, buf, cmd_flags);
			if (rc != 0)
				goto nvram_write_end;

			cmd_flags = 0;
			buf += 4;
		}

		/* Loop to write back the buffer data from data_end
		 * to page_end */
		if (sc->bce_flash_info->buffered == 0) {
			for (addr = data_end; addr < page_end;
			     addr += 4, i += 4) {
				if (addr == page_end-4)
					cmd_flags = BCE_NVM_COMMAND_LAST;

				rc = bce_nvram_write_dword(sc, addr,
					&flash_buffer[i], cmd_flags);
				if (rc != 0)
					goto nvram_write_end;

				cmd_flags = 0;
			}
		}

		/* Disable writes to flash interface (lock write-protect) */
		bce_disable_nvram_write(sc);

		/* Disable access to flash interface */
		bce_disable_nvram_access(sc);
		bce_release_nvram_lock(sc);

		/* Increment written */
		written += data_end - data_start;
	}

nvram_write_end:
	if (align_start || align_end)
		kfree(buf, M_DEVBUF);
	return rc;
}
#endif /* BCE_NVRAM_WRITE_SUPPORT */


/****************************************************************************/
/* Verifies that NVRAM is accessible and contains valid data.               */
/*                                                                          */
/* Reads the configuration data from NVRAM and verifies that the CRC is     */
/* correct.                                                                 */
/*                                                                          */
/* Returns:                                                                 */
/*   0 on success, positive value on failure.                               */
/****************************************************************************/
static int
bce_nvram_test(struct bce_softc *sc)
{
	uint32_t buf[BCE_NVRAM_SIZE / 4];
	uint32_t magic, csum;
	uint8_t *data = (uint8_t *)buf;
	int rc = 0;

	/*
	 * Check that the device NVRAM is valid by reading
	 * the magic value at offset 0.
	 */
	rc = bce_nvram_read(sc, 0, data, 4);
	if (rc != 0)
		return rc;

	magic = be32toh(buf[0]);
	if (magic != BCE_NVRAM_MAGIC) {
		if_printf(&sc->arpcom.ac_if,
			  "Invalid NVRAM magic value! Expected: 0x%08X, "
			  "Found: 0x%08X\n", BCE_NVRAM_MAGIC, magic);
		return ENODEV;
	}

	/*
	 * Verify that the device NVRAM includes valid
	 * configuration data.
	 */
	rc = bce_nvram_read(sc, 0x100, data, BCE_NVRAM_SIZE);
	if (rc != 0)
		return rc;

	csum = ether_crc32_le(data, 0x100);
	if (csum != BCE_CRC32_RESIDUAL) {
		if_printf(&sc->arpcom.ac_if,
			  "Invalid Manufacturing Information NVRAM CRC! "
			  "Expected: 0x%08X, Found: 0x%08X\n",
			  BCE_CRC32_RESIDUAL, csum);
		return ENODEV;
	}

	csum = ether_crc32_le(data + 0x100, 0x100);
	if (csum != BCE_CRC32_RESIDUAL) {
		if_printf(&sc->arpcom.ac_if,
			  "Invalid Feature Configuration Information "
			  "NVRAM CRC! Expected: 0x%08X, Found: 08%08X\n",
			  BCE_CRC32_RESIDUAL, csum);
		rc = ENODEV;
	}
	return rc;
}


/****************************************************************************/
/* Free any DMA memory owned by the driver.                                 */
/*                                                                          */
/* Scans through each data structre that requires DMA memory and frees      */
/* the memory if allocated.                                                 */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dma_free(struct bce_softc *sc)
{
	int i;

	/* Destroy the status block. */
	if (sc->status_tag != NULL) {
		if (sc->status_block != NULL) {
			bus_dmamap_unload(sc->status_tag, sc->status_map);
			bus_dmamem_free(sc->status_tag, sc->status_block,
					sc->status_map);
		}
		bus_dma_tag_destroy(sc->status_tag);
	}


	/* Destroy the statistics block. */
	if (sc->stats_tag != NULL) {
		if (sc->stats_block != NULL) {
			bus_dmamap_unload(sc->stats_tag, sc->stats_map);
			bus_dmamem_free(sc->stats_tag, sc->stats_block,
					sc->stats_map);
		}
		bus_dma_tag_destroy(sc->stats_tag);
	}

	/* Destroy the TX buffer descriptor DMA stuffs. */
	if (sc->tx_bd_chain_tag != NULL) {
		for (i = 0; i < TX_PAGES; i++) {
			if (sc->tx_bd_chain[i] != NULL) {
				bus_dmamap_unload(sc->tx_bd_chain_tag,
						  sc->tx_bd_chain_map[i]);
				bus_dmamem_free(sc->tx_bd_chain_tag,
						sc->tx_bd_chain[i],
						sc->tx_bd_chain_map[i]);
			}
		}
		bus_dma_tag_destroy(sc->tx_bd_chain_tag);
	}

	/* Destroy the RX buffer descriptor DMA stuffs. */
	if (sc->rx_bd_chain_tag != NULL) {
		for (i = 0; i < RX_PAGES; i++) {
			if (sc->rx_bd_chain[i] != NULL) {
				bus_dmamap_unload(sc->rx_bd_chain_tag,
						  sc->rx_bd_chain_map[i]);
				bus_dmamem_free(sc->rx_bd_chain_tag,
						sc->rx_bd_chain[i],
						sc->rx_bd_chain_map[i]);
			}
		}
		bus_dma_tag_destroy(sc->rx_bd_chain_tag);
	}

	/* Destroy the TX mbuf DMA stuffs. */
	if (sc->tx_mbuf_tag != NULL) {
		for (i = 0; i < TOTAL_TX_BD; i++) {
			/* Must have been unloaded in bce_stop() */
			KKASSERT(sc->tx_mbuf_ptr[i] == NULL);
			bus_dmamap_destroy(sc->tx_mbuf_tag,
					   sc->tx_mbuf_map[i]);
		}
		bus_dma_tag_destroy(sc->tx_mbuf_tag);
	}

	/* Destroy the RX mbuf DMA stuffs. */
	if (sc->rx_mbuf_tag != NULL) {
		for (i = 0; i < TOTAL_RX_BD; i++) {
			/* Must have been unloaded in bce_stop() */
			KKASSERT(sc->rx_mbuf_ptr[i] == NULL);
			bus_dmamap_destroy(sc->rx_mbuf_tag,
					   sc->rx_mbuf_map[i]);
		}
		bus_dmamap_destroy(sc->rx_mbuf_tag, sc->rx_mbuf_tmpmap);
		bus_dma_tag_destroy(sc->rx_mbuf_tag);
	}

	/* Destroy the parent tag */
	if (sc->parent_tag != NULL)
		bus_dma_tag_destroy(sc->parent_tag);
}


/****************************************************************************/
/* Get DMA memory from the OS.                                              */
/*                                                                          */
/* Validates that the OS has provided DMA buffers in response to a          */
/* bus_dmamap_load() call and saves the physical address of those buffers.  */
/* When the callback is used the OS will return 0 for the mapping function  */
/* (bus_dmamap_load()) so we use the value of map_arg->maxsegs to pass any  */
/* failures back to the caller.                                             */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dma_map_addr(void *arg, bus_dma_segment_t *segs, int nseg, int error)
{
	bus_addr_t *busaddr = arg;

	/*
	 * Simulate a mapping failure.
	 * XXX not correct.
	 */
	DBRUNIF(DB_RANDOMTRUE(bce_debug_dma_map_addr_failure),
		kprintf("bce: %s(%d): Simulating DMA mapping error.\n",
			__FILE__, __LINE__);
		error = ENOMEM);
		
	/* Check for an error and signal the caller that an error occurred. */
	if (error)
		return;

	KASSERT(nseg == 1, ("only one segment is allowed\n"));
	*busaddr = segs->ds_addr;
}


/****************************************************************************/
/* Allocate any DMA memory needed by the driver.                            */
/*                                                                          */
/* Allocates DMA memory needed for the various global structures needed by  */
/* hardware.                                                                */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_dma_alloc(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	int i, j, rc = 0;
	bus_addr_t busaddr;

	/*
	 * Allocate the parent bus DMA tag appropriate for PCI.
	 */
	rc = bus_dma_tag_create(NULL, 1, BCE_DMA_BOUNDARY,
				sc->max_bus_addr, BUS_SPACE_MAXADDR,
				NULL, NULL,
				BUS_SPACE_MAXSIZE_32BIT, 0,
				BUS_SPACE_MAXSIZE_32BIT,
				0, &sc->parent_tag);
	if (rc != 0) {
		if_printf(ifp, "Could not allocate parent DMA tag!\n");
		return rc;
	}

	/*
	 * Allocate status block.
	 */
	sc->status_block = bus_dmamem_coherent_any(sc->parent_tag,
				BCE_DMA_ALIGN, BCE_STATUS_BLK_SZ,
				BUS_DMA_WAITOK | BUS_DMA_ZERO,
				&sc->status_tag, &sc->status_map,
				&sc->status_block_paddr);
	if (sc->status_block == NULL) {
		if_printf(ifp, "Could not allocate status block!\n");
		return ENOMEM;
	}

	/*
	 * Allocate statistics block.
	 */
	sc->stats_block = bus_dmamem_coherent_any(sc->parent_tag,
				BCE_DMA_ALIGN, BCE_STATS_BLK_SZ,
				BUS_DMA_WAITOK | BUS_DMA_ZERO,
				&sc->stats_tag, &sc->stats_map,
				&sc->stats_block_paddr);
	if (sc->stats_block == NULL) {
		if_printf(ifp, "Could not allocate statistics block!\n");
		return ENOMEM;
	}

	/*
	 * Create a DMA tag for the TX buffer descriptor chain,
	 * allocate and clear the  memory, and fetch the
	 * physical address of the block.
	 */
	rc = bus_dma_tag_create(sc->parent_tag, BCM_PAGE_SIZE, 0,
				BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR,
				NULL, NULL,
				BCE_TX_CHAIN_PAGE_SZ, 1, BCE_TX_CHAIN_PAGE_SZ,
				0, &sc->tx_bd_chain_tag);
	if (rc != 0) {
		if_printf(ifp, "Could not allocate "
			  "TX descriptor chain DMA tag!\n");
		return rc;
	}

	for (i = 0; i < TX_PAGES; i++) {
		rc = bus_dmamem_alloc(sc->tx_bd_chain_tag,
				      (void **)&sc->tx_bd_chain[i],
				      BUS_DMA_WAITOK | BUS_DMA_ZERO |
				      BUS_DMA_COHERENT,
				      &sc->tx_bd_chain_map[i]);
		if (rc != 0) {
			if_printf(ifp, "Could not allocate %dth TX descriptor "
				  "chain DMA memory!\n", i);
			return rc;
		}

		rc = bus_dmamap_load(sc->tx_bd_chain_tag,
				     sc->tx_bd_chain_map[i],
				     sc->tx_bd_chain[i], BCE_TX_CHAIN_PAGE_SZ,
				     bce_dma_map_addr, &busaddr,
				     BUS_DMA_WAITOK);
		if (rc != 0) {
			if (rc == EINPROGRESS) {
				panic("%s coherent memory loading "
				      "is still in progress!", ifp->if_xname);
			}
			if_printf(ifp, "Could not map %dth TX descriptor "
				  "chain DMA memory!\n", i);
			bus_dmamem_free(sc->tx_bd_chain_tag,
					sc->tx_bd_chain[i],
					sc->tx_bd_chain_map[i]);
			sc->tx_bd_chain[i] = NULL;
			return rc;
		}

		sc->tx_bd_chain_paddr[i] = busaddr;
		/* DRC - Fix for 64 bit systems. */
		DBPRINT(sc, BCE_INFO, "tx_bd_chain_paddr[%d] = 0x%08X\n", 
			i, (uint32_t)sc->tx_bd_chain_paddr[i]);
	}

	/* Create a DMA tag for TX mbufs. */
	rc = bus_dma_tag_create(sc->parent_tag, 1, 0,
				BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR,
				NULL, NULL,
				/* BCE_MAX_JUMBO_ETHER_MTU_VLAN */MCLBYTES,
				BCE_MAX_SEGMENTS, MCLBYTES,
				BUS_DMA_ALLOCNOW | BUS_DMA_WAITOK |
				BUS_DMA_ONEBPAGE,
				&sc->tx_mbuf_tag);
	if (rc != 0) {
		if_printf(ifp, "Could not allocate TX mbuf DMA tag!\n");
		return rc;
	}

	/* Create DMA maps for the TX mbufs clusters. */
	for (i = 0; i < TOTAL_TX_BD; i++) {
		rc = bus_dmamap_create(sc->tx_mbuf_tag,
				       BUS_DMA_WAITOK | BUS_DMA_ONEBPAGE,
				       &sc->tx_mbuf_map[i]);
		if (rc != 0) {
			for (j = 0; j < i; ++j) {
				bus_dmamap_destroy(sc->tx_mbuf_tag,
						   sc->tx_mbuf_map[i]);
			}
			bus_dma_tag_destroy(sc->tx_mbuf_tag);
			sc->tx_mbuf_tag = NULL;

			if_printf(ifp, "Unable to create "
				  "%dth TX mbuf DMA map!\n", i);
			return rc;
		}
	}

	/*
	 * Create a DMA tag for the RX buffer descriptor chain,
	 * allocate and clear the  memory, and fetch the physical
	 * address of the blocks.
	 */
	rc = bus_dma_tag_create(sc->parent_tag, BCM_PAGE_SIZE, 0,
				BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR,
				NULL, NULL,
				BCE_RX_CHAIN_PAGE_SZ, 1, BCE_RX_CHAIN_PAGE_SZ,
				0, &sc->rx_bd_chain_tag);
	if (rc != 0) {
		if_printf(ifp, "Could not allocate "
			  "RX descriptor chain DMA tag!\n");
		return rc;
	}

	for (i = 0; i < RX_PAGES; i++) {
		rc = bus_dmamem_alloc(sc->rx_bd_chain_tag,
				      (void **)&sc->rx_bd_chain[i],
				      BUS_DMA_WAITOK | BUS_DMA_ZERO |
				      BUS_DMA_COHERENT,
				      &sc->rx_bd_chain_map[i]);
		if (rc != 0) {
			if_printf(ifp, "Could not allocate %dth RX descriptor "
				  "chain DMA memory!\n", i);
			return rc;
		}

		rc = bus_dmamap_load(sc->rx_bd_chain_tag,
				     sc->rx_bd_chain_map[i],
				     sc->rx_bd_chain[i], BCE_RX_CHAIN_PAGE_SZ,
				     bce_dma_map_addr, &busaddr,
				     BUS_DMA_WAITOK);
		if (rc != 0) {
			if (rc == EINPROGRESS) {
				panic("%s coherent memory loading "
				      "is still in progress!", ifp->if_xname);
			}
			if_printf(ifp, "Could not map %dth RX descriptor "
				  "chain DMA memory!\n", i);
			bus_dmamem_free(sc->rx_bd_chain_tag,
					sc->rx_bd_chain[i],
					sc->rx_bd_chain_map[i]);
			sc->rx_bd_chain[i] = NULL;
			return rc;
		}

		sc->rx_bd_chain_paddr[i] = busaddr;
		/* DRC - Fix for 64 bit systems. */
		DBPRINT(sc, BCE_INFO, "rx_bd_chain_paddr[%d] = 0x%08X\n",
			i, (uint32_t)sc->rx_bd_chain_paddr[i]);
	}

	/* Create a DMA tag for RX mbufs. */
	rc = bus_dma_tag_create(sc->parent_tag, 1, 0,
				BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR,
				NULL, NULL,
				MCLBYTES, 1, MCLBYTES,
				BUS_DMA_ALLOCNOW | BUS_DMA_WAITOK,
				&sc->rx_mbuf_tag);
	if (rc != 0) {
		if_printf(ifp, "Could not allocate RX mbuf DMA tag!\n");
		return rc;
	}

	/* Create tmp DMA map for RX mbuf clusters. */
	rc = bus_dmamap_create(sc->rx_mbuf_tag, BUS_DMA_WAITOK,
			       &sc->rx_mbuf_tmpmap);
	if (rc != 0) {
		bus_dma_tag_destroy(sc->rx_mbuf_tag);
		sc->rx_mbuf_tag = NULL;

		if_printf(ifp, "Could not create RX mbuf tmp DMA map!\n");
		return rc;
	}

	/* Create DMA maps for the RX mbuf clusters. */
	for (i = 0; i < TOTAL_RX_BD; i++) {
		rc = bus_dmamap_create(sc->rx_mbuf_tag, BUS_DMA_WAITOK,
				       &sc->rx_mbuf_map[i]);
		if (rc != 0) {
			for (j = 0; j < i; ++j) {
				bus_dmamap_destroy(sc->rx_mbuf_tag,
						   sc->rx_mbuf_map[j]);
			}
			bus_dma_tag_destroy(sc->rx_mbuf_tag);
			sc->rx_mbuf_tag = NULL;

			if_printf(ifp, "Unable to create "
				  "%dth RX mbuf DMA map!\n", i);
			return rc;
		}
	}
	return 0;
}


/****************************************************************************/
/* Firmware synchronization.                                                */
/*                                                                          */
/* Before performing certain events such as a chip reset, synchronize with  */
/* the firmware first.                                                      */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_fw_sync(struct bce_softc *sc, uint32_t msg_data)
{
	int i, rc = 0;
	uint32_t val;

	/* Don't waste any time if we've timed out before. */
	if (sc->bce_fw_timed_out)
		return EBUSY;

	/* Increment the message sequence number. */
	sc->bce_fw_wr_seq++;
	msg_data |= sc->bce_fw_wr_seq;

 	DBPRINT(sc, BCE_VERBOSE, "bce_fw_sync(): msg_data = 0x%08X\n", msg_data);

	/* Send the message to the bootcode driver mailbox. */
	REG_WR_IND(sc, sc->bce_shmem_base + BCE_DRV_MB, msg_data);

	/* Wait for the bootcode to acknowledge the message. */
	for (i = 0; i < FW_ACK_TIME_OUT_MS; i++) {
		/* Check for a response in the bootcode firmware mailbox. */
		val = REG_RD_IND(sc, sc->bce_shmem_base + BCE_FW_MB);
		if ((val & BCE_FW_MSG_ACK) == (msg_data & BCE_DRV_MSG_SEQ))
			break;
		DELAY(1000);
	}

	/* If we've timed out, tell the bootcode that we've stopped waiting. */
	if ((val & BCE_FW_MSG_ACK) != (msg_data & BCE_DRV_MSG_SEQ) &&
	    (msg_data & BCE_DRV_MSG_DATA) != BCE_DRV_MSG_DATA_WAIT0) {
		if_printf(&sc->arpcom.ac_if,
			  "Firmware synchronization timeout! "
			  "msg_data = 0x%08X\n", msg_data);

		msg_data &= ~BCE_DRV_MSG_CODE;
		msg_data |= BCE_DRV_MSG_CODE_FW_TIMEOUT;

		REG_WR_IND(sc, sc->bce_shmem_base + BCE_DRV_MB, msg_data);

		sc->bce_fw_timed_out = 1;
		rc = EBUSY;
	}
	return rc;
}


/****************************************************************************/
/* Load Receive Virtual 2 Physical (RV2P) processor firmware.               */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_load_rv2p_fw(struct bce_softc *sc, uint32_t *rv2p_code,
		 uint32_t rv2p_code_len, uint32_t rv2p_proc)
{
	int i;
	uint32_t val;

	for (i = 0; i < rv2p_code_len; i += 8) {
		REG_WR(sc, BCE_RV2P_INSTR_HIGH, *rv2p_code);
		rv2p_code++;
		REG_WR(sc, BCE_RV2P_INSTR_LOW, *rv2p_code);
		rv2p_code++;

		if (rv2p_proc == RV2P_PROC1) {
			val = (i / 8) | BCE_RV2P_PROC1_ADDR_CMD_RDWR;
			REG_WR(sc, BCE_RV2P_PROC1_ADDR_CMD, val);
		} else {
			val = (i / 8) | BCE_RV2P_PROC2_ADDR_CMD_RDWR;
			REG_WR(sc, BCE_RV2P_PROC2_ADDR_CMD, val);
		}
	}

	/* Reset the processor, un-stall is done later. */
	if (rv2p_proc == RV2P_PROC1)
		REG_WR(sc, BCE_RV2P_COMMAND, BCE_RV2P_COMMAND_PROC1_RESET);
	else
		REG_WR(sc, BCE_RV2P_COMMAND, BCE_RV2P_COMMAND_PROC2_RESET);
}


/****************************************************************************/
/* Load RISC processor firmware.                                            */
/*                                                                          */
/* Loads firmware from the file if_bcefw.h into the scratchpad memory       */
/* associated with a particular processor.                                  */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_load_cpu_fw(struct bce_softc *sc, struct cpu_reg *cpu_reg,
		struct fw_info *fw)
{
	uint32_t offset, val;
	int j;

	/* Halt the CPU. */
	val = REG_RD_IND(sc, cpu_reg->mode);
	val |= cpu_reg->mode_value_halt;
	REG_WR_IND(sc, cpu_reg->mode, val);
	REG_WR_IND(sc, cpu_reg->state, cpu_reg->state_value_clear);

	/* Load the Text area. */
	offset = cpu_reg->spad_base + (fw->text_addr - cpu_reg->mips_view_base);
	if (fw->text) {
		for (j = 0; j < (fw->text_len / 4); j++, offset += 4)
			REG_WR_IND(sc, offset, fw->text[j]);
	}

	/* Load the Data area. */
	offset = cpu_reg->spad_base + (fw->data_addr - cpu_reg->mips_view_base);
	if (fw->data) {
		for (j = 0; j < (fw->data_len / 4); j++, offset += 4)
			REG_WR_IND(sc, offset, fw->data[j]);
	}

	/* Load the SBSS area. */
	offset = cpu_reg->spad_base + (fw->sbss_addr - cpu_reg->mips_view_base);
	if (fw->sbss) {
		for (j = 0; j < (fw->sbss_len / 4); j++, offset += 4)
			REG_WR_IND(sc, offset, fw->sbss[j]);
	}

	/* Load the BSS area. */
	offset = cpu_reg->spad_base + (fw->bss_addr - cpu_reg->mips_view_base);
	if (fw->bss) {
		for (j = 0; j < (fw->bss_len/4); j++, offset += 4)
			REG_WR_IND(sc, offset, fw->bss[j]);
	}

	/* Load the Read-Only area. */
	offset = cpu_reg->spad_base +
		(fw->rodata_addr - cpu_reg->mips_view_base);
	if (fw->rodata) {
		for (j = 0; j < (fw->rodata_len / 4); j++, offset += 4)
			REG_WR_IND(sc, offset, fw->rodata[j]);
	}

	/* Clear the pre-fetch instruction. */
	REG_WR_IND(sc, cpu_reg->inst, 0);
	REG_WR_IND(sc, cpu_reg->pc, fw->start_addr);

	/* Start the CPU. */
	val = REG_RD_IND(sc, cpu_reg->mode);
	val &= ~cpu_reg->mode_value_halt;
	REG_WR_IND(sc, cpu_reg->state, cpu_reg->state_value_clear);
	REG_WR_IND(sc, cpu_reg->mode, val);
}


/****************************************************************************/
/* Initialize the RV2P, RX, TX, TPAT, and COM CPUs.                         */
/*                                                                          */
/* Loads the firmware for each CPU and starts the CPU.                      */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_init_cpus(struct bce_softc *sc)
{
	struct cpu_reg cpu_reg;
	struct fw_info fw;

	/* Initialize the RV2P processor. */
	bce_load_rv2p_fw(sc, bce_rv2p_proc1, sizeof(bce_rv2p_proc1), RV2P_PROC1);
	bce_load_rv2p_fw(sc, bce_rv2p_proc2, sizeof(bce_rv2p_proc2), RV2P_PROC2);

	/* Initialize the RX Processor. */
	cpu_reg.mode = BCE_RXP_CPU_MODE;
	cpu_reg.mode_value_halt = BCE_RXP_CPU_MODE_SOFT_HALT;
	cpu_reg.mode_value_sstep = BCE_RXP_CPU_MODE_STEP_ENA;
	cpu_reg.state = BCE_RXP_CPU_STATE;
	cpu_reg.state_value_clear = 0xffffff;
	cpu_reg.gpr0 = BCE_RXP_CPU_REG_FILE;
	cpu_reg.evmask = BCE_RXP_CPU_EVENT_MASK;
	cpu_reg.pc = BCE_RXP_CPU_PROGRAM_COUNTER;
	cpu_reg.inst = BCE_RXP_CPU_INSTRUCTION;
	cpu_reg.bp = BCE_RXP_CPU_HW_BREAKPOINT;
	cpu_reg.spad_base = BCE_RXP_SCRATCH;
	cpu_reg.mips_view_base = 0x8000000;

	fw.ver_major = bce_RXP_b06FwReleaseMajor;
	fw.ver_minor = bce_RXP_b06FwReleaseMinor;
	fw.ver_fix = bce_RXP_b06FwReleaseFix;
	fw.start_addr = bce_RXP_b06FwStartAddr;

	fw.text_addr = bce_RXP_b06FwTextAddr;
	fw.text_len = bce_RXP_b06FwTextLen;
	fw.text_index = 0;
	fw.text = bce_RXP_b06FwText;

	fw.data_addr = bce_RXP_b06FwDataAddr;
	fw.data_len = bce_RXP_b06FwDataLen;
	fw.data_index = 0;
	fw.data = bce_RXP_b06FwData;

	fw.sbss_addr = bce_RXP_b06FwSbssAddr;
	fw.sbss_len = bce_RXP_b06FwSbssLen;
	fw.sbss_index = 0;
	fw.sbss = bce_RXP_b06FwSbss;

	fw.bss_addr = bce_RXP_b06FwBssAddr;
	fw.bss_len = bce_RXP_b06FwBssLen;
	fw.bss_index = 0;
	fw.bss = bce_RXP_b06FwBss;

	fw.rodata_addr = bce_RXP_b06FwRodataAddr;
	fw.rodata_len = bce_RXP_b06FwRodataLen;
	fw.rodata_index = 0;
	fw.rodata = bce_RXP_b06FwRodata;

	DBPRINT(sc, BCE_INFO_RESET, "Loading RX firmware.\n");
	bce_load_cpu_fw(sc, &cpu_reg, &fw);

	/* Initialize the TX Processor. */
	cpu_reg.mode = BCE_TXP_CPU_MODE;
	cpu_reg.mode_value_halt = BCE_TXP_CPU_MODE_SOFT_HALT;
	cpu_reg.mode_value_sstep = BCE_TXP_CPU_MODE_STEP_ENA;
	cpu_reg.state = BCE_TXP_CPU_STATE;
	cpu_reg.state_value_clear = 0xffffff;
	cpu_reg.gpr0 = BCE_TXP_CPU_REG_FILE;
	cpu_reg.evmask = BCE_TXP_CPU_EVENT_MASK;
	cpu_reg.pc = BCE_TXP_CPU_PROGRAM_COUNTER;
	cpu_reg.inst = BCE_TXP_CPU_INSTRUCTION;
	cpu_reg.bp = BCE_TXP_CPU_HW_BREAKPOINT;
	cpu_reg.spad_base = BCE_TXP_SCRATCH;
	cpu_reg.mips_view_base = 0x8000000;

	fw.ver_major = bce_TXP_b06FwReleaseMajor;
	fw.ver_minor = bce_TXP_b06FwReleaseMinor;
	fw.ver_fix = bce_TXP_b06FwReleaseFix;
	fw.start_addr = bce_TXP_b06FwStartAddr;

	fw.text_addr = bce_TXP_b06FwTextAddr;
	fw.text_len = bce_TXP_b06FwTextLen;
	fw.text_index = 0;
	fw.text = bce_TXP_b06FwText;

	fw.data_addr = bce_TXP_b06FwDataAddr;
	fw.data_len = bce_TXP_b06FwDataLen;
	fw.data_index = 0;
	fw.data = bce_TXP_b06FwData;

	fw.sbss_addr = bce_TXP_b06FwSbssAddr;
	fw.sbss_len = bce_TXP_b06FwSbssLen;
	fw.sbss_index = 0;
	fw.sbss = bce_TXP_b06FwSbss;

	fw.bss_addr = bce_TXP_b06FwBssAddr;
	fw.bss_len = bce_TXP_b06FwBssLen;
	fw.bss_index = 0;
	fw.bss = bce_TXP_b06FwBss;

	fw.rodata_addr = bce_TXP_b06FwRodataAddr;
	fw.rodata_len = bce_TXP_b06FwRodataLen;
	fw.rodata_index = 0;
	fw.rodata = bce_TXP_b06FwRodata;

	DBPRINT(sc, BCE_INFO_RESET, "Loading TX firmware.\n");
	bce_load_cpu_fw(sc, &cpu_reg, &fw);

	/* Initialize the TX Patch-up Processor. */
	cpu_reg.mode = BCE_TPAT_CPU_MODE;
	cpu_reg.mode_value_halt = BCE_TPAT_CPU_MODE_SOFT_HALT;
	cpu_reg.mode_value_sstep = BCE_TPAT_CPU_MODE_STEP_ENA;
	cpu_reg.state = BCE_TPAT_CPU_STATE;
	cpu_reg.state_value_clear = 0xffffff;
	cpu_reg.gpr0 = BCE_TPAT_CPU_REG_FILE;
	cpu_reg.evmask = BCE_TPAT_CPU_EVENT_MASK;
	cpu_reg.pc = BCE_TPAT_CPU_PROGRAM_COUNTER;
	cpu_reg.inst = BCE_TPAT_CPU_INSTRUCTION;
	cpu_reg.bp = BCE_TPAT_CPU_HW_BREAKPOINT;
	cpu_reg.spad_base = BCE_TPAT_SCRATCH;
	cpu_reg.mips_view_base = 0x8000000;

	fw.ver_major = bce_TPAT_b06FwReleaseMajor;
	fw.ver_minor = bce_TPAT_b06FwReleaseMinor;
	fw.ver_fix = bce_TPAT_b06FwReleaseFix;
	fw.start_addr = bce_TPAT_b06FwStartAddr;

	fw.text_addr = bce_TPAT_b06FwTextAddr;
	fw.text_len = bce_TPAT_b06FwTextLen;
	fw.text_index = 0;
	fw.text = bce_TPAT_b06FwText;

	fw.data_addr = bce_TPAT_b06FwDataAddr;
	fw.data_len = bce_TPAT_b06FwDataLen;
	fw.data_index = 0;
	fw.data = bce_TPAT_b06FwData;

	fw.sbss_addr = bce_TPAT_b06FwSbssAddr;
	fw.sbss_len = bce_TPAT_b06FwSbssLen;
	fw.sbss_index = 0;
	fw.sbss = bce_TPAT_b06FwSbss;

	fw.bss_addr = bce_TPAT_b06FwBssAddr;
	fw.bss_len = bce_TPAT_b06FwBssLen;
	fw.bss_index = 0;
	fw.bss = bce_TPAT_b06FwBss;

	fw.rodata_addr = bce_TPAT_b06FwRodataAddr;
	fw.rodata_len = bce_TPAT_b06FwRodataLen;
	fw.rodata_index = 0;
	fw.rodata = bce_TPAT_b06FwRodata;

	DBPRINT(sc, BCE_INFO_RESET, "Loading TPAT firmware.\n");
	bce_load_cpu_fw(sc, &cpu_reg, &fw);

	/* Initialize the Completion Processor. */
	cpu_reg.mode = BCE_COM_CPU_MODE;
	cpu_reg.mode_value_halt = BCE_COM_CPU_MODE_SOFT_HALT;
	cpu_reg.mode_value_sstep = BCE_COM_CPU_MODE_STEP_ENA;
	cpu_reg.state = BCE_COM_CPU_STATE;
	cpu_reg.state_value_clear = 0xffffff;
	cpu_reg.gpr0 = BCE_COM_CPU_REG_FILE;
	cpu_reg.evmask = BCE_COM_CPU_EVENT_MASK;
	cpu_reg.pc = BCE_COM_CPU_PROGRAM_COUNTER;
	cpu_reg.inst = BCE_COM_CPU_INSTRUCTION;
	cpu_reg.bp = BCE_COM_CPU_HW_BREAKPOINT;
	cpu_reg.spad_base = BCE_COM_SCRATCH;
	cpu_reg.mips_view_base = 0x8000000;

	fw.ver_major = bce_COM_b06FwReleaseMajor;
	fw.ver_minor = bce_COM_b06FwReleaseMinor;
	fw.ver_fix = bce_COM_b06FwReleaseFix;
	fw.start_addr = bce_COM_b06FwStartAddr;

	fw.text_addr = bce_COM_b06FwTextAddr;
	fw.text_len = bce_COM_b06FwTextLen;
	fw.text_index = 0;
	fw.text = bce_COM_b06FwText;

	fw.data_addr = bce_COM_b06FwDataAddr;
	fw.data_len = bce_COM_b06FwDataLen;
	fw.data_index = 0;
	fw.data = bce_COM_b06FwData;

	fw.sbss_addr = bce_COM_b06FwSbssAddr;
	fw.sbss_len = bce_COM_b06FwSbssLen;
	fw.sbss_index = 0;
	fw.sbss = bce_COM_b06FwSbss;

	fw.bss_addr = bce_COM_b06FwBssAddr;
	fw.bss_len = bce_COM_b06FwBssLen;
	fw.bss_index = 0;
	fw.bss = bce_COM_b06FwBss;

	fw.rodata_addr = bce_COM_b06FwRodataAddr;
	fw.rodata_len = bce_COM_b06FwRodataLen;
	fw.rodata_index = 0;
	fw.rodata = bce_COM_b06FwRodata;

	DBPRINT(sc, BCE_INFO_RESET, "Loading COM firmware.\n");
	bce_load_cpu_fw(sc, &cpu_reg, &fw);
}


/****************************************************************************/
/* Initialize context memory.                                               */
/*                                                                          */
/* Clears the memory associated with each Context ID (CID).                 */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_init_ctx(struct bce_softc *sc)
{
	uint32_t vcid = 96;

	while (vcid) {
		uint32_t vcid_addr, pcid_addr, offset;
		int i;

		vcid--;

   		vcid_addr = GET_CID_ADDR(vcid);
		pcid_addr = vcid_addr;

		for (i = 0; i < (CTX_SIZE / PHY_CTX_SIZE); i++) {
			vcid_addr += (i << PHY_CTX_SHIFT);
			pcid_addr += (i << PHY_CTX_SHIFT);

			REG_WR(sc, BCE_CTX_VIRT_ADDR, vcid_addr);
			REG_WR(sc, BCE_CTX_PAGE_TBL, pcid_addr);

			/* Zero out the context. */
			for (offset = 0; offset < PHY_CTX_SIZE; offset += 4)
				CTX_WR(sc, vcid_addr, offset, 0);
		}
	}
}


/****************************************************************************/
/* Fetch the permanent MAC address of the controller.                       */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_get_mac_addr(struct bce_softc *sc)
{
	uint32_t mac_lo = 0, mac_hi = 0;

	/*
	 * The NetXtreme II bootcode populates various NIC
	 * power-on and runtime configuration items in a
	 * shared memory area.  The factory configured MAC
	 * address is available from both NVRAM and the
	 * shared memory area so we'll read the value from
	 * shared memory for speed.
	 */

	mac_hi = REG_RD_IND(sc, sc->bce_shmem_base + BCE_PORT_HW_CFG_MAC_UPPER);
	mac_lo = REG_RD_IND(sc, sc->bce_shmem_base + BCE_PORT_HW_CFG_MAC_LOWER);

	if (mac_lo == 0 && mac_hi == 0) {
		if_printf(&sc->arpcom.ac_if, "Invalid Ethernet address!\n");
	} else {
		sc->eaddr[0] = (u_char)(mac_hi >> 8);
		sc->eaddr[1] = (u_char)(mac_hi >> 0);
		sc->eaddr[2] = (u_char)(mac_lo >> 24);
		sc->eaddr[3] = (u_char)(mac_lo >> 16);
		sc->eaddr[4] = (u_char)(mac_lo >> 8);
		sc->eaddr[5] = (u_char)(mac_lo >> 0);
	}

	DBPRINT(sc, BCE_INFO, "Permanent Ethernet address = %6D\n", sc->eaddr, ":");
}


/****************************************************************************/
/* Program the MAC address.                                                 */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_set_mac_addr(struct bce_softc *sc)
{
	const uint8_t *mac_addr = sc->eaddr;
	uint32_t val;

	DBPRINT(sc, BCE_INFO, "Setting Ethernet address = %6D\n",
		sc->eaddr, ":");

	val = (mac_addr[0] << 8) | mac_addr[1];
	REG_WR(sc, BCE_EMAC_MAC_MATCH0, val);

	val = (mac_addr[2] << 24) |
	      (mac_addr[3] << 16) |
	      (mac_addr[4] << 8) |
	      mac_addr[5];
	REG_WR(sc, BCE_EMAC_MAC_MATCH1, val);
}


/****************************************************************************/
/* Stop the controller.                                                     */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_stop(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	struct mii_data *mii = device_get_softc(sc->bce_miibus);
	struct ifmedia_entry *ifm;
	int mtmp, itmp;

	ASSERT_SERIALIZED(ifp->if_serializer);

	callout_stop(&sc->bce_stat_ch);

	/* Disable the transmit/receive blocks. */
	REG_WR(sc, BCE_MISC_ENABLE_CLR_BITS, 0x5ffffff);
	REG_RD(sc, BCE_MISC_ENABLE_CLR_BITS);
	DELAY(20);

	bce_disable_intr(sc);

	/* Tell firmware that the driver is going away. */
	bce_reset(sc, BCE_DRV_MSG_CODE_SUSPEND_NO_WOL);

	/* Free the RX lists. */
	bce_free_rx_chain(sc);

	/* Free TX buffers. */
	bce_free_tx_chain(sc);

	/*
	 * Isolate/power down the PHY, but leave the media selection
	 * unchanged so that things will be put back to normal when
	 * we bring the interface back up.
	 *
	 * 'mii' may be NULL if bce_stop() is called by bce_detach().
	 */
	if (mii != NULL) {
		itmp = ifp->if_flags;
		ifp->if_flags |= IFF_UP;
		ifm = mii->mii_media.ifm_cur;
		mtmp = ifm->ifm_media;
		ifm->ifm_media = IFM_ETHER | IFM_NONE;
		mii_mediachg(mii);
		ifm->ifm_media = mtmp;
		ifp->if_flags = itmp;
	}

	sc->bce_link = 0;
	sc->bce_coalchg_mask = 0;

	ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);
	ifp->if_timer = 0;

	bce_mgmt_init(sc);
}


static int
bce_reset(struct bce_softc *sc, uint32_t reset_code)
{
	uint32_t val;
	int i, rc = 0;

	/* Wait for pending PCI transactions to complete. */
	REG_WR(sc, BCE_MISC_ENABLE_CLR_BITS,
	       BCE_MISC_ENABLE_CLR_BITS_TX_DMA_ENABLE |
	       BCE_MISC_ENABLE_CLR_BITS_DMA_ENGINE_ENABLE |
	       BCE_MISC_ENABLE_CLR_BITS_RX_DMA_ENABLE |
	       BCE_MISC_ENABLE_CLR_BITS_HOST_COALESCE_ENABLE);
	val = REG_RD(sc, BCE_MISC_ENABLE_CLR_BITS);
	DELAY(5);

	/* Assume bootcode is running. */
	sc->bce_fw_timed_out = 0;

	/* Give the firmware a chance to prepare for the reset. */
	rc = bce_fw_sync(sc, BCE_DRV_MSG_DATA_WAIT0 | reset_code);
	if (rc) {
		if_printf(&sc->arpcom.ac_if,
			  "Firmware is not ready for reset\n");
		return rc;
	}

	/* Set a firmware reminder that this is a soft reset. */
	REG_WR_IND(sc, sc->bce_shmem_base + BCE_DRV_RESET_SIGNATURE,
		   BCE_DRV_RESET_SIGNATURE_MAGIC);

	/* Dummy read to force the chip to complete all current transactions. */
	val = REG_RD(sc, BCE_MISC_ID);

	/* Chip reset. */
	val = BCE_PCICFG_MISC_CONFIG_CORE_RST_REQ |
	      BCE_PCICFG_MISC_CONFIG_REG_WINDOW_ENA |
	      BCE_PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP;
	REG_WR(sc, BCE_PCICFG_MISC_CONFIG, val);

	/* Allow up to 30us for reset to complete. */
	for (i = 0; i < 10; i++) {
		val = REG_RD(sc, BCE_PCICFG_MISC_CONFIG);
		if ((val & (BCE_PCICFG_MISC_CONFIG_CORE_RST_REQ |
			    BCE_PCICFG_MISC_CONFIG_CORE_RST_BSY)) == 0) {
			break;
		}
		DELAY(10);
	}

	/* Check that reset completed successfully. */
	if (val & (BCE_PCICFG_MISC_CONFIG_CORE_RST_REQ |
		   BCE_PCICFG_MISC_CONFIG_CORE_RST_BSY)) {
		if_printf(&sc->arpcom.ac_if, "Reset failed!\n");
		return EBUSY;
	}

	/* Make sure byte swapping is properly configured. */
	val = REG_RD(sc, BCE_PCI_SWAP_DIAG0);
	if (val != 0x01020304) {
		if_printf(&sc->arpcom.ac_if, "Byte swap is incorrect!\n");
		return ENODEV;
	}

	/* Just completed a reset, assume that firmware is running again. */
	sc->bce_fw_timed_out = 0;

	/* Wait for the firmware to finish its initialization. */
	rc = bce_fw_sync(sc, BCE_DRV_MSG_DATA_WAIT1 | reset_code);
	if (rc) {
		if_printf(&sc->arpcom.ac_if,
			  "Firmware did not complete initialization!\n");
	}
	return rc;
}


static int
bce_chipinit(struct bce_softc *sc)
{
	uint32_t val;
	int rc = 0;

	/* Make sure the interrupt is not active. */
	REG_WR(sc, BCE_PCICFG_INT_ACK_CMD, BCE_PCICFG_INT_ACK_CMD_MASK_INT);

	/*
	 * Initialize DMA byte/word swapping, configure the number of DMA
	 * channels and PCI clock compensation delay.
	 */
	val = BCE_DMA_CONFIG_DATA_BYTE_SWAP |
	      BCE_DMA_CONFIG_DATA_WORD_SWAP |
#if BYTE_ORDER == BIG_ENDIAN
	      BCE_DMA_CONFIG_CNTL_BYTE_SWAP |
#endif
	      BCE_DMA_CONFIG_CNTL_WORD_SWAP |
	      DMA_READ_CHANS << 12 |
	      DMA_WRITE_CHANS << 16;

	val |= (0x2 << 20) | BCE_DMA_CONFIG_CNTL_PCI_COMP_DLY;

	if ((sc->bce_flags & BCE_PCIX_FLAG) && sc->bus_speed_mhz == 133)
		val |= BCE_DMA_CONFIG_PCI_FAST_CLK_CMP;

	/*
	 * This setting resolves a problem observed on certain Intel PCI
	 * chipsets that cannot handle multiple outstanding DMA operations.
	 * See errata E9_5706A1_65.
	 */
	if (BCE_CHIP_NUM(sc) == BCE_CHIP_NUM_5706 &&
	    BCE_CHIP_ID(sc) != BCE_CHIP_ID_5706_A0 &&
	    !(sc->bce_flags & BCE_PCIX_FLAG))
		val |= BCE_DMA_CONFIG_CNTL_PING_PONG_DMA;

	REG_WR(sc, BCE_DMA_CONFIG, val);

	/* Clear the PCI-X relaxed ordering bit. See errata E3_5708CA0_570. */
	if (sc->bce_flags & BCE_PCIX_FLAG) {
		uint16_t cmd;

		cmd = pci_read_config(sc->bce_dev, BCE_PCI_PCIX_CMD, 2);
		pci_write_config(sc->bce_dev, BCE_PCI_PCIX_CMD, cmd & ~0x2, 2);
	}

	/* Enable the RX_V2P and Context state machines before access. */
	REG_WR(sc, BCE_MISC_ENABLE_SET_BITS,
	       BCE_MISC_ENABLE_SET_BITS_HOST_COALESCE_ENABLE |
	       BCE_MISC_ENABLE_STATUS_BITS_RX_V2P_ENABLE |
	       BCE_MISC_ENABLE_STATUS_BITS_CONTEXT_ENABLE);

	/* Initialize context mapping and zero out the quick contexts. */
	bce_init_ctx(sc);

	/* Initialize the on-boards CPUs */
	bce_init_cpus(sc);

	/* Prepare NVRAM for access. */
	rc = bce_init_nvram(sc);
	if (rc != 0)
		return rc;

	/* Set the kernel bypass block size */
	val = REG_RD(sc, BCE_MQ_CONFIG);
	val &= ~BCE_MQ_CONFIG_KNL_BYP_BLK_SIZE;
	val |= BCE_MQ_CONFIG_KNL_BYP_BLK_SIZE_256;
	REG_WR(sc, BCE_MQ_CONFIG, val);

	val = 0x10000 + (MAX_CID_CNT * MB_KERNEL_CTX_SIZE);
	REG_WR(sc, BCE_MQ_KNL_BYP_WIND_START, val);
	REG_WR(sc, BCE_MQ_KNL_WIND_END, val);

	/* Set the page size and clear the RV2P processor stall bits. */
	val = (BCM_PAGE_BITS - 8) << 24;
	REG_WR(sc, BCE_RV2P_CONFIG, val);

	/* Configure page size. */
	val = REG_RD(sc, BCE_TBDR_CONFIG);
	val &= ~BCE_TBDR_CONFIG_PAGE_SIZE;
	val |= (BCM_PAGE_BITS - 8) << 24 | 0x40;
	REG_WR(sc, BCE_TBDR_CONFIG, val);

	return 0;
}


/****************************************************************************/
/* Initialize the controller in preparation to send/receive traffic.        */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_blockinit(struct bce_softc *sc)
{
	uint32_t reg, val;
	int rc = 0;

	/* Load the hardware default MAC address. */
	bce_set_mac_addr(sc);

	/* Set the Ethernet backoff seed value */
	val = sc->eaddr[0] + (sc->eaddr[1] << 8) + (sc->eaddr[2] << 16) +
	      sc->eaddr[3] + (sc->eaddr[4] << 8) + (sc->eaddr[5] << 16);
	REG_WR(sc, BCE_EMAC_BACKOFF_SEED, val);

	sc->last_status_idx = 0;
	sc->rx_mode = BCE_EMAC_RX_MODE_SORT_MODE;

	/* Set up link change interrupt generation. */
	REG_WR(sc, BCE_EMAC_ATTENTION_ENA, BCE_EMAC_ATTENTION_ENA_LINK);

	/* Program the physical address of the status block. */
	REG_WR(sc, BCE_HC_STATUS_ADDR_L, BCE_ADDR_LO(sc->status_block_paddr));
	REG_WR(sc, BCE_HC_STATUS_ADDR_H, BCE_ADDR_HI(sc->status_block_paddr));

	/* Program the physical address of the statistics block. */
	REG_WR(sc, BCE_HC_STATISTICS_ADDR_L,
	       BCE_ADDR_LO(sc->stats_block_paddr));
	REG_WR(sc, BCE_HC_STATISTICS_ADDR_H,
	       BCE_ADDR_HI(sc->stats_block_paddr));

	/* Program various host coalescing parameters. */
	REG_WR(sc, BCE_HC_TX_QUICK_CONS_TRIP,
	       (sc->bce_tx_quick_cons_trip_int << 16) |
	       sc->bce_tx_quick_cons_trip);
	REG_WR(sc, BCE_HC_RX_QUICK_CONS_TRIP,
	       (sc->bce_rx_quick_cons_trip_int << 16) |
	       sc->bce_rx_quick_cons_trip);
	REG_WR(sc, BCE_HC_COMP_PROD_TRIP,
	       (sc->bce_comp_prod_trip_int << 16) | sc->bce_comp_prod_trip);
	REG_WR(sc, BCE_HC_TX_TICKS,
	       (sc->bce_tx_ticks_int << 16) | sc->bce_tx_ticks);
	REG_WR(sc, BCE_HC_RX_TICKS,
	       (sc->bce_rx_ticks_int << 16) | sc->bce_rx_ticks);
	REG_WR(sc, BCE_HC_COM_TICKS,
	       (sc->bce_com_ticks_int << 16) | sc->bce_com_ticks);
	REG_WR(sc, BCE_HC_CMD_TICKS,
	       (sc->bce_cmd_ticks_int << 16) | sc->bce_cmd_ticks);
	REG_WR(sc, BCE_HC_STATS_TICKS, (sc->bce_stats_ticks & 0xffff00));
	REG_WR(sc, BCE_HC_STAT_COLLECT_TICKS, 0xbb8);	/* 3ms */
	REG_WR(sc, BCE_HC_CONFIG,
	       BCE_HC_CONFIG_TX_TMR_MODE |
	       BCE_HC_CONFIG_COLLECT_STATS);

	/* Clear the internal statistics counters. */
	REG_WR(sc, BCE_HC_COMMAND, BCE_HC_COMMAND_CLR_STAT_NOW);

	/* Verify that bootcode is running. */
	reg = REG_RD_IND(sc, sc->bce_shmem_base + BCE_DEV_INFO_SIGNATURE);

	DBRUNIF(DB_RANDOMTRUE(bce_debug_bootcode_running_failure),
		if_printf(&sc->arpcom.ac_if,
			  "%s(%d): Simulating bootcode failure.\n",
			  __FILE__, __LINE__);
		reg = 0);

	if ((reg & BCE_DEV_INFO_SIGNATURE_MAGIC_MASK) !=
	    BCE_DEV_INFO_SIGNATURE_MAGIC) {
		if_printf(&sc->arpcom.ac_if,
			  "Bootcode not running! Found: 0x%08X, "
			  "Expected: 08%08X\n",
			  reg & BCE_DEV_INFO_SIGNATURE_MAGIC_MASK,
			  BCE_DEV_INFO_SIGNATURE_MAGIC);
		return ENODEV;
	}

	/* Check if any management firmware is running. */
	reg = REG_RD_IND(sc, sc->bce_shmem_base + BCE_PORT_FEATURE);
	if (reg & (BCE_PORT_FEATURE_ASF_ENABLED |
		   BCE_PORT_FEATURE_IMD_ENABLED)) {
		DBPRINT(sc, BCE_INFO, "Management F/W Enabled.\n");
		sc->bce_flags |= BCE_MFW_ENABLE_FLAG;
	}

	sc->bce_fw_ver =
		REG_RD_IND(sc, sc->bce_shmem_base + BCE_DEV_INFO_BC_REV);
	DBPRINT(sc, BCE_INFO, "bootcode rev = 0x%08X\n", sc->bce_fw_ver);

	/* Allow bootcode to apply any additional fixes before enabling MAC. */
	rc = bce_fw_sync(sc, BCE_DRV_MSG_DATA_WAIT2 | BCE_DRV_MSG_CODE_RESET);

	/* Enable link state change interrupt generation. */
	REG_WR(sc, BCE_HC_ATTN_BITS_ENABLE, STATUS_ATTN_BITS_LINK_STATE);

	/* Enable all remaining blocks in the MAC. */
	REG_WR(sc, BCE_MISC_ENABLE_SET_BITS, 0x5ffffff);
	REG_RD(sc, BCE_MISC_ENABLE_SET_BITS);
	DELAY(20);

	return 0;
}


/****************************************************************************/
/* Encapsulate an mbuf cluster into the rx_bd chain.                        */
/*                                                                          */
/* The NetXtreme II can support Jumbo frames by using multiple rx_bd's.     */
/* This routine will map an mbuf cluster into 1 or more rx_bd's as          */
/* necessary.                                                               */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_newbuf_std(struct bce_softc *sc, uint16_t *prod, uint16_t *chain_prod,
	       uint32_t *prod_bseq, int init)
{
	bus_dmamap_t map;
	bus_dma_segment_t seg;
	struct mbuf *m_new;
	int error, nseg;
#ifdef BCE_DEBUG
	uint16_t debug_chain_prod = *chain_prod;
#endif

	/* Make sure the inputs are valid. */
	DBRUNIF((*chain_prod > MAX_RX_BD),
		if_printf(&sc->arpcom.ac_if, "%s(%d): "
			  "RX producer out of range: 0x%04X > 0x%04X\n",
			  __FILE__, __LINE__,
			  *chain_prod, (uint16_t)MAX_RX_BD));

	DBPRINT(sc, BCE_VERBOSE_RECV, "%s(enter): prod = 0x%04X, chain_prod = 0x%04X, "
		"prod_bseq = 0x%08X\n", __func__, *prod, *chain_prod, *prod_bseq);

	DBRUNIF(DB_RANDOMTRUE(bce_debug_mbuf_allocation_failure),
		if_printf(&sc->arpcom.ac_if, "%s(%d): "
			  "Simulating mbuf allocation failure.\n",
			  __FILE__, __LINE__);
		sc->mbuf_alloc_failed++;
		return ENOBUFS);

	/* This is a new mbuf allocation. */
	m_new = m_getcl(init ? MB_WAIT : MB_DONTWAIT, MT_DATA, M_PKTHDR);
	if (m_new == NULL)
		return ENOBUFS;
	DBRUNIF(1, sc->rx_mbuf_alloc++);

	m_new->m_len = m_new->m_pkthdr.len = MCLBYTES;

	/* Map the mbuf cluster into device memory. */
	error = bus_dmamap_load_mbuf_segment(sc->rx_mbuf_tag,
			sc->rx_mbuf_tmpmap, m_new, &seg, 1, &nseg,
			BUS_DMA_NOWAIT);
	if (error) {
		m_freem(m_new);
		if (init) {
			if_printf(&sc->arpcom.ac_if,
				  "Error mapping mbuf into RX chain!\n");
		}
		DBRUNIF(1, sc->rx_mbuf_alloc--);
		return error;
	}

	if (sc->rx_mbuf_ptr[*chain_prod] != NULL) {
		bus_dmamap_unload(sc->rx_mbuf_tag,
				  sc->rx_mbuf_map[*chain_prod]);
	}

	map = sc->rx_mbuf_map[*chain_prod];
	sc->rx_mbuf_map[*chain_prod] = sc->rx_mbuf_tmpmap;
	sc->rx_mbuf_tmpmap = map;

	/* Watch for overflow. */
	DBRUNIF((sc->free_rx_bd > USABLE_RX_BD),
		if_printf(&sc->arpcom.ac_if, "%s(%d): "
			  "Too many free rx_bd (0x%04X > 0x%04X)!\n",
			  __FILE__, __LINE__, sc->free_rx_bd,
			  (uint16_t)USABLE_RX_BD));

	/* Update some debug statistic counters */
	DBRUNIF((sc->free_rx_bd < sc->rx_low_watermark),
		sc->rx_low_watermark = sc->free_rx_bd);
	DBRUNIF((sc->free_rx_bd == 0), sc->rx_empty_count++);

	/* Save the mbuf and update our counter. */
	sc->rx_mbuf_ptr[*chain_prod] = m_new;
	sc->rx_mbuf_paddr[*chain_prod] = seg.ds_addr;
	sc->free_rx_bd--;

	bce_setup_rxdesc_std(sc, *chain_prod, prod_bseq);

	DBRUN(BCE_VERBOSE_RECV,
	      bce_dump_rx_mbuf_chain(sc, debug_chain_prod, 1));

	DBPRINT(sc, BCE_VERBOSE_RECV, "%s(exit): prod = 0x%04X, chain_prod = 0x%04X, "
		"prod_bseq = 0x%08X\n", __func__, *prod, *chain_prod, *prod_bseq);

	return 0;
}


static void
bce_setup_rxdesc_std(struct bce_softc *sc, uint16_t chain_prod, uint32_t *prod_bseq)
{
	struct rx_bd *rxbd;
	bus_addr_t paddr;
	int len;

	paddr = sc->rx_mbuf_paddr[chain_prod];
	len = sc->rx_mbuf_ptr[chain_prod]->m_len;

	/* Setup the rx_bd for the first segment. */
	rxbd = &sc->rx_bd_chain[RX_PAGE(chain_prod)][RX_IDX(chain_prod)];

	rxbd->rx_bd_haddr_lo = htole32(BCE_ADDR_LO(paddr));
	rxbd->rx_bd_haddr_hi = htole32(BCE_ADDR_HI(paddr));
	rxbd->rx_bd_len = htole32(len);
	rxbd->rx_bd_flags = htole32(RX_BD_FLAGS_START);
	*prod_bseq += len;

	rxbd->rx_bd_flags |= htole32(RX_BD_FLAGS_END);
}


/****************************************************************************/
/* Allocate memory and initialize the TX data structures.                   */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_init_tx_chain(struct bce_softc *sc)
{
	struct tx_bd *txbd;
	uint32_t val;
	int i, rc = 0;

	DBPRINT(sc, BCE_VERBOSE_RESET, "Entering %s()\n", __func__);

	/* Set the initial TX producer/consumer indices. */
	sc->tx_prod = 0;
	sc->tx_cons = 0;
	sc->tx_prod_bseq   = 0;
	sc->used_tx_bd = 0;
	sc->max_tx_bd = USABLE_TX_BD;
	DBRUNIF(1, sc->tx_hi_watermark = USABLE_TX_BD);
	DBRUNIF(1, sc->tx_full_count = 0);

	/*
	 * The NetXtreme II supports a linked-list structre called
	 * a Buffer Descriptor Chain (or BD chain).  A BD chain
	 * consists of a series of 1 or more chain pages, each of which
	 * consists of a fixed number of BD entries.
	 * The last BD entry on each page is a pointer to the next page
	 * in the chain, and the last pointer in the BD chain
	 * points back to the beginning of the chain.
	 */

	/* Set the TX next pointer chain entries. */
	for (i = 0; i < TX_PAGES; i++) {
		int j;

		txbd = &sc->tx_bd_chain[i][USABLE_TX_BD_PER_PAGE];

		/* Check if we've reached the last page. */
		if (i == (TX_PAGES - 1))
			j = 0;
		else
			j = i + 1;

		txbd->tx_bd_haddr_hi =
			htole32(BCE_ADDR_HI(sc->tx_bd_chain_paddr[j]));
		txbd->tx_bd_haddr_lo =
			htole32(BCE_ADDR_LO(sc->tx_bd_chain_paddr[j]));
	}

	/* Initialize the context ID for an L2 TX chain. */
	val = BCE_L2CTX_TYPE_TYPE_L2;
	val |= BCE_L2CTX_TYPE_SIZE_L2;
	CTX_WR(sc, GET_CID_ADDR(TX_CID), BCE_L2CTX_TYPE, val);

	val = BCE_L2CTX_CMD_TYPE_TYPE_L2 | (8 << 16);
	CTX_WR(sc, GET_CID_ADDR(TX_CID), BCE_L2CTX_CMD_TYPE, val);

	/* Point the hardware to the first page in the chain. */
	val = BCE_ADDR_HI(sc->tx_bd_chain_paddr[0]);
	CTX_WR(sc, GET_CID_ADDR(TX_CID), BCE_L2CTX_TBDR_BHADDR_HI, val);
	val = BCE_ADDR_LO(sc->tx_bd_chain_paddr[0]);
	CTX_WR(sc, GET_CID_ADDR(TX_CID), BCE_L2CTX_TBDR_BHADDR_LO, val);

	DBRUN(BCE_VERBOSE_SEND, bce_dump_tx_chain(sc, 0, TOTAL_TX_BD));

	DBPRINT(sc, BCE_VERBOSE_RESET, "Exiting %s()\n", __func__);

	return(rc);
}


/****************************************************************************/
/* Free memory and clear the TX data structures.                            */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_free_tx_chain(struct bce_softc *sc)
{
	int i;

	DBPRINT(sc, BCE_VERBOSE_RESET, "Entering %s()\n", __func__);

	/* Unmap, unload, and free any mbufs still in the TX mbuf chain. */
	for (i = 0; i < TOTAL_TX_BD; i++) {
		if (sc->tx_mbuf_ptr[i] != NULL) {
			bus_dmamap_unload(sc->tx_mbuf_tag, sc->tx_mbuf_map[i]);
			m_freem(sc->tx_mbuf_ptr[i]);
			sc->tx_mbuf_ptr[i] = NULL;
			DBRUNIF(1, sc->tx_mbuf_alloc--);
		}
	}

	/* Clear each TX chain page. */
	for (i = 0; i < TX_PAGES; i++)
		bzero(sc->tx_bd_chain[i], BCE_TX_CHAIN_PAGE_SZ);
	sc->used_tx_bd = 0;

	/* Check if we lost any mbufs in the process. */
	DBRUNIF((sc->tx_mbuf_alloc),
		if_printf(&sc->arpcom.ac_if,
			  "%s(%d): Memory leak! "
			  "Lost %d mbufs from tx chain!\n",
			  __FILE__, __LINE__, sc->tx_mbuf_alloc));

	DBPRINT(sc, BCE_VERBOSE_RESET, "Exiting %s()\n", __func__);
}


/****************************************************************************/
/* Allocate memory and initialize the RX data structures.                   */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_init_rx_chain(struct bce_softc *sc)
{
	struct rx_bd *rxbd;
	int i, rc = 0;
	uint16_t prod, chain_prod;
	uint32_t prod_bseq, val;

	DBPRINT(sc, BCE_VERBOSE_RESET, "Entering %s()\n", __func__);

	/* Initialize the RX producer and consumer indices. */
	sc->rx_prod = 0;
	sc->rx_cons = 0;
	sc->rx_prod_bseq = 0;
	sc->free_rx_bd = USABLE_RX_BD;
	sc->max_rx_bd = USABLE_RX_BD;
	DBRUNIF(1, sc->rx_low_watermark = USABLE_RX_BD);
	DBRUNIF(1, sc->rx_empty_count = 0);

	/* Initialize the RX next pointer chain entries. */
	for (i = 0; i < RX_PAGES; i++) {
		int j;

		rxbd = &sc->rx_bd_chain[i][USABLE_RX_BD_PER_PAGE];

		/* Check if we've reached the last page. */
		if (i == (RX_PAGES - 1))
			j = 0;
		else
			j = i + 1;

		/* Setup the chain page pointers. */
		rxbd->rx_bd_haddr_hi =
			htole32(BCE_ADDR_HI(sc->rx_bd_chain_paddr[j]));
		rxbd->rx_bd_haddr_lo =
			htole32(BCE_ADDR_LO(sc->rx_bd_chain_paddr[j]));
	}

	/* Initialize the context ID for an L2 RX chain. */
	val = BCE_L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE_VALUE;
	val |= BCE_L2CTX_CTX_TYPE_SIZE_L2;
	val |= 0x02 << 8;
	CTX_WR(sc, GET_CID_ADDR(RX_CID), BCE_L2CTX_CTX_TYPE, val);

	/* Point the hardware to the first page in the chain. */
	/* XXX shouldn't this after RX descriptor initialization? */
	val = BCE_ADDR_HI(sc->rx_bd_chain_paddr[0]);
	CTX_WR(sc, GET_CID_ADDR(RX_CID), BCE_L2CTX_NX_BDHADDR_HI, val);
	val = BCE_ADDR_LO(sc->rx_bd_chain_paddr[0]);
	CTX_WR(sc, GET_CID_ADDR(RX_CID), BCE_L2CTX_NX_BDHADDR_LO, val);

	/* Allocate mbuf clusters for the rx_bd chain. */
	prod = prod_bseq = 0;
	while (prod < TOTAL_RX_BD) {
		chain_prod = RX_CHAIN_IDX(prod);
		if (bce_newbuf_std(sc, &prod, &chain_prod, &prod_bseq, 1)) {
			if_printf(&sc->arpcom.ac_if,
				  "Error filling RX chain: rx_bd[0x%04X]!\n",
				  chain_prod);
			rc = ENOBUFS;
			break;
		}
		prod = NEXT_RX_BD(prod);
	}

	/* Save the RX chain producer index. */
	sc->rx_prod = prod;
	sc->rx_prod_bseq = prod_bseq;

	/* Tell the chip about the waiting rx_bd's. */
	REG_WR16(sc, MB_RX_CID_ADDR + BCE_L2CTX_HOST_BDIDX, sc->rx_prod);
	REG_WR(sc, MB_RX_CID_ADDR + BCE_L2CTX_HOST_BSEQ, sc->rx_prod_bseq);

	DBRUN(BCE_VERBOSE_RECV, bce_dump_rx_chain(sc, 0, TOTAL_RX_BD));

	DBPRINT(sc, BCE_VERBOSE_RESET, "Exiting %s()\n", __func__);

	return(rc);
}


/****************************************************************************/
/* Free memory and clear the RX data structures.                            */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_free_rx_chain(struct bce_softc *sc)
{
	int i;

	DBPRINT(sc, BCE_VERBOSE_RESET, "Entering %s()\n", __func__);

	/* Free any mbufs still in the RX mbuf chain. */
	for (i = 0; i < TOTAL_RX_BD; i++) {
		if (sc->rx_mbuf_ptr[i] != NULL) {
			bus_dmamap_unload(sc->rx_mbuf_tag, sc->rx_mbuf_map[i]);
			m_freem(sc->rx_mbuf_ptr[i]);
			sc->rx_mbuf_ptr[i] = NULL;
			DBRUNIF(1, sc->rx_mbuf_alloc--);
		}
	}

	/* Clear each RX chain page. */
	for (i = 0; i < RX_PAGES; i++)
		bzero(sc->rx_bd_chain[i], BCE_RX_CHAIN_PAGE_SZ);

	/* Check if we lost any mbufs in the process. */
	DBRUNIF((sc->rx_mbuf_alloc),
		if_printf(&sc->arpcom.ac_if,
			  "%s(%d): Memory leak! "
			  "Lost %d mbufs from rx chain!\n",
			  __FILE__, __LINE__, sc->rx_mbuf_alloc));

	DBPRINT(sc, BCE_VERBOSE_RESET, "Exiting %s()\n", __func__);
}


/****************************************************************************/
/* Set media options.                                                       */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_ifmedia_upd(struct ifnet *ifp)
{
	struct bce_softc *sc = ifp->if_softc;
	struct mii_data *mii = device_get_softc(sc->bce_miibus);

	/*
	 * 'mii' will be NULL, when this function is called on following
	 * code path: bce_attach() -> bce_mgmt_init()
	 */
	if (mii != NULL) {
		/* Make sure the MII bus has been enumerated. */
		sc->bce_link = 0;
		if (mii->mii_instance) {
			struct mii_softc *miisc;

			LIST_FOREACH(miisc, &mii->mii_phys, mii_list)
				mii_phy_reset(miisc);
		}
		mii_mediachg(mii);
	}
	return 0;
}


/****************************************************************************/
/* Reports current media status.                                            */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_ifmedia_sts(struct ifnet *ifp, struct ifmediareq *ifmr)
{
	struct bce_softc *sc = ifp->if_softc;
	struct mii_data *mii = device_get_softc(sc->bce_miibus);

	mii_pollstat(mii);
	ifmr->ifm_active = mii->mii_media_active;
	ifmr->ifm_status = mii->mii_media_status;
}


/****************************************************************************/
/* Handles PHY generated interrupt events.                                  */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_phy_intr(struct bce_softc *sc)
{
	uint32_t new_link_state, old_link_state;
	struct ifnet *ifp = &sc->arpcom.ac_if;

	ASSERT_SERIALIZED(ifp->if_serializer);

	new_link_state = sc->status_block->status_attn_bits &
			 STATUS_ATTN_BITS_LINK_STATE;
	old_link_state = sc->status_block->status_attn_bits_ack &
			 STATUS_ATTN_BITS_LINK_STATE;

	/* Handle any changes if the link state has changed. */
	if (new_link_state != old_link_state) {	/* XXX redundant? */
		DBRUN(BCE_VERBOSE_INTR, bce_dump_status_block(sc));

		sc->bce_link = 0;
		callout_stop(&sc->bce_stat_ch);
		bce_tick_serialized(sc);

		/* Update the status_attn_bits_ack field in the status block. */
		if (new_link_state) {
			REG_WR(sc, BCE_PCICFG_STATUS_BIT_SET_CMD,
			       STATUS_ATTN_BITS_LINK_STATE);
			if (bootverbose)
				if_printf(ifp, "Link is now UP.\n");
		} else {
			REG_WR(sc, BCE_PCICFG_STATUS_BIT_CLEAR_CMD,
			       STATUS_ATTN_BITS_LINK_STATE);
			if (bootverbose)
				if_printf(ifp, "Link is now DOWN.\n");
		}
	}

	/* Acknowledge the link change interrupt. */
	REG_WR(sc, BCE_EMAC_STATUS, BCE_EMAC_STATUS_LINK_CHANGE);
}


/****************************************************************************/
/* Reads the receive consumer value from the status block (skipping over    */
/* chain page pointer if necessary).                                        */
/*                                                                          */
/* Returns:                                                                 */
/*   hw_cons                                                                */
/****************************************************************************/
static __inline uint16_t
bce_get_hw_rx_cons(struct bce_softc *sc)
{
	uint16_t hw_cons = sc->status_block->status_rx_quick_consumer_index0;

	if ((hw_cons & USABLE_RX_BD_PER_PAGE) == USABLE_RX_BD_PER_PAGE)
		hw_cons++;
	return hw_cons;
}


/****************************************************************************/
/* Handles received frame interrupt events.                                 */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_rx_intr(struct bce_softc *sc, int count)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint16_t hw_cons, sw_cons, sw_chain_cons, sw_prod, sw_chain_prod;
	uint32_t sw_prod_bseq;
	struct mbuf_chain chain[MAXCPU];

	ASSERT_SERIALIZED(ifp->if_serializer);

	ether_input_chain_init(chain);

	DBRUNIF(1, sc->rx_interrupts++);

	/* Get the hardware's view of the RX consumer index. */
	hw_cons = sc->hw_rx_cons = bce_get_hw_rx_cons(sc);

	/* Get working copies of the driver's view of the RX indices. */
	sw_cons = sc->rx_cons;
	sw_prod = sc->rx_prod;
	sw_prod_bseq = sc->rx_prod_bseq;

	DBPRINT(sc, BCE_INFO_RECV, "%s(enter): sw_prod = 0x%04X, "
		"sw_cons = 0x%04X, sw_prod_bseq = 0x%08X\n",
		__func__, sw_prod, sw_cons, sw_prod_bseq);

	/* Prevent speculative reads from getting ahead of the status block. */
	bus_space_barrier(sc->bce_btag, sc->bce_bhandle, 0, 0,
			  BUS_SPACE_BARRIER_READ);

	/* Update some debug statistics counters */
	DBRUNIF((sc->free_rx_bd < sc->rx_low_watermark),
		sc->rx_low_watermark = sc->free_rx_bd);
	DBRUNIF((sc->free_rx_bd == 0), sc->rx_empty_count++);

	/* Scan through the receive chain as long as there is work to do. */
	while (sw_cons != hw_cons) {
		struct mbuf *m = NULL;
		struct l2_fhdr *l2fhdr = NULL;
		struct rx_bd *rxbd;
		unsigned int len;
		uint32_t status = 0;

#ifdef DEVICE_POLLING
		if (count >= 0 && count-- == 0) {
			sc->hw_rx_cons = sw_cons;
			break;
		}
#endif

		/*
		 * Convert the producer/consumer indices
		 * to an actual rx_bd index.
		 */
		sw_chain_cons = RX_CHAIN_IDX(sw_cons);
		sw_chain_prod = RX_CHAIN_IDX(sw_prod);

		/* Get the used rx_bd. */
		rxbd = &sc->rx_bd_chain[RX_PAGE(sw_chain_cons)]
				       [RX_IDX(sw_chain_cons)];
		sc->free_rx_bd++;

		DBRUN(BCE_VERBOSE_RECV,
		      if_printf(ifp, "%s(): ", __func__);
		      bce_dump_rxbd(sc, sw_chain_cons, rxbd));

		/* The mbuf is stored with the last rx_bd entry of a packet. */
		if (sc->rx_mbuf_ptr[sw_chain_cons] != NULL) {
			/* Validate that this is the last rx_bd. */
			DBRUNIF((!(rxbd->rx_bd_flags & RX_BD_FLAGS_END)),
				if_printf(ifp, "%s(%d): "
				"Unexpected mbuf found in rx_bd[0x%04X]!\n",
				__FILE__, __LINE__, sw_chain_cons);
				bce_breakpoint(sc));

			if (sw_chain_cons != sw_chain_prod) {
				if_printf(ifp, "RX cons(%d) != prod(%d), "
					  "drop!\n", sw_chain_cons,
					  sw_chain_prod);
				ifp->if_ierrors++;

				bce_setup_rxdesc_std(sc, sw_chain_cons,
						     &sw_prod_bseq);
				m = NULL;
				goto bce_rx_int_next_rx;
			}

			/* Unmap the mbuf from DMA space. */
			bus_dmamap_sync(sc->rx_mbuf_tag,
					sc->rx_mbuf_map[sw_chain_cons],
					BUS_DMASYNC_POSTREAD);

			/* Save the mbuf from the driver's chain. */
			m = sc->rx_mbuf_ptr[sw_chain_cons];

			/*
			 * Frames received on the NetXteme II are prepended 
			 * with an l2_fhdr structure which provides status
			 * information about the received frame (including
			 * VLAN tags and checksum info).  The frames are also
			 * automatically adjusted to align the IP header
			 * (i.e. two null bytes are inserted before the 
			 * Ethernet header).
			 */
			l2fhdr = mtod(m, struct l2_fhdr *);

			len = l2fhdr->l2_fhdr_pkt_len;
			status = l2fhdr->l2_fhdr_status;

			DBRUNIF(DB_RANDOMTRUE(bce_debug_l2fhdr_status_check),
				if_printf(ifp,
				"Simulating l2_fhdr status error.\n");
				status = status | L2_FHDR_ERRORS_PHY_DECODE);

			/* Watch for unusual sized frames. */
			DBRUNIF((len < BCE_MIN_MTU ||
				 len > BCE_MAX_JUMBO_ETHER_MTU_VLAN),
				if_printf(ifp,
				"%s(%d): Unusual frame size found. "
				"Min(%d), Actual(%d), Max(%d)\n",
				__FILE__, __LINE__,
				(int)BCE_MIN_MTU, len,
				(int)BCE_MAX_JUMBO_ETHER_MTU_VLAN);
				bce_dump_mbuf(sc, m);
		 		bce_breakpoint(sc));

			len -= ETHER_CRC_LEN;

			/* Check the received frame for errors. */
			if (status & (L2_FHDR_ERRORS_BAD_CRC |
				      L2_FHDR_ERRORS_PHY_DECODE |
				      L2_FHDR_ERRORS_ALIGNMENT |
				      L2_FHDR_ERRORS_TOO_SHORT |
				      L2_FHDR_ERRORS_GIANT_FRAME)) {
				ifp->if_ierrors++;
				DBRUNIF(1, sc->l2fhdr_status_errors++);

				/* Reuse the mbuf for a new frame. */
				bce_setup_rxdesc_std(sc, sw_chain_prod,
						     &sw_prod_bseq);
				m = NULL;
				goto bce_rx_int_next_rx;
			}

			/* 
			 * Get a new mbuf for the rx_bd.   If no new
			 * mbufs are available then reuse the current mbuf,
			 * log an ierror on the interface, and generate
			 * an error in the system log.
			 */
			if (bce_newbuf_std(sc, &sw_prod, &sw_chain_prod,
					   &sw_prod_bseq, 0)) {
				DBRUN(BCE_WARN,
				      if_printf(ifp,
				      "%s(%d): Failed to allocate new mbuf, "
				      "incoming frame dropped!\n",
				      __FILE__, __LINE__));

				ifp->if_ierrors++;

				/* Try and reuse the exisitng mbuf. */
				bce_setup_rxdesc_std(sc, sw_chain_prod,
						     &sw_prod_bseq);
				m = NULL;
				goto bce_rx_int_next_rx;
			}

			/*
			 * Skip over the l2_fhdr when passing
			 * the data up the stack.
			 */
			m_adj(m, sizeof(struct l2_fhdr) + ETHER_ALIGN);

			m->m_pkthdr.len = m->m_len = len;
			m->m_pkthdr.rcvif = ifp;

			DBRUN(BCE_VERBOSE_RECV,
			      struct ether_header *eh;
			      eh = mtod(m, struct ether_header *);
			      if_printf(ifp, "%s(): to: %6D, from: %6D, "
			      		"type: 0x%04X\n", __func__,
					eh->ether_dhost, ":", 
					eh->ether_shost, ":",
					htons(eh->ether_type)));

			/* Validate the checksum if offload enabled. */
			if (ifp->if_capenable & IFCAP_RXCSUM) {
				/* Check for an IP datagram. */
				if (status & L2_FHDR_STATUS_IP_DATAGRAM) {
					m->m_pkthdr.csum_flags |=
						CSUM_IP_CHECKED;

					/* Check if the IP checksum is valid. */
					if ((l2fhdr->l2_fhdr_ip_xsum ^
					     0xffff) == 0) {
						m->m_pkthdr.csum_flags |=
							CSUM_IP_VALID;
					} else {
						DBPRINT(sc, BCE_WARN_RECV, 
							"%s(): Invalid IP checksum = 0x%04X!\n",
							__func__, l2fhdr->l2_fhdr_ip_xsum);
					}
				}

				/* Check for a valid TCP/UDP frame. */
				if (status & (L2_FHDR_STATUS_TCP_SEGMENT |
					      L2_FHDR_STATUS_UDP_DATAGRAM)) {

					/* Check for a good TCP/UDP checksum. */
					if ((status &
					     (L2_FHDR_ERRORS_TCP_XSUM |
					      L2_FHDR_ERRORS_UDP_XSUM)) == 0) {
						m->m_pkthdr.csum_data =
						l2fhdr->l2_fhdr_tcp_udp_xsum;
						m->m_pkthdr.csum_flags |=
							CSUM_DATA_VALID |
							CSUM_PSEUDO_HDR;
					} else {
						DBPRINT(sc, BCE_WARN_RECV,
							"%s(): Invalid TCP/UDP checksum = 0x%04X!\n",
							__func__, l2fhdr->l2_fhdr_tcp_udp_xsum);
					}
				}
			}

			ifp->if_ipackets++;
bce_rx_int_next_rx:
			sw_prod = NEXT_RX_BD(sw_prod);
		}

		sw_cons = NEXT_RX_BD(sw_cons);

		/* If we have a packet, pass it up the stack */
		if (m) {
			DBPRINT(sc, BCE_VERBOSE_RECV,
				"%s(): Passing received frame up.\n", __func__);

			if (status & L2_FHDR_STATUS_L2_VLAN_TAG) {
				m->m_flags |= M_VLANTAG;
				m->m_pkthdr.ether_vlantag =
					l2fhdr->l2_fhdr_vlan_tag;
			}
			ether_input_chain(ifp, m, NULL, chain);

			DBRUNIF(1, sc->rx_mbuf_alloc--);
		}

		/*
		 * If polling(4) is not enabled, refresh hw_cons to see
		 * whether there's new work.
		 *
		 * If polling(4) is enabled, i.e count >= 0, refreshing
		 * should not be performed, so that we would not spend
		 * too much time in RX processing.
		 */
		if (count < 0 && sw_cons == hw_cons)
			hw_cons = sc->hw_rx_cons = bce_get_hw_rx_cons(sc);

		/*
		 * Prevent speculative reads from getting ahead
		 * of the status block.
		 */
		bus_space_barrier(sc->bce_btag, sc->bce_bhandle, 0, 0,
				  BUS_SPACE_BARRIER_READ);
	}

	ether_input_dispatch(chain);

	sc->rx_cons = sw_cons;
	sc->rx_prod = sw_prod;
	sc->rx_prod_bseq = sw_prod_bseq;

	REG_WR16(sc, MB_RX_CID_ADDR + BCE_L2CTX_HOST_BDIDX, sc->rx_prod);
	REG_WR(sc, MB_RX_CID_ADDR + BCE_L2CTX_HOST_BSEQ, sc->rx_prod_bseq);

	DBPRINT(sc, BCE_INFO_RECV, "%s(exit): rx_prod = 0x%04X, "
		"rx_cons = 0x%04X, rx_prod_bseq = 0x%08X\n",
		__func__, sc->rx_prod, sc->rx_cons, sc->rx_prod_bseq);
}


/****************************************************************************/
/* Reads the transmit consumer value from the status block (skipping over   */
/* chain page pointer if necessary).                                        */
/*                                                                          */
/* Returns:                                                                 */
/*   hw_cons                                                                */
/****************************************************************************/
static __inline uint16_t
bce_get_hw_tx_cons(struct bce_softc *sc)
{
	uint16_t hw_cons = sc->status_block->status_tx_quick_consumer_index0;

	if ((hw_cons & USABLE_TX_BD_PER_PAGE) == USABLE_TX_BD_PER_PAGE)
		hw_cons++;
	return hw_cons;
}


/****************************************************************************/
/* Handles transmit completion interrupt events.                            */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_tx_intr(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint16_t hw_tx_cons, sw_tx_cons, sw_tx_chain_cons;

	ASSERT_SERIALIZED(ifp->if_serializer);

	DBRUNIF(1, sc->tx_interrupts++);

	/* Get the hardware's view of the TX consumer index. */
	hw_tx_cons = sc->hw_tx_cons = bce_get_hw_tx_cons(sc);
	sw_tx_cons = sc->tx_cons;

	/* Prevent speculative reads from getting ahead of the status block. */
	bus_space_barrier(sc->bce_btag, sc->bce_bhandle, 0, 0,
			  BUS_SPACE_BARRIER_READ);

	/* Cycle through any completed TX chain page entries. */
	while (sw_tx_cons != hw_tx_cons) {
#ifdef BCE_DEBUG
		struct tx_bd *txbd = NULL;
#endif
		sw_tx_chain_cons = TX_CHAIN_IDX(sw_tx_cons);

		DBPRINT(sc, BCE_INFO_SEND,
			"%s(): hw_tx_cons = 0x%04X, sw_tx_cons = 0x%04X, "
			"sw_tx_chain_cons = 0x%04X\n",
			__func__, hw_tx_cons, sw_tx_cons, sw_tx_chain_cons);

		DBRUNIF((sw_tx_chain_cons > MAX_TX_BD),
			if_printf(ifp, "%s(%d): "
				  "TX chain consumer out of range! "
				  " 0x%04X > 0x%04X\n",
				  __FILE__, __LINE__, sw_tx_chain_cons,
				  (int)MAX_TX_BD);
			bce_breakpoint(sc));

		DBRUNIF(1, txbd = &sc->tx_bd_chain[TX_PAGE(sw_tx_chain_cons)]
				[TX_IDX(sw_tx_chain_cons)]);

		DBRUNIF((txbd == NULL),
			if_printf(ifp, "%s(%d): "
				  "Unexpected NULL tx_bd[0x%04X]!\n",
				  __FILE__, __LINE__, sw_tx_chain_cons);
			bce_breakpoint(sc));

		DBRUN(BCE_INFO_SEND,
		      if_printf(ifp, "%s(): ", __func__);
		      bce_dump_txbd(sc, sw_tx_chain_cons, txbd));

		/*
		 * Free the associated mbuf. Remember
		 * that only the last tx_bd of a packet
		 * has an mbuf pointer and DMA map.
		 */
		if (sc->tx_mbuf_ptr[sw_tx_chain_cons] != NULL) {
			/* Validate that this is the last tx_bd. */
			DBRUNIF((!(txbd->tx_bd_flags & TX_BD_FLAGS_END)),
				if_printf(ifp, "%s(%d): "
				"tx_bd END flag not set but "
				"txmbuf == NULL!\n", __FILE__, __LINE__);
				bce_breakpoint(sc));

			DBRUN(BCE_INFO_SEND,
			      if_printf(ifp, "%s(): Unloading map/freeing mbuf "
			      		"from tx_bd[0x%04X]\n", __func__,
					sw_tx_chain_cons));

			/* Unmap the mbuf. */
			bus_dmamap_unload(sc->tx_mbuf_tag,
					  sc->tx_mbuf_map[sw_tx_chain_cons]);

			/* Free the mbuf. */
			m_freem(sc->tx_mbuf_ptr[sw_tx_chain_cons]);
			sc->tx_mbuf_ptr[sw_tx_chain_cons] = NULL;
			DBRUNIF(1, sc->tx_mbuf_alloc--);

			ifp->if_opackets++;
		}

		sc->used_tx_bd--;
		sw_tx_cons = NEXT_TX_BD(sw_tx_cons);

		if (sw_tx_cons == hw_tx_cons) {
			/* Refresh hw_cons to see if there's new work. */
			hw_tx_cons = sc->hw_tx_cons = bce_get_hw_tx_cons(sc);
		}

		/*
		 * Prevent speculative reads from getting
		 * ahead of the status block.
		 */
		bus_space_barrier(sc->bce_btag, sc->bce_bhandle, 0, 0,
				  BUS_SPACE_BARRIER_READ);
	}

	if (sc->used_tx_bd == 0) {
		/* Clear the TX timeout timer. */
		ifp->if_timer = 0;
	}

	/* Clear the tx hardware queue full flag. */
	if (sc->max_tx_bd - sc->used_tx_bd >= BCE_TX_SPARE_SPACE) {
		DBRUNIF((ifp->if_flags & IFF_OACTIVE),
			DBPRINT(sc, BCE_WARN_SEND,
				"%s(): Open TX chain! %d/%d (used/total)\n", 
				__func__, sc->used_tx_bd, sc->max_tx_bd));
		ifp->if_flags &= ~IFF_OACTIVE;
	}
	sc->tx_cons = sw_tx_cons;
}


/****************************************************************************/
/* Disables interrupt generation.                                           */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_disable_intr(struct bce_softc *sc)
{
	REG_WR(sc, BCE_PCICFG_INT_ACK_CMD, BCE_PCICFG_INT_ACK_CMD_MASK_INT);
	REG_RD(sc, BCE_PCICFG_INT_ACK_CMD);
	lwkt_serialize_handler_disable(sc->arpcom.ac_if.if_serializer);
}


/****************************************************************************/
/* Enables interrupt generation.                                            */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_enable_intr(struct bce_softc *sc)
{
	uint32_t val;

	lwkt_serialize_handler_enable(sc->arpcom.ac_if.if_serializer);

	REG_WR(sc, BCE_PCICFG_INT_ACK_CMD,
	       BCE_PCICFG_INT_ACK_CMD_INDEX_VALID |
	       BCE_PCICFG_INT_ACK_CMD_MASK_INT | sc->last_status_idx);

	REG_WR(sc, BCE_PCICFG_INT_ACK_CMD,
	       BCE_PCICFG_INT_ACK_CMD_INDEX_VALID | sc->last_status_idx);

	val = REG_RD(sc, BCE_HC_COMMAND);
	REG_WR(sc, BCE_HC_COMMAND, val | BCE_HC_COMMAND_COAL_NOW);
}


/****************************************************************************/
/* Handles controller initialization.                                       */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_init(void *xsc)
{
	struct bce_softc *sc = xsc;
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint32_t ether_mtu;
	int error;

	ASSERT_SERIALIZED(ifp->if_serializer);

	/* Check if the driver is still running and bail out if it is. */
	if (ifp->if_flags & IFF_RUNNING)
		return;

	bce_stop(sc);

	error = bce_reset(sc, BCE_DRV_MSG_CODE_RESET);
	if (error) {
		if_printf(ifp, "Controller reset failed!\n");
		goto back;
	}

	error = bce_chipinit(sc);
	if (error) {
		if_printf(ifp, "Controller initialization failed!\n");
		goto back;
	}

	error = bce_blockinit(sc);
	if (error) {
		if_printf(ifp, "Block initialization failed!\n");
		goto back;
	}

	/* Load our MAC address. */
	bcopy(IF_LLADDR(ifp), sc->eaddr, ETHER_ADDR_LEN);
	bce_set_mac_addr(sc);

	/* Calculate and program the Ethernet MTU size. */
	ether_mtu = ETHER_HDR_LEN + EVL_ENCAPLEN + ifp->if_mtu + ETHER_CRC_LEN;

	DBPRINT(sc, BCE_INFO, "%s(): setting mtu = %d\n", __func__, ether_mtu);

	/* 
	 * Program the mtu, enabling jumbo frame 
	 * support if necessary.  Also set the mbuf
	 * allocation count for RX frames.
	 */
	if (ether_mtu > ETHER_MAX_LEN + EVL_ENCAPLEN) {
#ifdef notyet
		REG_WR(sc, BCE_EMAC_RX_MTU_SIZE,
		       min(ether_mtu, BCE_MAX_JUMBO_ETHER_MTU) |
		       BCE_EMAC_RX_MTU_SIZE_JUMBO_ENA);
		sc->mbuf_alloc_size = MJUM9BYTES;
#else
		panic("jumbo buffer is not supported yet\n");
#endif
	} else {
		REG_WR(sc, BCE_EMAC_RX_MTU_SIZE, ether_mtu);
		sc->mbuf_alloc_size = MCLBYTES;
	}

	/* Calculate the RX Ethernet frame size for rx_bd's. */
	sc->max_frame_size = sizeof(struct l2_fhdr) + 2 + ether_mtu + 8;

	DBPRINT(sc, BCE_INFO,
		"%s(): mclbytes = %d, mbuf_alloc_size = %d, "
		"max_frame_size = %d\n",
		__func__, (int)MCLBYTES, sc->mbuf_alloc_size,
		sc->max_frame_size);

	/* Program appropriate promiscuous/multicast filtering. */
	bce_set_rx_mode(sc);

	/* Init RX buffer descriptor chain. */
	bce_init_rx_chain(sc);	/* XXX return value */

	/* Init TX buffer descriptor chain. */
	bce_init_tx_chain(sc);	/* XXX return value */

#ifdef DEVICE_POLLING
	/* Disable interrupts if we are polling. */
	if (ifp->if_flags & IFF_POLLING) {
		bce_disable_intr(sc);

		REG_WR(sc, BCE_HC_RX_QUICK_CONS_TRIP,
		       (1 << 16) | sc->bce_rx_quick_cons_trip);
		REG_WR(sc, BCE_HC_TX_QUICK_CONS_TRIP,
		       (1 << 16) | sc->bce_tx_quick_cons_trip);
	} else
#endif
	/* Enable host interrupts. */
	bce_enable_intr(sc);

	bce_ifmedia_upd(ifp);

	ifp->if_flags |= IFF_RUNNING;
	ifp->if_flags &= ~IFF_OACTIVE;

	callout_reset(&sc->bce_stat_ch, hz, bce_tick, sc);
back:
	if (error)
		bce_stop(sc);
}


/****************************************************************************/
/* Initialize the controller just enough so that any management firmware    */
/* running on the device will continue to operate corectly.                 */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_mgmt_init(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint32_t val;

	/* Check if the driver is still running and bail out if it is. */
	if (ifp->if_flags & IFF_RUNNING)
		return;

	/* Initialize the on-boards CPUs */
	bce_init_cpus(sc);

	/* Set the page size and clear the RV2P processor stall bits. */
	val = (BCM_PAGE_BITS - 8) << 24;
	REG_WR(sc, BCE_RV2P_CONFIG, val);

	/* Enable all critical blocks in the MAC. */
	REG_WR(sc, BCE_MISC_ENABLE_SET_BITS,
	       BCE_MISC_ENABLE_SET_BITS_RX_V2P_ENABLE |
	       BCE_MISC_ENABLE_SET_BITS_RX_DMA_ENABLE |
	       BCE_MISC_ENABLE_SET_BITS_COMPLETION_ENABLE);
	REG_RD(sc, BCE_MISC_ENABLE_SET_BITS);
	DELAY(20);

	bce_ifmedia_upd(ifp);
}


/****************************************************************************/
/* Encapsultes an mbuf cluster into the tx_bd chain structure and makes the */
/* memory visible to the controller.                                        */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_encap(struct bce_softc *sc, struct mbuf **m_head)
{
	bus_dma_segment_t segs[BCE_MAX_SEGMENTS];
	bus_dmamap_t map, tmp_map;
	struct mbuf *m0 = *m_head;
	struct tx_bd *txbd = NULL;
	uint16_t vlan_tag = 0, flags = 0;
	uint16_t chain_prod, chain_prod_start, prod;
	uint32_t prod_bseq;
	int i, error, maxsegs, nsegs;
#ifdef BCE_DEBUG
	uint16_t debug_prod;
#endif

	/* Transfer any checksum offload flags to the bd. */
	if (m0->m_pkthdr.csum_flags) {
		if (m0->m_pkthdr.csum_flags & CSUM_IP)
			flags |= TX_BD_FLAGS_IP_CKSUM;
		if (m0->m_pkthdr.csum_flags & (CSUM_TCP | CSUM_UDP))
			flags |= TX_BD_FLAGS_TCP_UDP_CKSUM;
	}

	/* Transfer any VLAN tags to the bd. */
	if (m0->m_flags & M_VLANTAG) {
		flags |= TX_BD_FLAGS_VLAN_TAG;
		vlan_tag = m0->m_pkthdr.ether_vlantag;
	}

	prod = sc->tx_prod;
	chain_prod_start = chain_prod = TX_CHAIN_IDX(prod);

	/* Map the mbuf into DMAable memory. */
	map = sc->tx_mbuf_map[chain_prod_start];

	maxsegs = sc->max_tx_bd - sc->used_tx_bd;
	KASSERT(maxsegs >= BCE_TX_SPARE_SPACE,
		("not enough segements %d\n", maxsegs));
	if (maxsegs > BCE_MAX_SEGMENTS)
		maxsegs = BCE_MAX_SEGMENTS;

	/* Map the mbuf into our DMA address space. */
	error = bus_dmamap_load_mbuf_defrag(sc->tx_mbuf_tag, map, m_head,
			segs, maxsegs, &nsegs, BUS_DMA_NOWAIT);
	if (error)
		goto back;
	bus_dmamap_sync(sc->tx_mbuf_tag, map, BUS_DMASYNC_PREWRITE);

	/* Reset m0 */
	m0 = *m_head;

	/* prod points to an empty tx_bd at this point. */
	prod_bseq  = sc->tx_prod_bseq;

#ifdef BCE_DEBUG
	debug_prod = chain_prod;
#endif

	DBPRINT(sc, BCE_INFO_SEND,
		"%s(): Start: prod = 0x%04X, chain_prod = %04X, "
		"prod_bseq = 0x%08X\n",
		__func__, prod, chain_prod, prod_bseq);

	/*
	 * Cycle through each mbuf segment that makes up
	 * the outgoing frame, gathering the mapping info
	 * for that segment and creating a tx_bd to for
	 * the mbuf.
	 */
	for (i = 0; i < nsegs; i++) {
		chain_prod = TX_CHAIN_IDX(prod);
		txbd= &sc->tx_bd_chain[TX_PAGE(chain_prod)][TX_IDX(chain_prod)];

		txbd->tx_bd_haddr_lo = htole32(BCE_ADDR_LO(segs[i].ds_addr));
		txbd->tx_bd_haddr_hi = htole32(BCE_ADDR_HI(segs[i].ds_addr));
		txbd->tx_bd_mss_nbytes = htole16(segs[i].ds_len);
		txbd->tx_bd_vlan_tag = htole16(vlan_tag);
		txbd->tx_bd_flags = htole16(flags);
		prod_bseq += segs[i].ds_len;
		if (i == 0)
			txbd->tx_bd_flags |= htole16(TX_BD_FLAGS_START);
		prod = NEXT_TX_BD(prod);
	}

	/* Set the END flag on the last TX buffer descriptor. */
	txbd->tx_bd_flags |= htole16(TX_BD_FLAGS_END);

	DBRUN(BCE_EXCESSIVE_SEND,
	      bce_dump_tx_chain(sc, debug_prod, nsegs));

	DBPRINT(sc, BCE_INFO_SEND,
		"%s(): End: prod = 0x%04X, chain_prod = %04X, "
		"prod_bseq = 0x%08X\n",
		__func__, prod, chain_prod, prod_bseq);

	/*
	 * Ensure that the mbuf pointer for this transmission
	 * is placed at the array index of the last
	 * descriptor in this chain.  This is done
	 * because a single map is used for all 
	 * segments of the mbuf and we don't want to
	 * unload the map before all of the segments
	 * have been freed.
	 */
	sc->tx_mbuf_ptr[chain_prod] = m0;

	tmp_map = sc->tx_mbuf_map[chain_prod];
	sc->tx_mbuf_map[chain_prod] = map;
	sc->tx_mbuf_map[chain_prod_start] = tmp_map;

	sc->used_tx_bd += nsegs;

	/* Update some debug statistic counters */
	DBRUNIF((sc->used_tx_bd > sc->tx_hi_watermark),
		sc->tx_hi_watermark = sc->used_tx_bd);
	DBRUNIF((sc->used_tx_bd == sc->max_tx_bd), sc->tx_full_count++);
	DBRUNIF(1, sc->tx_mbuf_alloc++);

	DBRUN(BCE_VERBOSE_SEND,
	      bce_dump_tx_mbuf_chain(sc, chain_prod, nsegs));

	/* prod points to the next free tx_bd at this point. */
	sc->tx_prod = prod;
	sc->tx_prod_bseq = prod_bseq;
back:
	if (error) {
		m_freem(*m_head);
		*m_head = NULL;
	}
	return error;
}


/****************************************************************************/
/* Main transmit routine when called from another routine with a lock.      */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_start(struct ifnet *ifp)
{
	struct bce_softc *sc = ifp->if_softc;
	int count = 0;

	ASSERT_SERIALIZED(ifp->if_serializer);

	/* If there's no link or the transmit queue is empty then just exit. */
	if (!sc->bce_link) {
		ifq_purge(&ifp->if_snd);
		return;
	}

	if ((ifp->if_flags & (IFF_RUNNING | IFF_OACTIVE)) != IFF_RUNNING)
		return;

	DBPRINT(sc, BCE_INFO_SEND,
		"%s(): Start: tx_prod = 0x%04X, tx_chain_prod = %04X, "
		"tx_prod_bseq = 0x%08X\n",
		__func__,
		sc->tx_prod, TX_CHAIN_IDX(sc->tx_prod), sc->tx_prod_bseq);

	for (;;) {
		struct mbuf *m_head;

		/*
		 * We keep BCE_TX_SPARE_SPACE entries, so bce_encap() is
		 * unlikely to fail.
		 */
		if (sc->max_tx_bd - sc->used_tx_bd < BCE_TX_SPARE_SPACE) {
			ifp->if_flags |= IFF_OACTIVE;
			break;
		}

		/* Check for any frames to send. */
		m_head = ifq_dequeue(&ifp->if_snd, NULL);
		if (m_head == NULL)
			break;

		/*
		 * Pack the data into the transmit ring. If we
		 * don't have room, place the mbuf back at the
		 * head of the queue and set the OACTIVE flag
		 * to wait for the NIC to drain the chain.
		 */
		if (bce_encap(sc, &m_head)) {
			ifp->if_oerrors++;
			if (sc->used_tx_bd == 0) {
				continue;
			} else {
				ifp->if_flags |= IFF_OACTIVE;
				break;
			}
		}

		count++;

		/* Send a copy of the frame to any BPF listeners. */
		ETHER_BPF_MTAP(ifp, m_head);
	}

	if (count == 0) {
		/* no packets were dequeued */
		DBPRINT(sc, BCE_VERBOSE_SEND,
			"%s(): No packets were dequeued\n", __func__);
		return;
	}

	DBPRINT(sc, BCE_INFO_SEND,
		"%s(): End: tx_prod = 0x%04X, tx_chain_prod = 0x%04X, "
		"tx_prod_bseq = 0x%08X\n",
		__func__,
		sc->tx_prod, TX_CHAIN_IDX(sc->tx_prod), sc->tx_prod_bseq);

	/* Start the transmit. */
	REG_WR16(sc, MB_TX_CID_ADDR + BCE_L2CTX_TX_HOST_BIDX, sc->tx_prod);
	REG_WR(sc, MB_TX_CID_ADDR + BCE_L2CTX_TX_HOST_BSEQ, sc->tx_prod_bseq);

	/* Set the tx timeout. */
	ifp->if_timer = BCE_TX_TIMEOUT;
}


/****************************************************************************/
/* Handles any IOCTL calls from the operating system.                       */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_ioctl(struct ifnet *ifp, u_long command, caddr_t data, struct ucred *cr)
{
	struct bce_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	struct mii_data *mii;
	int mask, error = 0;

	ASSERT_SERIALIZED(ifp->if_serializer);

	switch(command) {
	case SIOCSIFMTU:
		/* Check that the MTU setting is supported. */
		if (ifr->ifr_mtu < BCE_MIN_MTU ||
#ifdef notyet
		    ifr->ifr_mtu > BCE_MAX_JUMBO_MTU
#else
		    ifr->ifr_mtu > ETHERMTU
#endif
		   ) {
			error = EINVAL;
			break;
		}

		DBPRINT(sc, BCE_INFO, "Setting new MTU of %d\n", ifr->ifr_mtu);

		ifp->if_mtu = ifr->ifr_mtu;
		ifp->if_flags &= ~IFF_RUNNING;	/* Force reinitialize */
		bce_init(sc);
		break;

	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			if (ifp->if_flags & IFF_RUNNING) {
				mask = ifp->if_flags ^ sc->bce_if_flags;

				if (mask & (IFF_PROMISC | IFF_ALLMULTI))
					bce_set_rx_mode(sc);
			} else {
				bce_init(sc);
			}
		} else if (ifp->if_flags & IFF_RUNNING) {
			bce_stop(sc);
		}
		sc->bce_if_flags = ifp->if_flags;
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		if (ifp->if_flags & IFF_RUNNING)
			bce_set_rx_mode(sc);
		break;

	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
		DBPRINT(sc, BCE_VERBOSE, "bce_phy_flags = 0x%08X\n",
			sc->bce_phy_flags);
		DBPRINT(sc, BCE_VERBOSE, "Copper media set/get\n");

		mii = device_get_softc(sc->bce_miibus);
		error = ifmedia_ioctl(ifp, ifr, &mii->mii_media, command);
		break;

	case SIOCSIFCAP:
		mask = ifr->ifr_reqcap ^ ifp->if_capenable;
		DBPRINT(sc, BCE_INFO, "Received SIOCSIFCAP = 0x%08X\n",
			(uint32_t) mask);

		if (mask & IFCAP_HWCSUM) {
			ifp->if_capenable ^= (mask & IFCAP_HWCSUM);
			if (IFCAP_HWCSUM & ifp->if_capenable)
				ifp->if_hwassist = BCE_IF_HWASSIST;
			else
				ifp->if_hwassist = 0;
		}
		break;

	default:
		error = ether_ioctl(ifp, command, data);
		break;
	}
	return error;
}


/****************************************************************************/
/* Transmit timeout handler.                                                */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_watchdog(struct ifnet *ifp)
{
	struct bce_softc *sc = ifp->if_softc;

	ASSERT_SERIALIZED(ifp->if_serializer);

	DBRUN(BCE_VERBOSE_SEND,
	      bce_dump_driver_state(sc);
	      bce_dump_status_block(sc));

	/*
	 * If we are in this routine because of pause frames, then
	 * don't reset the hardware.
	 */
	if (REG_RD(sc, BCE_EMAC_TX_STATUS) & BCE_EMAC_TX_STATUS_XOFFED)	
		return;

	if_printf(ifp, "Watchdog timeout occurred, resetting!\n");

	/* DBRUN(BCE_FATAL, bce_breakpoint(sc)); */

	ifp->if_flags &= ~IFF_RUNNING;	/* Force reinitialize */
	bce_init(sc);

	ifp->if_oerrors++;

	if (!ifq_is_empty(&ifp->if_snd))
		if_devstart(ifp);
}


#ifdef DEVICE_POLLING

static void
bce_poll(struct ifnet *ifp, enum poll_cmd cmd, int count)
{
	struct bce_softc *sc = ifp->if_softc;
	struct status_block *sblk = sc->status_block;
	uint16_t hw_tx_cons, hw_rx_cons;

	ASSERT_SERIALIZED(ifp->if_serializer);

	switch (cmd) {
	case POLL_REGISTER:
		bce_disable_intr(sc);

		REG_WR(sc, BCE_HC_RX_QUICK_CONS_TRIP,
		       (1 << 16) | sc->bce_rx_quick_cons_trip);
		REG_WR(sc, BCE_HC_TX_QUICK_CONS_TRIP,
		       (1 << 16) | sc->bce_tx_quick_cons_trip);
		return;
	case POLL_DEREGISTER:
		bce_enable_intr(sc);

		REG_WR(sc, BCE_HC_TX_QUICK_CONS_TRIP,
		       (sc->bce_tx_quick_cons_trip_int << 16) |
		       sc->bce_tx_quick_cons_trip);
		REG_WR(sc, BCE_HC_RX_QUICK_CONS_TRIP,
		       (sc->bce_rx_quick_cons_trip_int << 16) |
		       sc->bce_rx_quick_cons_trip);
		return;
	default:
		break;
	}

	if (cmd == POLL_AND_CHECK_STATUS) {
		uint32_t status_attn_bits;

		status_attn_bits = sblk->status_attn_bits;

		DBRUNIF(DB_RANDOMTRUE(bce_debug_unexpected_attention),
			if_printf(ifp,
			"Simulating unexpected status attention bit set.");
			status_attn_bits |= STATUS_ATTN_BITS_PARITY_ERROR);

		/* Was it a link change interrupt? */
		if ((status_attn_bits & STATUS_ATTN_BITS_LINK_STATE) !=
		    (sblk->status_attn_bits_ack & STATUS_ATTN_BITS_LINK_STATE))
			bce_phy_intr(sc);

		/*
		 * If any other attention is asserted then
		 * the chip is toast.
		 */
		if ((status_attn_bits & ~STATUS_ATTN_BITS_LINK_STATE) !=
		     (sblk->status_attn_bits_ack &
		      ~STATUS_ATTN_BITS_LINK_STATE)) {
			DBRUN(1, sc->unexpected_attentions++);

			if_printf(ifp, "Fatal attention detected: 0x%08X\n",
				  sblk->status_attn_bits);

			DBRUN(BCE_FATAL,
			if (bce_debug_unexpected_attention == 0)
				bce_breakpoint(sc));

			bce_init(sc);
			return;
		}
	}

	hw_rx_cons = bce_get_hw_rx_cons(sc);
	hw_tx_cons = bce_get_hw_tx_cons(sc);

	/* Check for any completed RX frames. */
	if (hw_rx_cons != sc->hw_rx_cons)
		bce_rx_intr(sc, count);

	/* Check for any completed TX frames. */
	if (hw_tx_cons != sc->hw_tx_cons)
		bce_tx_intr(sc);

	/* Check for new frames to transmit. */
	if (!ifq_is_empty(&ifp->if_snd))
		if_devstart(ifp);
}

#endif	/* DEVICE_POLLING */


/*
 * Interrupt handler.
 */
/****************************************************************************/
/* Main interrupt entry point.  Verifies that the controller generated the  */
/* interrupt and then calls a separate routine for handle the various       */
/* interrupt causes (PHY, TX, RX).                                          */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static void
bce_intr(void *xsc)
{
	struct bce_softc *sc = xsc;
	struct ifnet *ifp = &sc->arpcom.ac_if;
	struct status_block *sblk;
	uint16_t hw_rx_cons, hw_tx_cons;

	ASSERT_SERIALIZED(ifp->if_serializer);

	DBPRINT(sc, BCE_EXCESSIVE, "Entering %s()\n", __func__);
	DBRUNIF(1, sc->interrupts_generated++);

	sblk = sc->status_block;

	/*
	 * If the hardware status block index matches the last value
	 * read by the driver and we haven't asserted our interrupt
	 * then there's nothing to do.
	 */
	if (sblk->status_idx == sc->last_status_idx &&
	    (REG_RD(sc, BCE_PCICFG_MISC_STATUS) &
	     BCE_PCICFG_MISC_STATUS_INTA_VALUE))
		return;

	/* Ack the interrupt and stop others from occuring. */
	REG_WR(sc, BCE_PCICFG_INT_ACK_CMD,
	       BCE_PCICFG_INT_ACK_CMD_USE_INT_HC_PARAM |
	       BCE_PCICFG_INT_ACK_CMD_MASK_INT);

	/* Check if the hardware has finished any work. */
	hw_rx_cons = bce_get_hw_rx_cons(sc);
	hw_tx_cons = bce_get_hw_tx_cons(sc);

	/* Keep processing data as long as there is work to do. */
	for (;;) {
		uint32_t status_attn_bits;

		status_attn_bits = sblk->status_attn_bits;

		DBRUNIF(DB_RANDOMTRUE(bce_debug_unexpected_attention),
			if_printf(ifp,
			"Simulating unexpected status attention bit set.");
			status_attn_bits |= STATUS_ATTN_BITS_PARITY_ERROR);

		/* Was it a link change interrupt? */
		if ((status_attn_bits & STATUS_ATTN_BITS_LINK_STATE) !=
		    (sblk->status_attn_bits_ack & STATUS_ATTN_BITS_LINK_STATE))
			bce_phy_intr(sc);

		/*
		 * If any other attention is asserted then
		 * the chip is toast.
		 */
		if ((status_attn_bits & ~STATUS_ATTN_BITS_LINK_STATE) !=
		     (sblk->status_attn_bits_ack &
		      ~STATUS_ATTN_BITS_LINK_STATE)) {
			DBRUN(1, sc->unexpected_attentions++);

			if_printf(ifp, "Fatal attention detected: 0x%08X\n",
				  sblk->status_attn_bits);

			DBRUN(BCE_FATAL,
			if (bce_debug_unexpected_attention == 0)
				bce_breakpoint(sc));

			bce_init(sc);
			return;
		}

		/* Check for any completed RX frames. */
		if (hw_rx_cons != sc->hw_rx_cons)
			bce_rx_intr(sc, -1);

		/* Check for any completed TX frames. */
		if (hw_tx_cons != sc->hw_tx_cons)
			bce_tx_intr(sc);

		/*
		 * Save the status block index value
		 * for use during the next interrupt.
		 */
		sc->last_status_idx = sblk->status_idx;

		/*
		 * Prevent speculative reads from getting
		 * ahead of the status block.
		 */
		bus_space_barrier(sc->bce_btag, sc->bce_bhandle, 0, 0,
				  BUS_SPACE_BARRIER_READ);

		/*
		 * If there's no work left then exit the
		 * interrupt service routine.
		 */
		hw_rx_cons = bce_get_hw_rx_cons(sc);
		hw_tx_cons = bce_get_hw_tx_cons(sc);
		if ((hw_rx_cons == sc->hw_rx_cons) && (hw_tx_cons == sc->hw_tx_cons))
			break;
	}

	/* Re-enable interrupts. */
	REG_WR(sc, BCE_PCICFG_INT_ACK_CMD,
	       BCE_PCICFG_INT_ACK_CMD_INDEX_VALID | sc->last_status_idx |
	       BCE_PCICFG_INT_ACK_CMD_MASK_INT);
	REG_WR(sc, BCE_PCICFG_INT_ACK_CMD,
	       BCE_PCICFG_INT_ACK_CMD_INDEX_VALID | sc->last_status_idx);

	if (sc->bce_coalchg_mask)
		bce_coal_change(sc);

	/* Handle any frames that arrived while handling the interrupt. */
	if (!ifq_is_empty(&ifp->if_snd))
		if_devstart(ifp);
}


/****************************************************************************/
/* Programs the various packet receive modes (broadcast and multicast).     */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_set_rx_mode(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	struct ifmultiaddr *ifma;
	uint32_t hashes[NUM_MC_HASH_REGISTERS] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	uint32_t rx_mode, sort_mode;
	int h, i;

	ASSERT_SERIALIZED(ifp->if_serializer);

	/* Initialize receive mode default settings. */
	rx_mode = sc->rx_mode &
		  ~(BCE_EMAC_RX_MODE_PROMISCUOUS |
		    BCE_EMAC_RX_MODE_KEEP_VLAN_TAG);
	sort_mode = 1 | BCE_RPM_SORT_USER0_BC_EN;

	/*
	 * ASF/IPMI/UMP firmware requires that VLAN tag stripping
	 * be enbled.
	 */
	if (!(BCE_IF_CAPABILITIES & IFCAP_VLAN_HWTAGGING) &&
	    !(sc->bce_flags & BCE_MFW_ENABLE_FLAG))
		rx_mode |= BCE_EMAC_RX_MODE_KEEP_VLAN_TAG;

	/*
	 * Check for promiscuous, all multicast, or selected
	 * multicast address filtering.
	 */
	if (ifp->if_flags & IFF_PROMISC) {
		DBPRINT(sc, BCE_INFO, "Enabling promiscuous mode.\n");

		/* Enable promiscuous mode. */
		rx_mode |= BCE_EMAC_RX_MODE_PROMISCUOUS;
		sort_mode |= BCE_RPM_SORT_USER0_PROM_EN;
	} else if (ifp->if_flags & IFF_ALLMULTI) {
		DBPRINT(sc, BCE_INFO, "Enabling all multicast mode.\n");

		/* Enable all multicast addresses. */
		for (i = 0; i < NUM_MC_HASH_REGISTERS; i++) {
			REG_WR(sc, BCE_EMAC_MULTICAST_HASH0 + (i * 4),
			       0xffffffff);
		}
		sort_mode |= BCE_RPM_SORT_USER0_MC_EN;
	} else {
		/* Accept one or more multicast(s). */
		DBPRINT(sc, BCE_INFO, "Enabling selective multicast mode.\n");

		TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
			if (ifma->ifma_addr->sa_family != AF_LINK)
				continue;
			h = ether_crc32_le(
			    LLADDR((struct sockaddr_dl *)ifma->ifma_addr),
			    ETHER_ADDR_LEN) & 0xFF;
			hashes[(h & 0xE0) >> 5] |= 1 << (h & 0x1F);
		}

		for (i = 0; i < NUM_MC_HASH_REGISTERS; i++) {
			REG_WR(sc, BCE_EMAC_MULTICAST_HASH0 + (i * 4),
			       hashes[i]);
		}
		sort_mode |= BCE_RPM_SORT_USER0_MC_HSH_EN;
	}

	/* Only make changes if the recive mode has actually changed. */
	if (rx_mode != sc->rx_mode) {
		DBPRINT(sc, BCE_VERBOSE, "Enabling new receive mode: 0x%08X\n",
			rx_mode);

		sc->rx_mode = rx_mode;
		REG_WR(sc, BCE_EMAC_RX_MODE, rx_mode);
	}

	/* Disable and clear the exisitng sort before enabling a new sort. */
	REG_WR(sc, BCE_RPM_SORT_USER0, 0x0);
	REG_WR(sc, BCE_RPM_SORT_USER0, sort_mode);
	REG_WR(sc, BCE_RPM_SORT_USER0, sort_mode | BCE_RPM_SORT_USER0_ENA);
}


/****************************************************************************/
/* Called periodically to updates statistics from the controllers           */
/* statistics block.                                                        */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_stats_update(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	struct statistics_block *stats = sc->stats_block;

	DBPRINT(sc, BCE_EXCESSIVE, "Entering %s()\n", __func__);

	ASSERT_SERIALIZED(ifp->if_serializer);

	/* 
	 * Update the interface statistics from the hardware statistics.
	 */
	ifp->if_collisions = (u_long)stats->stat_EtherStatsCollisions;

	ifp->if_ierrors = (u_long)stats->stat_EtherStatsUndersizePkts +
			  (u_long)stats->stat_EtherStatsOverrsizePkts +
			  (u_long)stats->stat_IfInMBUFDiscards +
			  (u_long)stats->stat_Dot3StatsAlignmentErrors +
			  (u_long)stats->stat_Dot3StatsFCSErrors;

	ifp->if_oerrors =
	(u_long)stats->stat_emac_tx_stat_dot3statsinternalmactransmiterrors +
	(u_long)stats->stat_Dot3StatsExcessiveCollisions +
	(u_long)stats->stat_Dot3StatsLateCollisions;

	/* 
	 * Certain controllers don't report carrier sense errors correctly.
	 * See errata E11_5708CA0_1165.
	 */
	if (!(BCE_CHIP_NUM(sc) == BCE_CHIP_NUM_5706) &&
	    !(BCE_CHIP_ID(sc) == BCE_CHIP_ID_5708_A0)) {
		ifp->if_oerrors +=
			(u_long)stats->stat_Dot3StatsCarrierSenseErrors;
	}

	/*
	 * Update the sysctl statistics from the hardware statistics.
	 */
	sc->stat_IfHCInOctets =
		((uint64_t)stats->stat_IfHCInOctets_hi << 32) +
		 (uint64_t)stats->stat_IfHCInOctets_lo;

	sc->stat_IfHCInBadOctets =
		((uint64_t)stats->stat_IfHCInBadOctets_hi << 32) +
		 (uint64_t)stats->stat_IfHCInBadOctets_lo;

	sc->stat_IfHCOutOctets =
		((uint64_t)stats->stat_IfHCOutOctets_hi << 32) +
		 (uint64_t)stats->stat_IfHCOutOctets_lo;

	sc->stat_IfHCOutBadOctets =
		((uint64_t)stats->stat_IfHCOutBadOctets_hi << 32) +
		 (uint64_t)stats->stat_IfHCOutBadOctets_lo;

	sc->stat_IfHCInUcastPkts =
		((uint64_t)stats->stat_IfHCInUcastPkts_hi << 32) +
		 (uint64_t)stats->stat_IfHCInUcastPkts_lo;

	sc->stat_IfHCInMulticastPkts =
		((uint64_t)stats->stat_IfHCInMulticastPkts_hi << 32) +
		 (uint64_t)stats->stat_IfHCInMulticastPkts_lo;

	sc->stat_IfHCInBroadcastPkts =
		((uint64_t)stats->stat_IfHCInBroadcastPkts_hi << 32) +
		 (uint64_t)stats->stat_IfHCInBroadcastPkts_lo;

	sc->stat_IfHCOutUcastPkts =
		((uint64_t)stats->stat_IfHCOutUcastPkts_hi << 32) +
		 (uint64_t)stats->stat_IfHCOutUcastPkts_lo;

	sc->stat_IfHCOutMulticastPkts =
		((uint64_t)stats->stat_IfHCOutMulticastPkts_hi << 32) +
		 (uint64_t)stats->stat_IfHCOutMulticastPkts_lo;

	sc->stat_IfHCOutBroadcastPkts =
		((uint64_t)stats->stat_IfHCOutBroadcastPkts_hi << 32) +
		 (uint64_t)stats->stat_IfHCOutBroadcastPkts_lo;

	sc->stat_emac_tx_stat_dot3statsinternalmactransmiterrors =
		stats->stat_emac_tx_stat_dot3statsinternalmactransmiterrors;

	sc->stat_Dot3StatsCarrierSenseErrors =
		stats->stat_Dot3StatsCarrierSenseErrors;

	sc->stat_Dot3StatsFCSErrors =
		stats->stat_Dot3StatsFCSErrors;

	sc->stat_Dot3StatsAlignmentErrors =
		stats->stat_Dot3StatsAlignmentErrors;

	sc->stat_Dot3StatsSingleCollisionFrames =
		stats->stat_Dot3StatsSingleCollisionFrames;

	sc->stat_Dot3StatsMultipleCollisionFrames =
		stats->stat_Dot3StatsMultipleCollisionFrames;

	sc->stat_Dot3StatsDeferredTransmissions =
		stats->stat_Dot3StatsDeferredTransmissions;

	sc->stat_Dot3StatsExcessiveCollisions =
		stats->stat_Dot3StatsExcessiveCollisions;

	sc->stat_Dot3StatsLateCollisions =
		stats->stat_Dot3StatsLateCollisions;

	sc->stat_EtherStatsCollisions =
		stats->stat_EtherStatsCollisions;

	sc->stat_EtherStatsFragments =
		stats->stat_EtherStatsFragments;

	sc->stat_EtherStatsJabbers =
		stats->stat_EtherStatsJabbers;

	sc->stat_EtherStatsUndersizePkts =
		stats->stat_EtherStatsUndersizePkts;

	sc->stat_EtherStatsOverrsizePkts =
		stats->stat_EtherStatsOverrsizePkts;

	sc->stat_EtherStatsPktsRx64Octets =
		stats->stat_EtherStatsPktsRx64Octets;

	sc->stat_EtherStatsPktsRx65Octetsto127Octets =
		stats->stat_EtherStatsPktsRx65Octetsto127Octets;

	sc->stat_EtherStatsPktsRx128Octetsto255Octets =
		stats->stat_EtherStatsPktsRx128Octetsto255Octets;

	sc->stat_EtherStatsPktsRx256Octetsto511Octets =
		stats->stat_EtherStatsPktsRx256Octetsto511Octets;

	sc->stat_EtherStatsPktsRx512Octetsto1023Octets =
		stats->stat_EtherStatsPktsRx512Octetsto1023Octets;

	sc->stat_EtherStatsPktsRx1024Octetsto1522Octets =
		stats->stat_EtherStatsPktsRx1024Octetsto1522Octets;

	sc->stat_EtherStatsPktsRx1523Octetsto9022Octets =
		stats->stat_EtherStatsPktsRx1523Octetsto9022Octets;

	sc->stat_EtherStatsPktsTx64Octets =
		stats->stat_EtherStatsPktsTx64Octets;

	sc->stat_EtherStatsPktsTx65Octetsto127Octets =
		stats->stat_EtherStatsPktsTx65Octetsto127Octets;

	sc->stat_EtherStatsPktsTx128Octetsto255Octets =
		stats->stat_EtherStatsPktsTx128Octetsto255Octets;

	sc->stat_EtherStatsPktsTx256Octetsto511Octets =
		stats->stat_EtherStatsPktsTx256Octetsto511Octets;

	sc->stat_EtherStatsPktsTx512Octetsto1023Octets =
		stats->stat_EtherStatsPktsTx512Octetsto1023Octets;

	sc->stat_EtherStatsPktsTx1024Octetsto1522Octets =
		stats->stat_EtherStatsPktsTx1024Octetsto1522Octets;

	sc->stat_EtherStatsPktsTx1523Octetsto9022Octets =
		stats->stat_EtherStatsPktsTx1523Octetsto9022Octets;

	sc->stat_XonPauseFramesReceived =
		stats->stat_XonPauseFramesReceived;

	sc->stat_XoffPauseFramesReceived =
		stats->stat_XoffPauseFramesReceived;

	sc->stat_OutXonSent =
		stats->stat_OutXonSent;

	sc->stat_OutXoffSent =
		stats->stat_OutXoffSent;

	sc->stat_FlowControlDone =
		stats->stat_FlowControlDone;

	sc->stat_MacControlFramesReceived =
		stats->stat_MacControlFramesReceived;

	sc->stat_XoffStateEntered =
		stats->stat_XoffStateEntered;

	sc->stat_IfInFramesL2FilterDiscards =
		stats->stat_IfInFramesL2FilterDiscards;

	sc->stat_IfInRuleCheckerDiscards =
		stats->stat_IfInRuleCheckerDiscards;

	sc->stat_IfInFTQDiscards =
		stats->stat_IfInFTQDiscards;

	sc->stat_IfInMBUFDiscards =
		stats->stat_IfInMBUFDiscards;

	sc->stat_IfInRuleCheckerP4Hit =
		stats->stat_IfInRuleCheckerP4Hit;

	sc->stat_CatchupInRuleCheckerDiscards =
		stats->stat_CatchupInRuleCheckerDiscards;

	sc->stat_CatchupInFTQDiscards =
		stats->stat_CatchupInFTQDiscards;

	sc->stat_CatchupInMBUFDiscards =
		stats->stat_CatchupInMBUFDiscards;

	sc->stat_CatchupInRuleCheckerP4Hit =
		stats->stat_CatchupInRuleCheckerP4Hit;

	sc->com_no_buffers = REG_RD_IND(sc, 0x120084);

	DBPRINT(sc, BCE_EXCESSIVE, "Exiting %s()\n", __func__);
}


/****************************************************************************/
/* Periodic function to perform maintenance tasks.                          */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_tick_serialized(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	struct mii_data *mii;
	uint32_t msg;

	ASSERT_SERIALIZED(ifp->if_serializer);

	/* Tell the firmware that the driver is still running. */
#ifdef BCE_DEBUG
	msg = (uint32_t)BCE_DRV_MSG_DATA_PULSE_CODE_ALWAYS_ALIVE;
#else
	msg = (uint32_t)++sc->bce_fw_drv_pulse_wr_seq;
#endif
	REG_WR_IND(sc, sc->bce_shmem_base + BCE_DRV_PULSE_MB, msg);

	/* Update the statistics from the hardware statistics block. */
	bce_stats_update(sc);

	/* Schedule the next tick. */
	callout_reset(&sc->bce_stat_ch, hz, bce_tick, sc);

	/* If link is up already up then we're done. */
	if (sc->bce_link)
		return;

	mii = device_get_softc(sc->bce_miibus);
	mii_tick(mii);

	/* Check if the link has come up. */
	if (!sc->bce_link && (mii->mii_media_status & IFM_ACTIVE) &&
	    IFM_SUBTYPE(mii->mii_media_active) != IFM_NONE) {
		sc->bce_link++;
		/* Now that link is up, handle any outstanding TX traffic. */
		if (!ifq_is_empty(&ifp->if_snd))
			if_devstart(ifp);
	}
}


static void
bce_tick(void *xsc)
{
	struct bce_softc *sc = xsc;
	struct ifnet *ifp = &sc->arpcom.ac_if;

	lwkt_serialize_enter(ifp->if_serializer);
	bce_tick_serialized(sc);
	lwkt_serialize_exit(ifp->if_serializer);
}


#ifdef BCE_DEBUG
/****************************************************************************/
/* Allows the driver state to be dumped through the sysctl interface.       */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_sysctl_driver_state(SYSCTL_HANDLER_ARGS)
{
        int error;
        int result;
        struct bce_softc *sc;

        result = -1;
        error = sysctl_handle_int(oidp, &result, 0, req);

        if (error || !req->newptr)
                return (error);

        if (result == 1) {
                sc = (struct bce_softc *)arg1;
                bce_dump_driver_state(sc);
        }

        return error;
}


/****************************************************************************/
/* Allows the hardware state to be dumped through the sysctl interface.     */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_sysctl_hw_state(SYSCTL_HANDLER_ARGS)
{
        int error;
        int result;
        struct bce_softc *sc;

        result = -1;
        error = sysctl_handle_int(oidp, &result, 0, req);

        if (error || !req->newptr)
                return (error);

        if (result == 1) {
                sc = (struct bce_softc *)arg1;
                bce_dump_hw_state(sc);
        }

        return error;
}


/****************************************************************************/
/* Provides a sysctl interface to allows dumping the RX chain.              */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_sysctl_dump_rx_chain(SYSCTL_HANDLER_ARGS)
{
        int error;
        int result;
        struct bce_softc *sc;

        result = -1;
        error = sysctl_handle_int(oidp, &result, 0, req);

        if (error || !req->newptr)
                return (error);

        if (result == 1) {
                sc = (struct bce_softc *)arg1;
                bce_dump_rx_chain(sc, 0, USABLE_RX_BD);
        }

        return error;
}


/****************************************************************************/
/* Provides a sysctl interface to allows dumping the TX chain.              */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_sysctl_dump_tx_chain(SYSCTL_HANDLER_ARGS)
{
        int error;
        int result;
        struct bce_softc *sc;

        result = -1;
        error = sysctl_handle_int(oidp, &result, 0, req);

        if (error || !req->newptr)
                return (error);

        if (result == 1) {
                sc = (struct bce_softc *)arg1;
                bce_dump_tx_chain(sc, 0, USABLE_TX_BD);
        }

        return error;
}


/****************************************************************************/
/* Provides a sysctl interface to allow reading arbitrary registers in the  */
/* device.  DO NOT ENABLE ON PRODUCTION SYSTEMS!                            */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_sysctl_reg_read(SYSCTL_HANDLER_ARGS)
{
	struct bce_softc *sc;
	int error;
	uint32_t val, result;

	result = -1;
	error = sysctl_handle_int(oidp, &result, 0, req);
	if (error || (req->newptr == NULL))
		return (error);

	/* Make sure the register is accessible. */
	if (result < 0x8000) {
		sc = (struct bce_softc *)arg1;
		val = REG_RD(sc, result);
		if_printf(&sc->arpcom.ac_if, "reg 0x%08X = 0x%08X\n",
			  result, val);
	} else if (result < 0x0280000) {
		sc = (struct bce_softc *)arg1;
		val = REG_RD_IND(sc, result);
		if_printf(&sc->arpcom.ac_if, "reg 0x%08X = 0x%08X\n",
			  result, val);
	}
	return (error);
}


/****************************************************************************/
/* Provides a sysctl interface to allow reading arbitrary PHY registers in  */
/* the device.  DO NOT ENABLE ON PRODUCTION SYSTEMS!                        */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_sysctl_phy_read(SYSCTL_HANDLER_ARGS)
{
	struct bce_softc *sc;
	device_t dev;
	int error, result;
	uint16_t val;

	result = -1;
	error = sysctl_handle_int(oidp, &result, 0, req);
	if (error || (req->newptr == NULL))
		return (error);

	/* Make sure the register is accessible. */
	if (result < 0x20) {
		sc = (struct bce_softc *)arg1;
		dev = sc->bce_dev;
		val = bce_miibus_read_reg(dev, sc->bce_phy_addr, result);
		if_printf(&sc->arpcom.ac_if,
			  "phy 0x%02X = 0x%04X\n", result, val);
	}
	return (error);
}


/****************************************************************************/
/* Provides a sysctl interface to forcing the driver to dump state and      */
/* enter the debugger.  DO NOT ENABLE ON PRODUCTION SYSTEMS!                */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static int
bce_sysctl_breakpoint(SYSCTL_HANDLER_ARGS)
{
        int error;
        int result;
        struct bce_softc *sc;

        result = -1;
        error = sysctl_handle_int(oidp, &result, 0, req);

        if (error || !req->newptr)
                return (error);

        if (result == 1) {
                sc = (struct bce_softc *)arg1;
                bce_breakpoint(sc);
        }

        return error;
}
#endif


/****************************************************************************/
/* Adds any sysctl parameters for tuning or debugging purposes.             */
/*                                                                          */
/* Returns:                                                                 */
/*   0 for success, positive value for failure.                             */
/****************************************************************************/
static void
bce_add_sysctls(struct bce_softc *sc)
{
	struct sysctl_ctx_list *ctx;
	struct sysctl_oid_list *children;

	sysctl_ctx_init(&sc->bce_sysctl_ctx);
	sc->bce_sysctl_tree = SYSCTL_ADD_NODE(&sc->bce_sysctl_ctx,
					      SYSCTL_STATIC_CHILDREN(_hw),
					      OID_AUTO,
					      device_get_nameunit(sc->bce_dev),
					      CTLFLAG_RD, 0, "");
	if (sc->bce_sysctl_tree == NULL) {
		device_printf(sc->bce_dev, "can't add sysctl node\n");
		return;
	}

	ctx = &sc->bce_sysctl_ctx;
	children = SYSCTL_CHILDREN(sc->bce_sysctl_tree);

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "tx_bds_int",
			CTLTYPE_INT | CTLFLAG_RW,
			sc, 0, bce_sysctl_tx_bds_int, "I",
			"Send max coalesced BD count during interrupt");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "tx_bds",
			CTLTYPE_INT | CTLFLAG_RW,
			sc, 0, bce_sysctl_tx_bds, "I",
			"Send max coalesced BD count");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "tx_ticks_int",
			CTLTYPE_INT | CTLFLAG_RW,
			sc, 0, bce_sysctl_tx_ticks_int, "I",
			"Send coalescing ticks during interrupt");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "tx_ticks",
			CTLTYPE_INT | CTLFLAG_RW,
			sc, 0, bce_sysctl_tx_ticks, "I",
			"Send coalescing ticks");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "rx_bds_int",
			CTLTYPE_INT | CTLFLAG_RW,
			sc, 0, bce_sysctl_rx_bds_int, "I",
			"Receive max coalesced BD count during interrupt");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "rx_bds",
			CTLTYPE_INT | CTLFLAG_RW,
			sc, 0, bce_sysctl_rx_bds, "I",
			"Receive max coalesced BD count");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "rx_ticks_int",
			CTLTYPE_INT | CTLFLAG_RW,
			sc, 0, bce_sysctl_rx_ticks_int, "I",
			"Receive coalescing ticks during interrupt");
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, "rx_ticks",
			CTLTYPE_INT | CTLFLAG_RW,
			sc, 0, bce_sysctl_rx_ticks, "I",
			"Receive coalescing ticks");

#ifdef BCE_DEBUG
	SYSCTL_ADD_INT(ctx, children, OID_AUTO, 
		"rx_low_watermark",
		CTLFLAG_RD, &sc->rx_low_watermark,
		0, "Lowest level of free rx_bd's");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, 
		"rx_empty_count",
		CTLFLAG_RD, &sc->rx_empty_count,
		0, "Number of times the RX chain was empty");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, 
		"tx_hi_watermark",
		CTLFLAG_RD, &sc->tx_hi_watermark,
		0, "Highest level of used tx_bd's");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, 
		"tx_full_count",
		CTLFLAG_RD, &sc->tx_full_count,
		0, "Number of times the TX chain was full");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, 
		"l2fhdr_status_errors",
		CTLFLAG_RD, &sc->l2fhdr_status_errors,
		0, "l2_fhdr status errors");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, 
		"unexpected_attentions",
		CTLFLAG_RD, &sc->unexpected_attentions,
		0, "unexpected attentions");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, 
		"lost_status_block_updates",
		CTLFLAG_RD, &sc->lost_status_block_updates,
		0, "lost status block updates");

	SYSCTL_ADD_INT(ctx, children, OID_AUTO, 
		"mbuf_alloc_failed",
		CTLFLAG_RD, &sc->mbuf_alloc_failed,
		0, "mbuf cluster allocation failures");
#endif

	SYSCTL_ADD_ULONG(ctx, children, OID_AUTO, 
		"stat_IfHCInOctets",
		CTLFLAG_RD, &sc->stat_IfHCInOctets,
		"Bytes received");

	SYSCTL_ADD_ULONG(ctx, children, OID_AUTO, 
		"stat_IfHCInBadOctets",
		CTLFLAG_RD, &sc->stat_IfHCInBadOctets,
		"Bad bytes received");

	SYSCTL_ADD_ULONG(ctx, children, OID_AUTO, 
		"stat_IfHCOutOctets",
		CTLFLAG_RD, &sc->stat_IfHCOutOctets,
		"Bytes sent");

	SYSCTL_ADD_ULONG(ctx, children, OID_AUTO, 
		"stat_IfHCOutBadOctets",
		CTLFLAG_RD, &sc->stat_IfHCOutBadOctets,
		"Bad bytes sent");

	SYSCTL_ADD_ULONG(ctx, children, OID_AUTO, 
		"stat_IfHCInUcastPkts",
		CTLFLAG_RD, &sc->stat_IfHCInUcastPkts,
		"Unicast packets received");

	SYSCTL_ADD_ULONG(ctx, children, OID_AUTO, 
		"stat_IfHCInMulticastPkts",
		CTLFLAG_RD, &sc->stat_IfHCInMulticastPkts,
		"Multicast packets received");

	SYSCTL_ADD_ULONG(ctx, children, OID_AUTO, 
		"stat_IfHCInBroadcastPkts",
		CTLFLAG_RD, &sc->stat_IfHCInBroadcastPkts,
		"Broadcast packets received");

	SYSCTL_ADD_ULONG(ctx, children, OID_AUTO, 
		"stat_IfHCOutUcastPkts",
		CTLFLAG_RD, &sc->stat_IfHCOutUcastPkts,
		"Unicast packets sent");

	SYSCTL_ADD_ULONG(ctx, children, OID_AUTO, 
		"stat_IfHCOutMulticastPkts",
		CTLFLAG_RD, &sc->stat_IfHCOutMulticastPkts,
		"Multicast packets sent");

	SYSCTL_ADD_ULONG(ctx, children, OID_AUTO, 
		"stat_IfHCOutBroadcastPkts",
		CTLFLAG_RD, &sc->stat_IfHCOutBroadcastPkts,
		"Broadcast packets sent");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_emac_tx_stat_dot3statsinternalmactransmiterrors",
		CTLFLAG_RD, &sc->stat_emac_tx_stat_dot3statsinternalmactransmiterrors,
		0, "Internal MAC transmit errors");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_Dot3StatsCarrierSenseErrors",
		CTLFLAG_RD, &sc->stat_Dot3StatsCarrierSenseErrors,
		0, "Carrier sense errors");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_Dot3StatsFCSErrors",
		CTLFLAG_RD, &sc->stat_Dot3StatsFCSErrors,
		0, "Frame check sequence errors");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_Dot3StatsAlignmentErrors",
		CTLFLAG_RD, &sc->stat_Dot3StatsAlignmentErrors,
		0, "Alignment errors");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_Dot3StatsSingleCollisionFrames",
		CTLFLAG_RD, &sc->stat_Dot3StatsSingleCollisionFrames,
		0, "Single Collision Frames");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_Dot3StatsMultipleCollisionFrames",
		CTLFLAG_RD, &sc->stat_Dot3StatsMultipleCollisionFrames,
		0, "Multiple Collision Frames");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_Dot3StatsDeferredTransmissions",
		CTLFLAG_RD, &sc->stat_Dot3StatsDeferredTransmissions,
		0, "Deferred Transmissions");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_Dot3StatsExcessiveCollisions",
		CTLFLAG_RD, &sc->stat_Dot3StatsExcessiveCollisions,
		0, "Excessive Collisions");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_Dot3StatsLateCollisions",
		CTLFLAG_RD, &sc->stat_Dot3StatsLateCollisions,
		0, "Late Collisions");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsCollisions",
		CTLFLAG_RD, &sc->stat_EtherStatsCollisions,
		0, "Collisions");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsFragments",
		CTLFLAG_RD, &sc->stat_EtherStatsFragments,
		0, "Fragments");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsJabbers",
		CTLFLAG_RD, &sc->stat_EtherStatsJabbers,
		0, "Jabbers");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsUndersizePkts",
		CTLFLAG_RD, &sc->stat_EtherStatsUndersizePkts,
		0, "Undersize packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsOverrsizePkts",
		CTLFLAG_RD, &sc->stat_EtherStatsOverrsizePkts,
		0, "stat_EtherStatsOverrsizePkts");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsRx64Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsRx64Octets,
		0, "Bytes received in 64 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsRx65Octetsto127Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsRx65Octetsto127Octets,
		0, "Bytes received in 65 to 127 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsRx128Octetsto255Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsRx128Octetsto255Octets,
		0, "Bytes received in 128 to 255 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsRx256Octetsto511Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsRx256Octetsto511Octets,
		0, "Bytes received in 256 to 511 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsRx512Octetsto1023Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsRx512Octetsto1023Octets,
		0, "Bytes received in 512 to 1023 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsRx1024Octetsto1522Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsRx1024Octetsto1522Octets,
		0, "Bytes received in 1024 t0 1522 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsRx1523Octetsto9022Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsRx1523Octetsto9022Octets,
		0, "Bytes received in 1523 to 9022 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsTx64Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsTx64Octets,
		0, "Bytes sent in 64 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsTx65Octetsto127Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsTx65Octetsto127Octets,
		0, "Bytes sent in 65 to 127 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsTx128Octetsto255Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsTx128Octetsto255Octets,
		0, "Bytes sent in 128 to 255 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsTx256Octetsto511Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsTx256Octetsto511Octets,
		0, "Bytes sent in 256 to 511 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsTx512Octetsto1023Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsTx512Octetsto1023Octets,
		0, "Bytes sent in 512 to 1023 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsTx1024Octetsto1522Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsTx1024Octetsto1522Octets,
		0, "Bytes sent in 1024 to 1522 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_EtherStatsPktsTx1523Octetsto9022Octets",
		CTLFLAG_RD, &sc->stat_EtherStatsPktsTx1523Octetsto9022Octets,
		0, "Bytes sent in 1523 to 9022 byte packets");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_XonPauseFramesReceived",
		CTLFLAG_RD, &sc->stat_XonPauseFramesReceived,
		0, "XON pause frames receved");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_XoffPauseFramesReceived",
		CTLFLAG_RD, &sc->stat_XoffPauseFramesReceived,
		0, "XOFF pause frames received");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_OutXonSent",
		CTLFLAG_RD, &sc->stat_OutXonSent,
		0, "XON pause frames sent");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_OutXoffSent",
		CTLFLAG_RD, &sc->stat_OutXoffSent,
		0, "XOFF pause frames sent");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_FlowControlDone",
		CTLFLAG_RD, &sc->stat_FlowControlDone,
		0, "Flow control done");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_MacControlFramesReceived",
		CTLFLAG_RD, &sc->stat_MacControlFramesReceived,
		0, "MAC control frames received");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_XoffStateEntered",
		CTLFLAG_RD, &sc->stat_XoffStateEntered,
		0, "XOFF state entered");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_IfInFramesL2FilterDiscards",
		CTLFLAG_RD, &sc->stat_IfInFramesL2FilterDiscards,
		0, "Received L2 packets discarded");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_IfInRuleCheckerDiscards",
		CTLFLAG_RD, &sc->stat_IfInRuleCheckerDiscards,
		0, "Received packets discarded by rule");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_IfInFTQDiscards",
		CTLFLAG_RD, &sc->stat_IfInFTQDiscards,
		0, "Received packet FTQ discards");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_IfInMBUFDiscards",
		CTLFLAG_RD, &sc->stat_IfInMBUFDiscards,
		0, "Received packets discarded due to lack of controller buffer memory");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_IfInRuleCheckerP4Hit",
		CTLFLAG_RD, &sc->stat_IfInRuleCheckerP4Hit,
		0, "Received packets rule checker hits");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_CatchupInRuleCheckerDiscards",
		CTLFLAG_RD, &sc->stat_CatchupInRuleCheckerDiscards,
		0, "Received packets discarded in Catchup path");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_CatchupInFTQDiscards",
		CTLFLAG_RD, &sc->stat_CatchupInFTQDiscards,
		0, "Received packets discarded in FTQ in Catchup path");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_CatchupInMBUFDiscards",
		CTLFLAG_RD, &sc->stat_CatchupInMBUFDiscards,
		0, "Received packets discarded in controller buffer memory in Catchup path");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"stat_CatchupInRuleCheckerP4Hit",
		CTLFLAG_RD, &sc->stat_CatchupInRuleCheckerP4Hit,
		0, "Received packets rule checker hits in Catchup path");

	SYSCTL_ADD_UINT(ctx, children, OID_AUTO, 
		"com_no_buffers",
		CTLFLAG_RD, &sc->com_no_buffers,
		0, "Valid packets received but no RX buffers available");

#ifdef BCE_DEBUG
	SYSCTL_ADD_PROC(ctx, children, OID_AUTO,
		"driver_state", CTLTYPE_INT | CTLFLAG_RW,
		(void *)sc, 0,
		bce_sysctl_driver_state, "I", "Drive state information");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO,
		"hw_state", CTLTYPE_INT | CTLFLAG_RW,
		(void *)sc, 0,
		bce_sysctl_hw_state, "I", "Hardware state information");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO,
		"dump_rx_chain", CTLTYPE_INT | CTLFLAG_RW,
		(void *)sc, 0,
		bce_sysctl_dump_rx_chain, "I", "Dump rx_bd chain");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO,
		"dump_tx_chain", CTLTYPE_INT | CTLFLAG_RW,
		(void *)sc, 0,
		bce_sysctl_dump_tx_chain, "I", "Dump tx_bd chain");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO,
		"breakpoint", CTLTYPE_INT | CTLFLAG_RW,
		(void *)sc, 0,
		bce_sysctl_breakpoint, "I", "Driver breakpoint");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO,
		"reg_read", CTLTYPE_INT | CTLFLAG_RW,
		(void *)sc, 0,
		bce_sysctl_reg_read, "I", "Register read");

	SYSCTL_ADD_PROC(ctx, children, OID_AUTO, 
		"phy_read", CTLTYPE_INT | CTLFLAG_RW, 
		(void *)sc, 0, 
		bce_sysctl_phy_read, "I", "PHY register read");

#endif

}


/****************************************************************************/
/* BCE Debug Routines                                                       */
/****************************************************************************/
#ifdef BCE_DEBUG

/****************************************************************************/
/* Freezes the controller to allow for a cohesive state dump.               */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_freeze_controller(struct bce_softc *sc)
{
	uint32_t val;

	val = REG_RD(sc, BCE_MISC_COMMAND);
	val |= BCE_MISC_COMMAND_DISABLE_ALL;
	REG_WR(sc, BCE_MISC_COMMAND, val);
}


/****************************************************************************/
/* Unfreezes the controller after a freeze operation.  This may not always  */
/* work and the controller will require a reset!                            */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_unfreeze_controller(struct bce_softc *sc)
{
	uint32_t val;

	val = REG_RD(sc, BCE_MISC_COMMAND);
	val |= BCE_MISC_COMMAND_ENABLE_ALL;
	REG_WR(sc, BCE_MISC_COMMAND, val);
}


/****************************************************************************/
/* Prints out information about an mbuf.                                    */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_mbuf(struct bce_softc *sc, struct mbuf *m)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint32_t val_hi, val_lo;
	struct mbuf *mp = m;

	if (m == NULL) {
		/* Index out of range. */
		if_printf(ifp, "mbuf: null pointer\n");
		return;
	}

	while (mp) {
		val_hi = BCE_ADDR_HI(mp);
		val_lo = BCE_ADDR_LO(mp);
		if_printf(ifp, "mbuf: vaddr = 0x%08X:%08X, m_len = %d, "
			  "m_flags = ( ", val_hi, val_lo, mp->m_len);

		if (mp->m_flags & M_EXT)
			kprintf("M_EXT ");
		if (mp->m_flags & M_PKTHDR)
			kprintf("M_PKTHDR ");
		if (mp->m_flags & M_EOR)
			kprintf("M_EOR ");
#ifdef M_RDONLY
		if (mp->m_flags & M_RDONLY)
			kprintf("M_RDONLY ");
#endif

		val_hi = BCE_ADDR_HI(mp->m_data);
		val_lo = BCE_ADDR_LO(mp->m_data);
		kprintf(") m_data = 0x%08X:%08X\n", val_hi, val_lo);

		if (mp->m_flags & M_PKTHDR) {
			if_printf(ifp, "- m_pkthdr: flags = ( ");
			if (mp->m_flags & M_BCAST) 
				kprintf("M_BCAST ");
			if (mp->m_flags & M_MCAST)
				kprintf("M_MCAST ");
			if (mp->m_flags & M_FRAG)
				kprintf("M_FRAG ");
			if (mp->m_flags & M_FIRSTFRAG)
				kprintf("M_FIRSTFRAG ");
			if (mp->m_flags & M_LASTFRAG)
				kprintf("M_LASTFRAG ");
#ifdef M_VLANTAG
			if (mp->m_flags & M_VLANTAG)
				kprintf("M_VLANTAG ");
#endif
#ifdef M_PROMISC
			if (mp->m_flags & M_PROMISC)
				kprintf("M_PROMISC ");
#endif
			kprintf(") csum_flags = ( ");
			if (mp->m_pkthdr.csum_flags & CSUM_IP)
				kprintf("CSUM_IP ");
			if (mp->m_pkthdr.csum_flags & CSUM_TCP)
				kprintf("CSUM_TCP ");
			if (mp->m_pkthdr.csum_flags & CSUM_UDP)
				kprintf("CSUM_UDP ");
			if (mp->m_pkthdr.csum_flags & CSUM_IP_FRAGS)
				kprintf("CSUM_IP_FRAGS ");
			if (mp->m_pkthdr.csum_flags & CSUM_FRAGMENT)
				kprintf("CSUM_FRAGMENT ");
#ifdef CSUM_TSO
			if (mp->m_pkthdr.csum_flags & CSUM_TSO)
				kprintf("CSUM_TSO ");
#endif
			if (mp->m_pkthdr.csum_flags & CSUM_IP_CHECKED)
				kprintf("CSUM_IP_CHECKED ");
			if (mp->m_pkthdr.csum_flags & CSUM_IP_VALID)
				kprintf("CSUM_IP_VALID ");
			if (mp->m_pkthdr.csum_flags & CSUM_DATA_VALID)
				kprintf("CSUM_DATA_VALID ");
			kprintf(")\n");
		}

		if (mp->m_flags & M_EXT) {
			val_hi = BCE_ADDR_HI(mp->m_ext.ext_buf);
			val_lo = BCE_ADDR_LO(mp->m_ext.ext_buf);
			if_printf(ifp, "- m_ext: vaddr = 0x%08X:%08X, "
				  "ext_size = %d\n",
				  val_hi, val_lo, mp->m_ext.ext_size);
		}
		mp = mp->m_next;
	}
}


/****************************************************************************/
/* Prints out the mbufs in the TX mbuf chain.                               */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_tx_mbuf_chain(struct bce_softc *sc, int chain_prod, int count)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	int i;

	if_printf(ifp,
	"----------------------------"
	"  tx mbuf data  "
	"----------------------------\n");

	for (i = 0; i < count; i++) {
		if_printf(ifp, "txmbuf[%d]\n", chain_prod);
		bce_dump_mbuf(sc, sc->tx_mbuf_ptr[chain_prod]);
		chain_prod = TX_CHAIN_IDX(NEXT_TX_BD(chain_prod));
	}

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out the mbufs in the RX mbuf chain.                               */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_rx_mbuf_chain(struct bce_softc *sc, int chain_prod, int count)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	int i;

	if_printf(ifp,
	"----------------------------"
	"  rx mbuf data  "
	"----------------------------\n");

	for (i = 0; i < count; i++) {
		if_printf(ifp, "rxmbuf[0x%04X]\n", chain_prod);
		bce_dump_mbuf(sc, sc->rx_mbuf_ptr[chain_prod]);
		chain_prod = RX_CHAIN_IDX(NEXT_RX_BD(chain_prod));
	}

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out a tx_bd structure.                                            */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_txbd(struct bce_softc *sc, int idx, struct tx_bd *txbd)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;

	if (idx > MAX_TX_BD) {
		/* Index out of range. */
		if_printf(ifp, "tx_bd[0x%04X]: Invalid tx_bd index!\n", idx);
	} else if ((idx & USABLE_TX_BD_PER_PAGE) == USABLE_TX_BD_PER_PAGE) {
		/* TX Chain page pointer. */
		if_printf(ifp, "tx_bd[0x%04X]: haddr = 0x%08X:%08X, "
			  "chain page pointer\n",
			  idx, txbd->tx_bd_haddr_hi, txbd->tx_bd_haddr_lo);
	} else {
		/* Normal tx_bd entry. */
		if_printf(ifp, "tx_bd[0x%04X]: haddr = 0x%08X:%08X, "
			  "nbytes = 0x%08X, "
			  "vlan tag= 0x%04X, flags = 0x%04X (",
			  idx, txbd->tx_bd_haddr_hi, txbd->tx_bd_haddr_lo,
			  txbd->tx_bd_mss_nbytes,
			  txbd->tx_bd_vlan_tag, txbd->tx_bd_flags);

		if (txbd->tx_bd_flags & TX_BD_FLAGS_CONN_FAULT)
			kprintf(" CONN_FAULT");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_TCP_UDP_CKSUM)
			kprintf(" TCP_UDP_CKSUM");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_IP_CKSUM)
			kprintf(" IP_CKSUM");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_VLAN_TAG)
			kprintf("  VLAN");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_COAL_NOW)
			kprintf(" COAL_NOW");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_DONT_GEN_CRC)
			kprintf(" DONT_GEN_CRC");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_START)
			kprintf(" START");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_END)
			kprintf(" END");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_SW_LSO)
			kprintf(" LSO");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_SW_OPTION_WORD)
			kprintf(" OPTION_WORD");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_SW_FLAGS)
			kprintf(" FLAGS");

		if (txbd->tx_bd_flags & TX_BD_FLAGS_SW_SNAP)
			kprintf(" SNAP");

		kprintf(" )\n");
	}
}


/****************************************************************************/
/* Prints out a rx_bd structure.                                            */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_rxbd(struct bce_softc *sc, int idx, struct rx_bd *rxbd)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;

	if (idx > MAX_RX_BD) {
		/* Index out of range. */
		if_printf(ifp, "rx_bd[0x%04X]: Invalid rx_bd index!\n", idx);
	} else if ((idx & USABLE_RX_BD_PER_PAGE) == USABLE_RX_BD_PER_PAGE) {
		/* TX Chain page pointer. */
		if_printf(ifp, "rx_bd[0x%04X]: haddr = 0x%08X:%08X, "
			  "chain page pointer\n",
			  idx, rxbd->rx_bd_haddr_hi, rxbd->rx_bd_haddr_lo);
	} else {
		/* Normal tx_bd entry. */
		if_printf(ifp, "rx_bd[0x%04X]: haddr = 0x%08X:%08X, "
			  "nbytes = 0x%08X, flags = 0x%08X\n",
			  idx, rxbd->rx_bd_haddr_hi, rxbd->rx_bd_haddr_lo,
			  rxbd->rx_bd_len, rxbd->rx_bd_flags);
	}
}


/****************************************************************************/
/* Prints out a l2_fhdr structure.                                          */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_l2fhdr(struct bce_softc *sc, int idx, struct l2_fhdr *l2fhdr)
{
	if_printf(&sc->arpcom.ac_if, "l2_fhdr[0x%04X]: status = 0x%08X, "
		  "pkt_len = 0x%04X, vlan = 0x%04x, "
		  "ip_xsum = 0x%04X, tcp_udp_xsum = 0x%04X\n",
		  idx, l2fhdr->l2_fhdr_status,
		  l2fhdr->l2_fhdr_pkt_len, l2fhdr->l2_fhdr_vlan_tag,
		  l2fhdr->l2_fhdr_ip_xsum, l2fhdr->l2_fhdr_tcp_udp_xsum);
}


/****************************************************************************/
/* Prints out the tx chain.                                                 */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_tx_chain(struct bce_softc *sc, int tx_prod, int count)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	int i;

	/* First some info about the tx_bd chain structure. */
	if_printf(ifp,
	"----------------------------"
	"  tx_bd  chain  "
	"----------------------------\n");

	if_printf(ifp, "page size      = 0x%08X, "
		  "tx chain pages        = 0x%08X\n",
		  (uint32_t)BCM_PAGE_SIZE, (uint32_t)TX_PAGES);

	if_printf(ifp, "tx_bd per page = 0x%08X, "
		  "usable tx_bd per page = 0x%08X\n",
		  (uint32_t)TOTAL_TX_BD_PER_PAGE,
		  (uint32_t)USABLE_TX_BD_PER_PAGE);

	if_printf(ifp, "total tx_bd    = 0x%08X\n", (uint32_t)TOTAL_TX_BD);

	if_printf(ifp,
	"----------------------------"
	"  tx_bd data    "
	"----------------------------\n");

	/* Now print out the tx_bd's themselves. */
	for (i = 0; i < count; i++) {
		struct tx_bd *txbd;

	 	txbd = &sc->tx_bd_chain[TX_PAGE(tx_prod)][TX_IDX(tx_prod)];
		bce_dump_txbd(sc, tx_prod, txbd);
		tx_prod = TX_CHAIN_IDX(NEXT_TX_BD(tx_prod));
	}

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out the rx chain.                                                 */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_rx_chain(struct bce_softc *sc, int rx_prod, int count)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	int i;

	/* First some info about the tx_bd chain structure. */
	if_printf(ifp,
	"----------------------------"
	"  rx_bd  chain  "
	"----------------------------\n");

	if_printf(ifp, "page size      = 0x%08X, "
		  "rx chain pages        = 0x%08X\n",
		  (uint32_t)BCM_PAGE_SIZE, (uint32_t)RX_PAGES);

	if_printf(ifp, "rx_bd per page = 0x%08X, "
		  "usable rx_bd per page = 0x%08X\n",
		  (uint32_t)TOTAL_RX_BD_PER_PAGE,
		  (uint32_t)USABLE_RX_BD_PER_PAGE);

	if_printf(ifp, "total rx_bd    = 0x%08X\n", (uint32_t)TOTAL_RX_BD);

	if_printf(ifp,
	"----------------------------"
	"   rx_bd data   "
	"----------------------------\n");

	/* Now print out the rx_bd's themselves. */
	for (i = 0; i < count; i++) {
		struct rx_bd *rxbd;

		rxbd = &sc->rx_bd_chain[RX_PAGE(rx_prod)][RX_IDX(rx_prod)];
		bce_dump_rxbd(sc, rx_prod, rxbd);
		rx_prod = RX_CHAIN_IDX(NEXT_RX_BD(rx_prod));
	}

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out the status block from host memory.                            */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_status_block(struct bce_softc *sc)
{
	struct status_block *sblk = sc->status_block;
	struct ifnet *ifp = &sc->arpcom.ac_if;

	if_printf(ifp,
	"----------------------------"
	"  Status Block  "
	"----------------------------\n");

	if_printf(ifp, "    0x%08X - attn_bits\n", sblk->status_attn_bits);

	if_printf(ifp, "    0x%08X - attn_bits_ack\n",
		  sblk->status_attn_bits_ack);

	if_printf(ifp, "0x%04X(0x%04X) - rx_cons0\n",
	    sblk->status_rx_quick_consumer_index0,
	    (uint16_t)RX_CHAIN_IDX(sblk->status_rx_quick_consumer_index0));

	if_printf(ifp, "0x%04X(0x%04X) - tx_cons0\n",
	    sblk->status_tx_quick_consumer_index0,
	    (uint16_t)TX_CHAIN_IDX(sblk->status_tx_quick_consumer_index0));

	if_printf(ifp, "        0x%04X - status_idx\n", sblk->status_idx);

	/* Theses indices are not used for normal L2 drivers. */
	if (sblk->status_rx_quick_consumer_index1) {
		if_printf(ifp, "0x%04X(0x%04X) - rx_cons1\n",
		sblk->status_rx_quick_consumer_index1,
		(uint16_t)RX_CHAIN_IDX(sblk->status_rx_quick_consumer_index1));
	}

	if (sblk->status_tx_quick_consumer_index1) {
		if_printf(ifp, "0x%04X(0x%04X) - tx_cons1\n",
		sblk->status_tx_quick_consumer_index1,
		(uint16_t)TX_CHAIN_IDX(sblk->status_tx_quick_consumer_index1));
	}

	if (sblk->status_rx_quick_consumer_index2) {
		if_printf(ifp, "0x%04X(0x%04X)- rx_cons2\n",
		sblk->status_rx_quick_consumer_index2,
		(uint16_t)RX_CHAIN_IDX(sblk->status_rx_quick_consumer_index2));
	}

	if (sblk->status_tx_quick_consumer_index2) {
		if_printf(ifp, "0x%04X(0x%04X) - tx_cons2\n",
		sblk->status_tx_quick_consumer_index2,
		(uint16_t)TX_CHAIN_IDX(sblk->status_tx_quick_consumer_index2));
	}

	if (sblk->status_rx_quick_consumer_index3) {
		if_printf(ifp, "0x%04X(0x%04X) - rx_cons3\n",
		sblk->status_rx_quick_consumer_index3,
		(uint16_t)RX_CHAIN_IDX(sblk->status_rx_quick_consumer_index3));
	}

	if (sblk->status_tx_quick_consumer_index3) {
		if_printf(ifp, "0x%04X(0x%04X) - tx_cons3\n",
		sblk->status_tx_quick_consumer_index3,
		(uint16_t)TX_CHAIN_IDX(sblk->status_tx_quick_consumer_index3));
	}

	if (sblk->status_rx_quick_consumer_index4 ||
	    sblk->status_rx_quick_consumer_index5) {
		if_printf(ifp, "rx_cons4  = 0x%08X, rx_cons5      = 0x%08X\n",
			  sblk->status_rx_quick_consumer_index4,
			  sblk->status_rx_quick_consumer_index5);
	}

	if (sblk->status_rx_quick_consumer_index6 ||
	    sblk->status_rx_quick_consumer_index7) {
		if_printf(ifp, "rx_cons6  = 0x%08X, rx_cons7      = 0x%08X\n",
			  sblk->status_rx_quick_consumer_index6,
			  sblk->status_rx_quick_consumer_index7);
	}

	if (sblk->status_rx_quick_consumer_index8 ||
	    sblk->status_rx_quick_consumer_index9) {
		if_printf(ifp, "rx_cons8  = 0x%08X, rx_cons9      = 0x%08X\n",
			  sblk->status_rx_quick_consumer_index8,
			  sblk->status_rx_quick_consumer_index9);
	}

	if (sblk->status_rx_quick_consumer_index10 ||
	    sblk->status_rx_quick_consumer_index11) {
		if_printf(ifp, "rx_cons10 = 0x%08X, rx_cons11     = 0x%08X\n",
			  sblk->status_rx_quick_consumer_index10,
			  sblk->status_rx_quick_consumer_index11);
	}

	if (sblk->status_rx_quick_consumer_index12 ||
	    sblk->status_rx_quick_consumer_index13) {
		if_printf(ifp, "rx_cons12 = 0x%08X, rx_cons13     = 0x%08X\n",
			  sblk->status_rx_quick_consumer_index12,
			  sblk->status_rx_quick_consumer_index13);
	}

	if (sblk->status_rx_quick_consumer_index14 ||
	    sblk->status_rx_quick_consumer_index15) {
		if_printf(ifp, "rx_cons14 = 0x%08X, rx_cons15     = 0x%08X\n",
			  sblk->status_rx_quick_consumer_index14,
			  sblk->status_rx_quick_consumer_index15);
	}

	if (sblk->status_completion_producer_index ||
	    sblk->status_cmd_consumer_index) {
		if_printf(ifp, "com_prod  = 0x%08X, cmd_cons      = 0x%08X\n",
			  sblk->status_completion_producer_index,
			  sblk->status_cmd_consumer_index);
	}

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out the statistics block.                                         */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_stats_block(struct bce_softc *sc)
{
	struct statistics_block *sblk = sc->stats_block;
	struct ifnet *ifp = &sc->arpcom.ac_if;

	if_printf(ifp,
	"---------------"
	" Stats Block  (All Stats Not Shown Are 0) "
	"---------------\n");

	if (sblk->stat_IfHCInOctets_hi || sblk->stat_IfHCInOctets_lo) {
		if_printf(ifp, "0x%08X:%08X : IfHcInOctets\n",
			  sblk->stat_IfHCInOctets_hi,
			  sblk->stat_IfHCInOctets_lo);
	}

	if (sblk->stat_IfHCInBadOctets_hi || sblk->stat_IfHCInBadOctets_lo) {
		if_printf(ifp, "0x%08X:%08X : IfHcInBadOctets\n",
			  sblk->stat_IfHCInBadOctets_hi,
			  sblk->stat_IfHCInBadOctets_lo);
	}

	if (sblk->stat_IfHCOutOctets_hi || sblk->stat_IfHCOutOctets_lo) {
		if_printf(ifp, "0x%08X:%08X : IfHcOutOctets\n",
			  sblk->stat_IfHCOutOctets_hi,
			  sblk->stat_IfHCOutOctets_lo);
	}

	if (sblk->stat_IfHCOutBadOctets_hi || sblk->stat_IfHCOutBadOctets_lo) {
		if_printf(ifp, "0x%08X:%08X : IfHcOutBadOctets\n",
			  sblk->stat_IfHCOutBadOctets_hi,
			  sblk->stat_IfHCOutBadOctets_lo);
	}

	if (sblk->stat_IfHCInUcastPkts_hi || sblk->stat_IfHCInUcastPkts_lo) {
		if_printf(ifp, "0x%08X:%08X : IfHcInUcastPkts\n",
			  sblk->stat_IfHCInUcastPkts_hi,
			  sblk->stat_IfHCInUcastPkts_lo);
	}

	if (sblk->stat_IfHCInBroadcastPkts_hi ||
	    sblk->stat_IfHCInBroadcastPkts_lo) {
		if_printf(ifp, "0x%08X:%08X : IfHcInBroadcastPkts\n",
			  sblk->stat_IfHCInBroadcastPkts_hi,
			  sblk->stat_IfHCInBroadcastPkts_lo);
	}

	if (sblk->stat_IfHCInMulticastPkts_hi ||
	    sblk->stat_IfHCInMulticastPkts_lo) {
		if_printf(ifp, "0x%08X:%08X : IfHcInMulticastPkts\n",
			  sblk->stat_IfHCInMulticastPkts_hi,
			  sblk->stat_IfHCInMulticastPkts_lo);
	}

	if (sblk->stat_IfHCOutUcastPkts_hi || sblk->stat_IfHCOutUcastPkts_lo) {
		if_printf(ifp, "0x%08X:%08X : IfHcOutUcastPkts\n",
			  sblk->stat_IfHCOutUcastPkts_hi,
			  sblk->stat_IfHCOutUcastPkts_lo);
	}

	if (sblk->stat_IfHCOutBroadcastPkts_hi ||
	    sblk->stat_IfHCOutBroadcastPkts_lo) {
		if_printf(ifp, "0x%08X:%08X : IfHcOutBroadcastPkts\n",
			  sblk->stat_IfHCOutBroadcastPkts_hi,
			  sblk->stat_IfHCOutBroadcastPkts_lo);
	}

	if (sblk->stat_IfHCOutMulticastPkts_hi ||
	    sblk->stat_IfHCOutMulticastPkts_lo) {
		if_printf(ifp, "0x%08X:%08X : IfHcOutMulticastPkts\n",
			  sblk->stat_IfHCOutMulticastPkts_hi,
			  sblk->stat_IfHCOutMulticastPkts_lo);
	}

	if (sblk->stat_emac_tx_stat_dot3statsinternalmactransmiterrors) {
		if_printf(ifp, "         0x%08X : "
		"emac_tx_stat_dot3statsinternalmactransmiterrors\n", 
		sblk->stat_emac_tx_stat_dot3statsinternalmactransmiterrors);
	}

	if (sblk->stat_Dot3StatsCarrierSenseErrors) {
		if_printf(ifp, "         0x%08X : "
			  "Dot3StatsCarrierSenseErrors\n",
			  sblk->stat_Dot3StatsCarrierSenseErrors);
	}

	if (sblk->stat_Dot3StatsFCSErrors) {
		if_printf(ifp, "         0x%08X : Dot3StatsFCSErrors\n",
			  sblk->stat_Dot3StatsFCSErrors);
	}

	if (sblk->stat_Dot3StatsAlignmentErrors) {
		if_printf(ifp, "         0x%08X : Dot3StatsAlignmentErrors\n",
			  sblk->stat_Dot3StatsAlignmentErrors);
	}

	if (sblk->stat_Dot3StatsSingleCollisionFrames) {
		if_printf(ifp, "         0x%08X : "
			  "Dot3StatsSingleCollisionFrames\n",
			  sblk->stat_Dot3StatsSingleCollisionFrames);
	}

	if (sblk->stat_Dot3StatsMultipleCollisionFrames) {
		if_printf(ifp, "         0x%08X : "
			  "Dot3StatsMultipleCollisionFrames\n",
			  sblk->stat_Dot3StatsMultipleCollisionFrames);
	}

	if (sblk->stat_Dot3StatsDeferredTransmissions) {
		if_printf(ifp, "         0x%08X : "
			  "Dot3StatsDeferredTransmissions\n",
			  sblk->stat_Dot3StatsDeferredTransmissions);
	}

	if (sblk->stat_Dot3StatsExcessiveCollisions) {
		if_printf(ifp, "         0x%08X : "
			  "Dot3StatsExcessiveCollisions\n",
			  sblk->stat_Dot3StatsExcessiveCollisions);
	}

	if (sblk->stat_Dot3StatsLateCollisions) {
		if_printf(ifp, "         0x%08X : Dot3StatsLateCollisions\n",
			  sblk->stat_Dot3StatsLateCollisions);
	}

	if (sblk->stat_EtherStatsCollisions) {
		if_printf(ifp, "         0x%08X : EtherStatsCollisions\n",
			  sblk->stat_EtherStatsCollisions);
	}

	if (sblk->stat_EtherStatsFragments)  {
		if_printf(ifp, "         0x%08X : EtherStatsFragments\n",
			  sblk->stat_EtherStatsFragments);
	}

	if (sblk->stat_EtherStatsJabbers) {
		if_printf(ifp, "         0x%08X : EtherStatsJabbers\n",
			  sblk->stat_EtherStatsJabbers);
	}

	if (sblk->stat_EtherStatsUndersizePkts) {
		if_printf(ifp, "         0x%08X : EtherStatsUndersizePkts\n",
			  sblk->stat_EtherStatsUndersizePkts);
	}

	if (sblk->stat_EtherStatsOverrsizePkts) {
		if_printf(ifp, "         0x%08X : EtherStatsOverrsizePkts\n",
			  sblk->stat_EtherStatsOverrsizePkts);
	}

	if (sblk->stat_EtherStatsPktsRx64Octets) {
		if_printf(ifp, "         0x%08X : EtherStatsPktsRx64Octets\n",
			  sblk->stat_EtherStatsPktsRx64Octets);
	}

	if (sblk->stat_EtherStatsPktsRx65Octetsto127Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsRx65Octetsto127Octets\n",
			  sblk->stat_EtherStatsPktsRx65Octetsto127Octets);
	}

	if (sblk->stat_EtherStatsPktsRx128Octetsto255Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsRx128Octetsto255Octets\n",
			  sblk->stat_EtherStatsPktsRx128Octetsto255Octets);
	}

	if (sblk->stat_EtherStatsPktsRx256Octetsto511Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsRx256Octetsto511Octets\n",
			  sblk->stat_EtherStatsPktsRx256Octetsto511Octets);
	}

	if (sblk->stat_EtherStatsPktsRx512Octetsto1023Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsRx512Octetsto1023Octets\n",
			  sblk->stat_EtherStatsPktsRx512Octetsto1023Octets);
	}

	if (sblk->stat_EtherStatsPktsRx1024Octetsto1522Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsRx1024Octetsto1522Octets\n",
			  sblk->stat_EtherStatsPktsRx1024Octetsto1522Octets);
	}

	if (sblk->stat_EtherStatsPktsRx1523Octetsto9022Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsRx1523Octetsto9022Octets\n",
			  sblk->stat_EtherStatsPktsRx1523Octetsto9022Octets);
	}

	if (sblk->stat_EtherStatsPktsTx64Octets) {
		if_printf(ifp, "         0x%08X : EtherStatsPktsTx64Octets\n",
			  sblk->stat_EtherStatsPktsTx64Octets);
	}

	if (sblk->stat_EtherStatsPktsTx65Octetsto127Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsTx65Octetsto127Octets\n",
			  sblk->stat_EtherStatsPktsTx65Octetsto127Octets);
	}

	if (sblk->stat_EtherStatsPktsTx128Octetsto255Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsTx128Octetsto255Octets\n",
			  sblk->stat_EtherStatsPktsTx128Octetsto255Octets);
	}

	if (sblk->stat_EtherStatsPktsTx256Octetsto511Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsTx256Octetsto511Octets\n",
			  sblk->stat_EtherStatsPktsTx256Octetsto511Octets);
	}

	if (sblk->stat_EtherStatsPktsTx512Octetsto1023Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsTx512Octetsto1023Octets\n",
			  sblk->stat_EtherStatsPktsTx512Octetsto1023Octets);
	}

	if (sblk->stat_EtherStatsPktsTx1024Octetsto1522Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsTx1024Octetsto1522Octets\n",
			  sblk->stat_EtherStatsPktsTx1024Octetsto1522Octets);
	}

	if (sblk->stat_EtherStatsPktsTx1523Octetsto9022Octets) {
		if_printf(ifp, "         0x%08X : "
			  "EtherStatsPktsTx1523Octetsto9022Octets\n",
			  sblk->stat_EtherStatsPktsTx1523Octetsto9022Octets);
	}

	if (sblk->stat_XonPauseFramesReceived) {
		if_printf(ifp, "         0x%08X : XonPauseFramesReceived\n",
			  sblk->stat_XonPauseFramesReceived);
	}

	if (sblk->stat_XoffPauseFramesReceived) {
		if_printf(ifp, "          0x%08X : XoffPauseFramesReceived\n",
			  sblk->stat_XoffPauseFramesReceived);
	}

	if (sblk->stat_OutXonSent) {
		if_printf(ifp, "         0x%08X : OutXoffSent\n",
			  sblk->stat_OutXonSent);
	}

	if (sblk->stat_OutXoffSent) {
		if_printf(ifp, "         0x%08X : OutXoffSent\n",
			  sblk->stat_OutXoffSent);
	}

	if (sblk->stat_FlowControlDone) {
		if_printf(ifp, "         0x%08X : FlowControlDone\n",
			  sblk->stat_FlowControlDone);
	}

	if (sblk->stat_MacControlFramesReceived) {
		if_printf(ifp, "         0x%08X : MacControlFramesReceived\n",
			  sblk->stat_MacControlFramesReceived);
	}

	if (sblk->stat_XoffStateEntered) {
		if_printf(ifp, "         0x%08X : XoffStateEntered\n",
			  sblk->stat_XoffStateEntered);
	}

	if (sblk->stat_IfInFramesL2FilterDiscards) {
		if_printf(ifp, "         0x%08X : IfInFramesL2FilterDiscards\n",			  sblk->stat_IfInFramesL2FilterDiscards);
	}

	if (sblk->stat_IfInRuleCheckerDiscards) {
		if_printf(ifp, "         0x%08X : IfInRuleCheckerDiscards\n",
			  sblk->stat_IfInRuleCheckerDiscards);
	}

	if (sblk->stat_IfInFTQDiscards) {
		if_printf(ifp, "         0x%08X : IfInFTQDiscards\n",
			  sblk->stat_IfInFTQDiscards);
	}

	if (sblk->stat_IfInMBUFDiscards) {
		if_printf(ifp, "         0x%08X : IfInMBUFDiscards\n",
			  sblk->stat_IfInMBUFDiscards);
	}

	if (sblk->stat_IfInRuleCheckerP4Hit) {
		if_printf(ifp, "         0x%08X : IfInRuleCheckerP4Hit\n",
			  sblk->stat_IfInRuleCheckerP4Hit);
	}

	if (sblk->stat_CatchupInRuleCheckerDiscards) {
		if_printf(ifp, "         0x%08X : "
			  "CatchupInRuleCheckerDiscards\n",
			  sblk->stat_CatchupInRuleCheckerDiscards);
	}

	if (sblk->stat_CatchupInFTQDiscards) {
		if_printf(ifp, "         0x%08X : CatchupInFTQDiscards\n",
			  sblk->stat_CatchupInFTQDiscards);
	}

	if (sblk->stat_CatchupInMBUFDiscards) {
		if_printf(ifp, "         0x%08X : CatchupInMBUFDiscards\n",
			  sblk->stat_CatchupInMBUFDiscards);
	}

	if (sblk->stat_CatchupInRuleCheckerP4Hit) {
		if_printf(ifp, "         0x%08X : CatchupInRuleCheckerP4Hit\n",
			  sblk->stat_CatchupInRuleCheckerP4Hit);
	}

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out a summary of the driver state.                                */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_driver_state(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint32_t val_hi, val_lo;

	if_printf(ifp,
	"-----------------------------"
	" Driver State "
	"-----------------------------\n");

	val_hi = BCE_ADDR_HI(sc);
	val_lo = BCE_ADDR_LO(sc);
	if_printf(ifp, "0x%08X:%08X - (sc) driver softc structure "
		  "virtual address\n", val_hi, val_lo);

	val_hi = BCE_ADDR_HI(sc->status_block);
	val_lo = BCE_ADDR_LO(sc->status_block);
	if_printf(ifp, "0x%08X:%08X - (sc->status_block) status block "
		  "virtual address\n", val_hi, val_lo);

	val_hi = BCE_ADDR_HI(sc->stats_block);
	val_lo = BCE_ADDR_LO(sc->stats_block);
	if_printf(ifp, "0x%08X:%08X - (sc->stats_block) statistics block "
		  "virtual address\n", val_hi, val_lo);

	val_hi = BCE_ADDR_HI(sc->tx_bd_chain);
	val_lo = BCE_ADDR_LO(sc->tx_bd_chain);
	if_printf(ifp, "0x%08X:%08X - (sc->tx_bd_chain) tx_bd chain "
		  "virtual adddress\n", val_hi, val_lo);

	val_hi = BCE_ADDR_HI(sc->rx_bd_chain);
	val_lo = BCE_ADDR_LO(sc->rx_bd_chain);
	if_printf(ifp, "0x%08X:%08X - (sc->rx_bd_chain) rx_bd chain "
		  "virtual address\n", val_hi, val_lo);

	val_hi = BCE_ADDR_HI(sc->tx_mbuf_ptr);
	val_lo = BCE_ADDR_LO(sc->tx_mbuf_ptr);
	if_printf(ifp, "0x%08X:%08X - (sc->tx_mbuf_ptr) tx mbuf chain "
		  "virtual address\n", val_hi, val_lo);

	val_hi = BCE_ADDR_HI(sc->rx_mbuf_ptr);
	val_lo = BCE_ADDR_LO(sc->rx_mbuf_ptr);
	if_printf(ifp, "0x%08X:%08X - (sc->rx_mbuf_ptr) rx mbuf chain "
		  "virtual address\n", val_hi, val_lo);

	if_printf(ifp, "         0x%08X - (sc->interrupts_generated) "
		  "h/w intrs\n", sc->interrupts_generated);

	if_printf(ifp, "         0x%08X - (sc->rx_interrupts) "
		  "rx interrupts handled\n", sc->rx_interrupts);

	if_printf(ifp, "         0x%08X - (sc->tx_interrupts) "
		  "tx interrupts handled\n", sc->tx_interrupts);

	if_printf(ifp, "         0x%08X - (sc->last_status_idx) "
		  "status block index\n", sc->last_status_idx);

	if_printf(ifp, "     0x%04X(0x%04X) - (sc->tx_prod) "
		  "tx producer index\n",
		  sc->tx_prod, (uint16_t)TX_CHAIN_IDX(sc->tx_prod));

	if_printf(ifp, "     0x%04X(0x%04X) - (sc->tx_cons) "
		  "tx consumer index\n",
		  sc->tx_cons, (uint16_t)TX_CHAIN_IDX(sc->tx_cons));

	if_printf(ifp, "         0x%08X - (sc->tx_prod_bseq) "
		  "tx producer bseq index\n", sc->tx_prod_bseq);

	if_printf(ifp, "     0x%04X(0x%04X) - (sc->rx_prod) "
		  "rx producer index\n",
		  sc->rx_prod, (uint16_t)RX_CHAIN_IDX(sc->rx_prod));

	if_printf(ifp, "     0x%04X(0x%04X) - (sc->rx_cons) "
		  "rx consumer index\n",
		  sc->rx_cons, (uint16_t)RX_CHAIN_IDX(sc->rx_cons));

	if_printf(ifp, "         0x%08X - (sc->rx_prod_bseq) "
		  "rx producer bseq index\n", sc->rx_prod_bseq);

	if_printf(ifp, "         0x%08X - (sc->rx_mbuf_alloc) "
		  "rx mbufs allocated\n", sc->rx_mbuf_alloc);

	if_printf(ifp, "         0x%08X - (sc->free_rx_bd) "
		  "free rx_bd's\n", sc->free_rx_bd);

	if_printf(ifp, "0x%08X/%08X - (sc->rx_low_watermark) rx "
		  "low watermark\n", sc->rx_low_watermark, sc->max_rx_bd);

	if_printf(ifp, "         0x%08X - (sc->txmbuf_alloc) "
		  "tx mbufs allocated\n", sc->tx_mbuf_alloc);

	if_printf(ifp, "         0x%08X - (sc->rx_mbuf_alloc) "
		  "rx mbufs allocated\n", sc->rx_mbuf_alloc);

	if_printf(ifp, "         0x%08X - (sc->used_tx_bd) used tx_bd's\n",
		  sc->used_tx_bd);

	if_printf(ifp, "0x%08X/%08X - (sc->tx_hi_watermark) tx hi watermark\n",
		  sc->tx_hi_watermark, sc->max_tx_bd);

	if_printf(ifp, "         0x%08X - (sc->mbuf_alloc_failed) "
		  "failed mbuf alloc\n", sc->mbuf_alloc_failed);

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out the hardware state through a summary of important registers,  */
/* followed by a complete register dump.                                    */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_hw_state(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint32_t val1;
	int i;

	if_printf(ifp,
	"----------------------------"
	" Hardware State "
	"----------------------------\n");

	if_printf(ifp, "0x%08X - bootcode version\n", sc->bce_fw_ver);

	val1 = REG_RD(sc, BCE_MISC_ENABLE_STATUS_BITS);
	if_printf(ifp, "0x%08X - (0x%06X) misc_enable_status_bits\n",
		  val1, BCE_MISC_ENABLE_STATUS_BITS);

	val1 = REG_RD(sc, BCE_DMA_STATUS);
	if_printf(ifp, "0x%08X - (0x%04X) dma_status\n", val1, BCE_DMA_STATUS);

	val1 = REG_RD(sc, BCE_CTX_STATUS);
	if_printf(ifp, "0x%08X - (0x%04X) ctx_status\n", val1, BCE_CTX_STATUS);

	val1 = REG_RD(sc, BCE_EMAC_STATUS);
	if_printf(ifp, "0x%08X - (0x%04X) emac_status\n",
		  val1, BCE_EMAC_STATUS);

	val1 = REG_RD(sc, BCE_RPM_STATUS);
	if_printf(ifp, "0x%08X - (0x%04X) rpm_status\n", val1, BCE_RPM_STATUS);

	val1 = REG_RD(sc, BCE_TBDR_STATUS);
	if_printf(ifp, "0x%08X - (0x%04X) tbdr_status\n",
		  val1, BCE_TBDR_STATUS);

	val1 = REG_RD(sc, BCE_TDMA_STATUS);
	if_printf(ifp, "0x%08X - (0x%04X) tdma_status\n",
		  val1, BCE_TDMA_STATUS);

	val1 = REG_RD(sc, BCE_HC_STATUS);
	if_printf(ifp, "0x%08X - (0x%06X) hc_status\n", val1, BCE_HC_STATUS);

	val1 = REG_RD_IND(sc, BCE_TXP_CPU_STATE);
	if_printf(ifp, "0x%08X - (0x%06X) txp_cpu_state\n",
		  val1, BCE_TXP_CPU_STATE);

	val1 = REG_RD_IND(sc, BCE_TPAT_CPU_STATE);
	if_printf(ifp, "0x%08X - (0x%06X) tpat_cpu_state\n",
		  val1, BCE_TPAT_CPU_STATE);

	val1 = REG_RD_IND(sc, BCE_RXP_CPU_STATE);
	if_printf(ifp, "0x%08X - (0x%06X) rxp_cpu_state\n",
		  val1, BCE_RXP_CPU_STATE);

	val1 = REG_RD_IND(sc, BCE_COM_CPU_STATE);
	if_printf(ifp, "0x%08X - (0x%06X) com_cpu_state\n",
		  val1, BCE_COM_CPU_STATE);

	val1 = REG_RD_IND(sc, BCE_MCP_CPU_STATE);
	if_printf(ifp, "0x%08X - (0x%06X) mcp_cpu_state\n",
		  val1, BCE_MCP_CPU_STATE);

	val1 = REG_RD_IND(sc, BCE_CP_CPU_STATE);
	if_printf(ifp, "0x%08X - (0x%06X) cp_cpu_state\n",
		  val1, BCE_CP_CPU_STATE);

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");

	if_printf(ifp,
	"----------------------------"
	" Register  Dump "
	"----------------------------\n");

	for (i = 0x400; i < 0x8000; i += 0x10) {
		if_printf(ifp, "0x%04X: 0x%08X 0x%08X 0x%08X 0x%08X\n", i,
			  REG_RD(sc, i),
			  REG_RD(sc, i + 0x4),
			  REG_RD(sc, i + 0x8),
			  REG_RD(sc, i + 0xc));
	}

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out the TXP state.                                                */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_txp_state(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint32_t val1;
	int i;

	if_printf(ifp,
	"----------------------------"
	"   TXP  State   "
	"----------------------------\n");

	val1 = REG_RD_IND(sc, BCE_TXP_CPU_MODE);
	if_printf(ifp, "0x%08X - (0x%06X) txp_cpu_mode\n",
		  val1, BCE_TXP_CPU_MODE);

	val1 = REG_RD_IND(sc, BCE_TXP_CPU_STATE);
	if_printf(ifp, "0x%08X - (0x%06X) txp_cpu_state\n",
		  val1, BCE_TXP_CPU_STATE);

	val1 = REG_RD_IND(sc, BCE_TXP_CPU_EVENT_MASK);
	if_printf(ifp, "0x%08X - (0x%06X) txp_cpu_event_mask\n",
		  val1, BCE_TXP_CPU_EVENT_MASK);

	if_printf(ifp,
	"----------------------------"
	" Register  Dump "
	"----------------------------\n");

	for (i = BCE_TXP_CPU_MODE; i < 0x68000; i += 0x10) {
		/* Skip the big blank spaces */
		if (i < 0x454000 && i > 0x5ffff) {
			if_printf(ifp, "0x%04X: "
				  "0x%08X 0x%08X 0x%08X 0x%08X\n", i,
				  REG_RD_IND(sc, i),
				  REG_RD_IND(sc, i + 0x4),
				  REG_RD_IND(sc, i + 0x8),
				  REG_RD_IND(sc, i + 0xc));
		}
	}

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out the RXP state.                                                */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_rxp_state(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint32_t val1;
	int i;

	if_printf(ifp,
	"----------------------------"
	"   RXP  State   "
	"----------------------------\n");

	val1 = REG_RD_IND(sc, BCE_RXP_CPU_MODE);
	if_printf(ifp, "0x%08X - (0x%06X) rxp_cpu_mode\n",
		  val1, BCE_RXP_CPU_MODE);

	val1 = REG_RD_IND(sc, BCE_RXP_CPU_STATE);
	if_printf(ifp, "0x%08X - (0x%06X) rxp_cpu_state\n",
		  val1, BCE_RXP_CPU_STATE);

	val1 = REG_RD_IND(sc, BCE_RXP_CPU_EVENT_MASK);
	if_printf(ifp, "0x%08X - (0x%06X) rxp_cpu_event_mask\n",
		  val1, BCE_RXP_CPU_EVENT_MASK);

	if_printf(ifp,
	"----------------------------"
	" Register  Dump "
	"----------------------------\n");

	for (i = BCE_RXP_CPU_MODE; i < 0xe8fff; i += 0x10) {
		/* Skip the big blank sapces */
		if (i < 0xc5400 && i > 0xdffff) {
			if_printf(ifp, "0x%04X: "
				  "0x%08X 0x%08X 0x%08X 0x%08X\n", i,
				  REG_RD_IND(sc, i),
				  REG_RD_IND(sc, i + 0x4),
				  REG_RD_IND(sc, i + 0x8),
				  REG_RD_IND(sc, i + 0xc));
		}
	}

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out the TPAT state.                                               */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_dump_tpat_state(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;
	uint32_t val1;
	int i;

	if_printf(ifp,
	"----------------------------"
	"   TPAT State   "
	"----------------------------\n");

	val1 = REG_RD_IND(sc, BCE_TPAT_CPU_MODE);
	if_printf(ifp, "0x%08X - (0x%06X) tpat_cpu_mode\n",
		  val1, BCE_TPAT_CPU_MODE);

	val1 = REG_RD_IND(sc, BCE_TPAT_CPU_STATE);
	if_printf(ifp, "0x%08X - (0x%06X) tpat_cpu_state\n",
		  val1, BCE_TPAT_CPU_STATE);

	val1 = REG_RD_IND(sc, BCE_TPAT_CPU_EVENT_MASK);
	if_printf(ifp, "0x%08X - (0x%06X) tpat_cpu_event_mask\n",
		  val1, BCE_TPAT_CPU_EVENT_MASK);

	if_printf(ifp,
	"----------------------------"
	" Register  Dump "
	"----------------------------\n");

	for (i = BCE_TPAT_CPU_MODE; i < 0xa3fff; i += 0x10) {
		/* Skip the big blank spaces */
		if (i < 0x854000 && i > 0x9ffff) {
			if_printf(ifp, "0x%04X: "
				  "0x%08X 0x%08X 0x%08X 0x%08X\n", i,
				  REG_RD_IND(sc, i),
				  REG_RD_IND(sc, i + 0x4),
				  REG_RD_IND(sc, i + 0x8),
				  REG_RD_IND(sc, i + 0xc));
		}
	}

	if_printf(ifp,
	"----------------------------"
	"----------------"
	"----------------------------\n");
}


/****************************************************************************/
/* Prints out the driver state and then enters the debugger.                */
/*                                                                          */
/* Returns:                                                                 */
/*   Nothing.                                                               */
/****************************************************************************/
static void
bce_breakpoint(struct bce_softc *sc)
{
#if 0
	bce_freeze_controller(sc);
#endif

	bce_dump_driver_state(sc);
	bce_dump_status_block(sc);
	bce_dump_tx_chain(sc, 0, TOTAL_TX_BD);
	bce_dump_hw_state(sc);
	bce_dump_txp_state(sc);

#if 0
	bce_unfreeze_controller(sc);
#endif

	/* Call the debugger. */
	breakpoint();
}

#endif	/* BCE_DEBUG */

static int
bce_sysctl_tx_bds_int(SYSCTL_HANDLER_ARGS)
{
	struct bce_softc *sc = arg1;

	return bce_sysctl_coal_change(oidp, arg1, arg2, req,
			&sc->bce_tx_quick_cons_trip_int,
			BCE_COALMASK_TX_BDS_INT);
}

static int
bce_sysctl_tx_bds(SYSCTL_HANDLER_ARGS)
{
	struct bce_softc *sc = arg1;

	return bce_sysctl_coal_change(oidp, arg1, arg2, req,
			&sc->bce_tx_quick_cons_trip,
			BCE_COALMASK_TX_BDS);
}

static int
bce_sysctl_tx_ticks_int(SYSCTL_HANDLER_ARGS)
{
	struct bce_softc *sc = arg1;

	return bce_sysctl_coal_change(oidp, arg1, arg2, req,
			&sc->bce_tx_ticks_int,
			BCE_COALMASK_TX_TICKS_INT);
}

static int
bce_sysctl_tx_ticks(SYSCTL_HANDLER_ARGS)
{
	struct bce_softc *sc = arg1;

	return bce_sysctl_coal_change(oidp, arg1, arg2, req,
			&sc->bce_tx_ticks,
			BCE_COALMASK_TX_TICKS);
}

static int
bce_sysctl_rx_bds_int(SYSCTL_HANDLER_ARGS)
{
	struct bce_softc *sc = arg1;

	return bce_sysctl_coal_change(oidp, arg1, arg2, req,
			&sc->bce_rx_quick_cons_trip_int,
			BCE_COALMASK_RX_BDS_INT);
}

static int
bce_sysctl_rx_bds(SYSCTL_HANDLER_ARGS)
{
	struct bce_softc *sc = arg1;

	return bce_sysctl_coal_change(oidp, arg1, arg2, req,
			&sc->bce_rx_quick_cons_trip,
			BCE_COALMASK_RX_BDS);
}

static int
bce_sysctl_rx_ticks_int(SYSCTL_HANDLER_ARGS)
{
	struct bce_softc *sc = arg1;

	return bce_sysctl_coal_change(oidp, arg1, arg2, req,
			&sc->bce_rx_ticks_int,
			BCE_COALMASK_RX_TICKS_INT);
}

static int
bce_sysctl_rx_ticks(SYSCTL_HANDLER_ARGS)
{
	struct bce_softc *sc = arg1;

	return bce_sysctl_coal_change(oidp, arg1, arg2, req,
			&sc->bce_rx_ticks,
			BCE_COALMASK_RX_TICKS);
}

static int
bce_sysctl_coal_change(SYSCTL_HANDLER_ARGS, uint32_t *coal,
		       uint32_t coalchg_mask)
{
	struct bce_softc *sc = arg1;
	struct ifnet *ifp = &sc->arpcom.ac_if;
	int error = 0, v;

	lwkt_serialize_enter(ifp->if_serializer);

	v = *coal;
	error = sysctl_handle_int(oidp, &v, 0, req);
	if (!error && req->newptr != NULL) {
		if (v < 0) {
			error = EINVAL;
		} else {
			*coal = v;
			sc->bce_coalchg_mask |= coalchg_mask;
		}
	}

	lwkt_serialize_exit(ifp->if_serializer);
	return error;
}

static void
bce_coal_change(struct bce_softc *sc)
{
	struct ifnet *ifp = &sc->arpcom.ac_if;

	ASSERT_SERIALIZED(ifp->if_serializer);

	if ((ifp->if_flags & IFF_RUNNING) == 0) {
		sc->bce_coalchg_mask = 0;
		return;
	}

	if (sc->bce_coalchg_mask &
	    (BCE_COALMASK_TX_BDS | BCE_COALMASK_TX_BDS_INT)) {
		REG_WR(sc, BCE_HC_TX_QUICK_CONS_TRIP,
		       (sc->bce_tx_quick_cons_trip_int << 16) |
		       sc->bce_tx_quick_cons_trip);
		if (bootverbose) {
			if_printf(ifp, "tx_bds %u, tx_bds_int %u\n",
				  sc->bce_tx_quick_cons_trip,
				  sc->bce_tx_quick_cons_trip_int);
		}
	}

	if (sc->bce_coalchg_mask &
	    (BCE_COALMASK_TX_TICKS | BCE_COALMASK_TX_TICKS_INT)) {
		REG_WR(sc, BCE_HC_TX_TICKS,
		       (sc->bce_tx_ticks_int << 16) | sc->bce_tx_ticks);
		if (bootverbose) {
			if_printf(ifp, "tx_ticks %u, tx_ticks_int %u\n",
				  sc->bce_tx_ticks, sc->bce_tx_ticks_int);
		}
	}

	if (sc->bce_coalchg_mask &
	    (BCE_COALMASK_RX_BDS | BCE_COALMASK_RX_BDS_INT)) {
		REG_WR(sc, BCE_HC_RX_QUICK_CONS_TRIP,
		       (sc->bce_rx_quick_cons_trip_int << 16) |
		       sc->bce_rx_quick_cons_trip);
		if (bootverbose) {
			if_printf(ifp, "rx_bds %u, rx_bds_int %u\n",
				  sc->bce_rx_quick_cons_trip,
				  sc->bce_rx_quick_cons_trip_int);
		}
	}

	if (sc->bce_coalchg_mask &
	    (BCE_COALMASK_RX_TICKS | BCE_COALMASK_RX_TICKS_INT)) {
		REG_WR(sc, BCE_HC_RX_TICKS,
		       (sc->bce_rx_ticks_int << 16) | sc->bce_rx_ticks);
		if (bootverbose) {
			if_printf(ifp, "rx_ticks %u, rx_ticks_int %u\n",
				  sc->bce_rx_ticks, sc->bce_rx_ticks_int);
		}
	}

	sc->bce_coalchg_mask = 0;
}
