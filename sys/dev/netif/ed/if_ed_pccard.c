/*
 * Copyright (c) 1995, David Greenman
 * All rights reserved.
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
 *
 * $FreeBSD: src/sys/dev/ed/if_ed_pccard.c,v 1.55 2003/12/31 04:25:00 kato Exp $
 */

#include "opt_ed.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/module.h>
#include <sys/interrupt.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_mib.h>
#include <net/if_media.h>

#include "if_edreg.h"
#include "if_edvar.h"
#include <bus/pccard/pccard_cis.h>
#include <bus/pccard/pccardvar.h>
#include <bus/pccard/pccarddevs.h>
#ifndef ED_NO_MIIBUS
#include <dev/netif/mii_layer/mii.h>
#include <dev/netif/mii_layer/miivar.h>
#endif

#include "card_if.h"
#ifndef ED_NO_MIIBUS
/* "device miibus" required.  See GENERIC if you get errors here. */
#include "miibus_if.h"

MODULE_DEPEND(ed, miibus, 1, 1, 1);
#endif
MODULE_DEPEND(ed, pccard, 1, 1, 1);

/*
 *      PC-Card (PCMCIA) specific code.
 */
static int	ed_pccard_match(device_t);
static int	ed_pccard_probe(device_t);
static int	ed_pccard_attach(device_t);
static int	ed_pccard_detach(device_t);

static int	ed_pccard_Linksys(device_t dev);
static int	ed_pccard_ax88190(device_t dev);

static void	ax88190_geteprom(struct ed_softc *);
static int	ed_pccard_memwrite(device_t dev, off_t offset, u_char byte);
#ifndef ED_NO_MIIBUS
static void	ed_pccard_dlink_mii_reset(struct ed_softc *sc);
static u_int	ed_pccard_dlink_mii_readbits(struct ed_softc *sc, int nbits);
static void	ed_pccard_dlink_mii_writebits(struct ed_softc *sc, u_int val,
    int nbits);
#endif

/*
 *      ed_pccard_detach - unload the driver and clear the table.
 *      XXX TODO:
 *      This is usually called when the card is ejected, but
 *      can be caused by a modunload of a controller driver.
 *      The idea is to reset the driver's view of the device
 *      and ensure that any driver entry points such as
 *      read and write do not hang.
 */
static int
ed_pccard_detach(device_t dev)
{
	struct ed_softc *sc = device_get_softc(dev);
	struct ifnet *ifp = &sc->arpcom.ac_if;

	lwkt_serialize_enter(ifp->if_serializer);

	if (sc->gone) {
		device_printf(dev, "already unloaded\n");
		lwkt_serialize_exit(ifp->if_serializer);
		return (0);
	}
	ed_stop(sc);
	ifp->if_flags &= ~IFF_RUNNING;
	sc->gone = 1;
	bus_teardown_intr(dev, sc->irq_res, sc->irq_handle);

	lwkt_serialize_exit(ifp->if_serializer);

	ether_ifdetach(ifp);
	ed_release_resources(dev);
	return (0);
}

static const struct ed_product {
	struct pccard_product	prod;
	int flags;
#define	NE2000DVF_DL10019	0x0001		/* chip is D-Link DL10019 */
#define	NE2000DVF_AX88190	0x0002		/* chip is ASIX AX88190 */
} ed_pccard_products[] = {
	{ PCMCIA_CARD(ACCTON, EN2212, 0), 0},
	{ PCMCIA_CARD(ALLIEDTELESIS, LA_PCM, 0), 0},
	{ PCMCIA_CARD(AMBICOM, AMB8002T, 0), 0},
	{ PCMCIA_CARD(BILLIONTON, LNT10TN, 0), 0},
	{ PCMCIA_CARD(BILLIONTON, CFLT10N, 0), 0},
	{ PCMCIA_CARD(BUFFALO, LPC3_CLT,  0), 0},
	{ PCMCIA_CARD(BUFFALO, LPC3_CLX,  0), NE2000DVF_AX88190},
	{ PCMCIA_CARD(BUFFALO, LPC_CF_CLT,  0), 0},
	{ PCMCIA_CARD(CNET, NE2000, 0), 0},
	{ PCMCIA_CARD(COMPEX, LINKPORT_ENET_B, 0), 0},
	{ PCMCIA_CARD(COREGA, ETHER_II_PCC_T, 0), 0},
	{ PCMCIA_CARD(COREGA, ETHER_II_PCC_TD, 0), 0},
	{ PCMCIA_CARD(COREGA, ETHER_PCC_T, 0), 0},
	{ PCMCIA_CARD(COREGA, ETHER_PCC_TD, 0), 0},
	{ PCMCIA_CARD(COREGA, FAST_ETHER_PCC_TX, 0), NE2000DVF_DL10019 },
	{ PCMCIA_CARD(COREGA, FETHER_PCC_TXD, 0), NE2000DVF_AX88190 },
	{ PCMCIA_CARD(COREGA, FETHER_PCC_TXF, 0), NE2000DVF_DL10019 },
	{ PCMCIA_CARD(DAYNA, COMMUNICARD_E_1, 0), 0},
	{ PCMCIA_CARD(DAYNA, COMMUNICARD_E_2, 0), 0},
	{ PCMCIA_CARD(DLINK, DE650, 0), 0},
	{ PCMCIA_CARD(DLINK, DE660, 0), 0 },
	{ PCMCIA_CARD(DLINK, DE660PLUS, 0), 0},
	{ PCMCIA_CARD(DLINK, DFE670TXD, 0), NE2000DVF_DL10019},
	{ PCMCIA_CARD(DYNALINK, L10C, 0), 0},
	{ PCMCIA_CARD(EDIMAX, EP4000A, 0), 0},
	{ PCMCIA_CARD(EPSON, EEN10B, 0), 0},
	{ PCMCIA_CARD(EXP, THINLANCOMBO, 0), 0},
	{ PCMCIA_CARD(IBM, INFOMOVER, 0), 0},
	{ PCMCIA_CARD(IODATA3, PCLAT, 0), 0},
	{ PCMCIA_CARD(KINGSTON, KNE2, 0), 0},
	{ PCMCIA_CARD(LANTECH, FASTNETTX, 0),NE2000DVF_AX88190 },
	{ PCMCIA_CARD(LINKSYS, COMBO_ECARD, 0), NE2000DVF_DL10019 },
	{ PCMCIA_CARD(LINKSYS, ECARD_1, 0), 0},
	{ PCMCIA_CARD(LINKSYS, ECARD_2, 0), 0},
	{ PCMCIA_CARD(LINKSYS, ETHERFAST, 0), NE2000DVF_DL10019 },
	{ PCMCIA_CARD(LINKSYS, TRUST_COMBO_ECARD, 0), 0},
	{ PCMCIA_CARD(MACNICA, ME1_JEIDA, 0), 0},
	{ PCMCIA_CARD(MELCO, LPC3_CLX,  0), NE2000DVF_AX88190},
	{ PCMCIA_CARD(MELCO, LPC3_TX, 0), NE2000DVF_AX88190 },
	{ PCMCIA_CARD(NDC, ND5100_E, 0), 0},
	{ PCMCIA_CARD(NETGEAR, FA410TXC, 0), NE2000DVF_DL10019},
	{ PCMCIA_CARD(NETGEAR, FA411, 0), NE2000DVF_AX88190},
	{ PCMCIA_CARD(NEXTCOM, NEXTHAWK, 0), 0},
	{ PCMCIA_CARD(OEM2, ETHERNET, 0), 0},
	{ PCMCIA_CARD(PLANET, SMARTCOM2000, 0), 0 },
	{ PCMCIA_CARD(PREMAX, PE200, 0), 0},
	{ PCMCIA_CARD(RACORE, ETHERNET, 0), 0},
	{ PCMCIA_CARD(RPTI, EP400, 0), 0},
	{ PCMCIA_CARD(RPTI, EP401, 0), 0},
	{ PCMCIA_CARD(SMC, EZCARD, 0), 0},
	{ PCMCIA_CARD(SOCKET, EA_ETHER, 0), 0},
	{ PCMCIA_CARD(SOCKET, LP_ETHER, 0), 0},
	{ PCMCIA_CARD(SOCKET, LP_ETHER_CF, 0), 0},
	{ PCMCIA_CARD(SOCKET, LP_ETH_10_100_CF, 0), NE2000DVF_DL10019},
	{ PCMCIA_CARD(SVEC, COMBOCARD, 0), 0},
	{ PCMCIA_CARD(SVEC, LANCARD, 0), 0},
	{ PCMCIA_CARD(TAMARACK, ETHERNET, 0), 0},
	{ PCMCIA_CARD(TDK, LAK_CD031, 0), 0},
	{ PCMCIA_CARD(TELECOMDEVICE, TCD_HPC100, 0), NE2000DVF_AX88190 },
	{ PCMCIA_CARD(XIRCOM, CFE_10, 0), 0},
	{ PCMCIA_CARD(ZONET, ZEN, 0), 0},
	{ { NULL } }
};

static int
ed_pccard_match(device_t dev)
{
	const struct ed_product *pp;

	if ((pp = (const struct ed_product *) pccard_product_lookup(dev, 
	    (const struct pccard_product *) ed_pccard_products,
	    sizeof(ed_pccard_products[0]), NULL)) != NULL) {
		if (pp->prod.pp_name != NULL)
			device_set_desc(dev, pp->prod.pp_name);
		if (pp->flags & NE2000DVF_DL10019)
			device_set_flags(dev, ED_FLAGS_LINKSYS);
		else if (pp->flags & NE2000DVF_AX88190)
			device_set_flags(dev, ED_FLAGS_AX88190);
		return (0);
	}
	return (EIO);
}

/* 
 * Probe framework for pccards.  Replicates the standard framework,
 * minus the pccard driver registration and ignores the ether address
 * supplied (from the CIS), relying on the probe to find it instead.
 */
static int
ed_pccard_probe(device_t dev)
{
	int	error;
	int	flags = device_get_flags(dev);

	if (ED_FLAGS_GETTYPE(flags) == ED_FLAGS_AX88190) {
		error = ed_pccard_ax88190(dev);
		goto end2;
	}

	error = ed_probe_Novell(dev, 0, flags);
	if (error == 0)
		goto end;
	ed_release_resources(dev);

	error = ed_probe_WD80x3(dev, 0, flags);
	if (error == 0)
		goto end;
	ed_release_resources(dev);
	goto end2;

end:
	if (ED_FLAGS_GETTYPE(flags) & ED_FLAGS_LINKSYS)
		ed_pccard_Linksys(dev);
end2:
	if (error == 0)
		error = ed_alloc_irq(dev, 0, 0);

	ed_release_resources(dev);
	return (error);
}

static int
ed_pccard_attach(device_t dev)
{
	struct ed_softc *sc = device_get_softc(dev);
	struct ifnet *ifp = &sc->arpcom.ac_if;
	int error;
	int i;
	uint8_t sum;
	const uint8_t *ether_addr;
	
	if (sc->port_used > 0)
		ed_alloc_port(dev, sc->port_rid, sc->port_used);
	if (sc->mem_used)
		ed_alloc_memory(dev, sc->mem_rid, sc->mem_used);
	ed_alloc_irq(dev, sc->irq_rid, 0);
		
	if (sc->vendor != ED_VENDOR_LINKSYS) {
		ether_addr = pccard_get_ether(dev);
		for (i = 0, sum = 0; i < ETHER_ADDR_LEN; i++)
			sum |= ether_addr[i];
		if (sum)
			bcopy(ether_addr, sc->arpcom.ac_enaddr, ETHER_ADDR_LEN);
	}

	error = ed_attach(dev);
#ifndef ED_NO_MIIBUS
	if (error == 0 && sc->vendor == ED_VENDOR_LINKSYS) {
		/* Probe for an MII bus, but ignore errors. */
		ed_pccard_dlink_mii_reset(sc);
		sc->mii_readbits = ed_pccard_dlink_mii_readbits;
		sc->mii_writebits = ed_pccard_dlink_mii_writebits;
		mii_phy_probe(dev, &sc->miibus, ed_ifmedia_upd,
		    ed_ifmedia_sts);
	}
#endif

	error = bus_setup_intr(dev, sc->irq_res, INTR_MPSAFE,
			       edintr, sc, &sc->irq_handle,
			       ifp->if_serializer);
	if (error) {
		kprintf("setup intr failed %d \n", error);
		ed_release_resources(dev);
		return (error);
	} else {
		ifp->if_cpuid = ithread_cpuid(rman_get_start(sc->irq_res));
		KKASSERT(ifp->if_cpuid >= 0 && ifp->if_cpuid < ncpus);
	}

	return (error);
}

static void
ax88190_geteprom(struct ed_softc *sc)
{
	int prom[16],i;
	u_char tmp;
	struct {
		u_char offset, value;
	} pg_seq[] = {
		{ED_P0_CR, ED_CR_RD2|ED_CR_STP},	/* Select Page0 */
		{ED_P0_DCR, 0x01},
		{ED_P0_RBCR0, 0x00},			/* Clear the count regs. */
		{ED_P0_RBCR1, 0x00},
		{ED_P0_IMR, 0x00},			/* Mask completion irq. */
		{ED_P0_ISR, 0xff},
		{ED_P0_RCR, ED_RCR_MON | ED_RCR_INTT},	/* Set To Monitor */
		{ED_P0_TCR, ED_TCR_LB0},		/* loopback mode. */
		{ED_P0_RBCR0, 32},
		{ED_P0_RBCR1, 0x00},
		{ED_P0_RSAR0, 0x00},
		{ED_P0_RSAR1, 0x04},
		{ED_P0_CR ,ED_CR_RD0 | ED_CR_STA},
	};

	/* Reset Card */
	tmp = ed_asic_inb(sc, ED_NOVELL_RESET);
	ed_asic_outb(sc, ED_NOVELL_RESET, tmp);
	DELAY(5000);
	ed_asic_outb(sc, ED_P0_CR, ED_CR_RD2 | ED_CR_STP);
	DELAY(5000);

	/* Card Settings */
	for (i = 0; i < NELEM(pg_seq); i++)
		ed_nic_outb(sc, pg_seq[i].offset, pg_seq[i].value);

	/* Get Data */
	for (i = 0; i < 16; i++)
		prom[i] = ed_asic_inb(sc, 0);
	sc->arpcom.ac_enaddr[0] = prom[0] & 0xff;
	sc->arpcom.ac_enaddr[1] = prom[0] >> 8;
	sc->arpcom.ac_enaddr[2] = prom[1] & 0xff;
	sc->arpcom.ac_enaddr[3] = prom[1] >> 8;
	sc->arpcom.ac_enaddr[4] = prom[2] & 0xff;
	sc->arpcom.ac_enaddr[5] = prom[2] >> 8;
}

static int
ed_pccard_memwrite(device_t dev, off_t offset, u_char byte)
{
	int cis_rid;
	struct resource *cis;
	
	cis_rid = 0;
	cis = bus_alloc_resource(dev, SYS_RES_MEMORY, &cis_rid, 0, ~0,
				 4 << 10, RF_ACTIVE | RF_SHAREABLE);
	if (cis == NULL)
		return (ENXIO);
	CARD_SET_RES_FLAGS(device_get_parent(dev), dev, SYS_RES_MEMORY,
			   cis_rid, PCCARD_A_MEM_ATTR);

	bus_space_write_1(rman_get_bustag(cis), rman_get_bushandle(cis),
			  offset, byte);

	bus_deactivate_resource(dev, SYS_RES_MEMORY, cis_rid, cis);
	bus_release_resource(dev, SYS_RES_MEMORY, cis_rid, cis);

	return (0);
}

/*
 * Probe the Ethernet MAC addrees for PCMCIA Linksys EtherFast 10/100 
 * and compatible cards (DL10019C Ethernet controller).
 *
 * Note: The PAO patches try to use more memory for the card, but that
 * seems to fail for my card.  A future optimization would add this back
 * conditionally.
 */
static int
ed_pccard_Linksys(device_t dev)
{
	struct ed_softc *sc = device_get_softc(dev);
	u_char sum;
	int i;

	/*
	 * Linksys registers(offset from ASIC base)
	 *
	 * 0x04-0x09 : Physical Address Register 0-5 (PAR0-PAR5)
	 * 0x0A      : Card ID Register (CIR)
	 * 0x0B      : Check Sum Register (SR)
	 */
	for (sum = 0, i = 0x04; i < 0x0c; i++)
		sum += ed_asic_inb(sc, i);
	if (sum != 0xff)
		return (0);		/* invalid DL10019C */
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		sc->arpcom.ac_enaddr[i] = ed_asic_inb(sc, 0x04 + i);
	}

	ed_nic_outb(sc, ED_P0_DCR, ED_DCR_WTS | ED_DCR_FT1 | ED_DCR_LS);
	sc->isa16bit = 1;
	sc->vendor = ED_VENDOR_LINKSYS;
	sc->type = ED_TYPE_NE2000;
	sc->type_str = "Linksys";

	return (1);
}

/*
 * Special setup for AX88190
 */
static int
ed_pccard_ax88190(device_t dev)
{
	int	error;
	int	flags = device_get_flags(dev);
	int	iobase;
	struct	ed_softc *sc = device_get_softc(dev);

	/* Allocate the port resource during setup. */
	error = ed_alloc_port(dev, 0, ED_NOVELL_IO_PORTS);
	if (error)
		return (error);

	sc->asic_offset = ED_NOVELL_ASIC_OFFSET;
	sc->nic_offset  = ED_NOVELL_NIC_OFFSET;
	sc->chip_type = ED_CHIP_TYPE_AX88190;

	/*
	 * Set Attribute Memory IOBASE Register.  Is this a deficiency in
	 * the PC Card layer, or an ax88190 specific issue? xxx
	 */
	iobase = rman_get_start(sc->port_res);
	ed_pccard_memwrite(dev, ED_AX88190_IOBASE0, iobase & 0xff);
	ed_pccard_memwrite(dev, ED_AX88190_IOBASE1, (iobase >> 8) & 0xff);
	ax88190_geteprom(sc);
	ed_release_resources(dev);
	error = ed_probe_Novell(dev, 0, flags);
	if (error == 0) {
		sc->vendor = ED_VENDOR_PCCARD;
		sc->type = ED_TYPE_NE2000;
		sc->type_str = "AX88190";
	}
	return (error);
}

#ifndef ED_NO_MIIBUS
/* MII bit-twiddling routines for cards using Dlink chipset */
#define DLINK_MIISET(sc, x) ed_asic_outb(sc, ED_DLINK_MIIBUS, \
    ed_asic_inb(sc, ED_DLINK_MIIBUS) | (x))
#define DLINK_MIICLR(sc, x) ed_asic_outb(sc, ED_DLINK_MIIBUS, \
    ed_asic_inb(sc, ED_DLINK_MIIBUS) & ~(x))

static void
ed_pccard_dlink_mii_reset(struct ed_softc *sc)
{
	ed_asic_outb(sc, ED_DLINK_MIIBUS, 0);
	DELAY(10);
	DLINK_MIISET(sc, ED_DLINK_MII_RESET2);
	DELAY(10);
	DLINK_MIISET(sc, ED_DLINK_MII_RESET1);
	DELAY(10);
	DLINK_MIICLR(sc, ED_DLINK_MII_RESET1);
	DELAY(10);
	DLINK_MIICLR(sc, ED_DLINK_MII_RESET2);
	DELAY(10);
}

static void
ed_pccard_dlink_mii_writebits(struct ed_softc *sc, u_int val, int nbits)
{
	int i;

	DLINK_MIISET(sc, ED_DLINK_MII_DIROUT);

	for (i = nbits - 1; i >= 0; i--) {
		if ((val >> i) & 1)
			DLINK_MIISET(sc, ED_DLINK_MII_DATAOUT);
		else
			DLINK_MIICLR(sc, ED_DLINK_MII_DATAOUT);
		DELAY(10);
		DLINK_MIISET(sc, ED_DLINK_MII_CLK);
		DELAY(10);
		DLINK_MIICLR(sc, ED_DLINK_MII_CLK);
		DELAY(10);
	}
}

static u_int
ed_pccard_dlink_mii_readbits(struct ed_softc *sc, int nbits)
{
	int i;
	u_int val = 0;

	DLINK_MIICLR(sc, ED_DLINK_MII_DIROUT);

	for (i = nbits - 1; i >= 0; i--) {
		DLINK_MIISET(sc, ED_DLINK_MII_CLK);
		DELAY(10);
		val <<= 1;
		if (ed_asic_inb(sc, ED_DLINK_MIIBUS) & ED_DLINK_MII_DATATIN)
			val++;
		DLINK_MIICLR(sc, ED_DLINK_MII_CLK);
		DELAY(10);
	}

	return val;
}
#endif

static device_method_t ed_pccard_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		pccard_compat_probe),
	DEVMETHOD(device_attach,	pccard_compat_attach),
	DEVMETHOD(device_detach,	ed_pccard_detach),

#ifndef ED_NO_MIIBUS
	/* Bus interface */
	DEVMETHOD(bus_child_detached,	ed_child_detached),

	/* MII interface */
	DEVMETHOD(miibus_readreg,	ed_miibus_readreg),
	DEVMETHOD(miibus_writereg,	ed_miibus_writereg),
#endif

	/* Card interface */
	DEVMETHOD(card_compat_match,	ed_pccard_match),
	DEVMETHOD(card_compat_probe,	ed_pccard_probe),
	DEVMETHOD(card_compat_attach,	ed_pccard_attach),
	{ 0, 0 }
};

static driver_t ed_pccard_driver = {
	"ed",
	ed_pccard_methods,
	sizeof(struct ed_softc)
};

DRIVER_MODULE(if_ed, pccard, ed_pccard_driver, ed_devclass, 0, 0);
#ifndef ED_NO_MIIBUS
MODULE_DEPEND(if_ed, miibus, 1, 1, 1);
DRIVER_MODULE(miibus, ed, miibus_driver, miibus_devclass, 0, 0);
#endif
