/*	$OpenBSD: brgphy.c,v 1.48 2006/05/20 23:03:53 brad Exp $	*/

/*
 * Copyright (c) 2000
 *	Bill Paul <wpaul@ee.columbia.edu>.  All rights reserved.
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
 * $FreeBSD: src/sys/dev/mii/brgphy.c,v 1.1.2.7 2003/05/11 18:00:55 ps Exp $
 */

/*
 * Driver for the Broadcom BCR5400 1000baseT PHY. Speed is always
 * 1000mbps; all we need to negotiate here is full or half duplex.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/bus.h>
#include <sys/sysctl.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_media.h>
#include <net/if_arp.h>

#include "mii.h"
#include "miivar.h"
#include "miidevs.h"

#include "brgphyreg.h"
#include <dev/netif/bge/if_bgereg.h>
#include <dev/netif/bce/if_bcereg.h>

#include "miibus_if.h"

static int brgphy_probe(device_t);
static int brgphy_attach(device_t);

static const struct mii_phydesc brgphys[] = {
	MII_PHYDESC(xxBROADCOM,	BCM5400),
	MII_PHYDESC(xxBROADCOM,	BCM5401),
	MII_PHYDESC(xxBROADCOM,	BCM5411),
	MII_PHYDESC(xxBROADCOM,	BCM5421),
	MII_PHYDESC(xxBROADCOM,	BCM54K2),
	MII_PHYDESC(xxBROADCOM,	BCM5462),

	MII_PHYDESC(xxBROADCOM,	BCM5701),
	MII_PHYDESC(xxBROADCOM,	BCM5703),
	MII_PHYDESC(xxBROADCOM,	BCM5704),
	MII_PHYDESC(xxBROADCOM,	BCM5705),

	MII_PHYDESC(xxBROADCOM,	BCM5714),
	MII_PHYDESC(xxBROADCOM2,BCM5722),
	MII_PHYDESC(xxBROADCOM,	BCM5750),
	MII_PHYDESC(xxBROADCOM,	BCM5752),
	MII_PHYDESC(xxBROADCOM2,BCM5755),
	MII_PHYDESC(xxBROADCOM,	BCM5780),
	MII_PHYDESC(xxBROADCOM2,BCM5787),

	MII_PHYDESC(xxBROADCOM,	BCM5706C),
	MII_PHYDESC(xxBROADCOM,	BCM5708C),
	MII_PHYDESC(xxBROADCOM2, BCM5709CAX),
	MII_PHYDESC(xxBROADCOM2, BCM5709C),

	MII_PHYDESC(BROADCOM2, BCM5906),

	MII_PHYDESC_NULL
};

static device_method_t brgphy_methods[] = {
	/* device interface */
	DEVMETHOD(device_probe,		brgphy_probe),
	DEVMETHOD(device_attach,	brgphy_attach),
	DEVMETHOD(device_detach,	ukphy_detach),
	DEVMETHOD(device_shutdown,	bus_generic_shutdown),
	{ 0, 0 }
};

static devclass_t brgphy_devclass;

static driver_t brgphy_driver = {
	"brgphy",
	brgphy_methods,
	sizeof(struct mii_softc)
};

DRIVER_MODULE(brgphy, miibus, brgphy_driver, brgphy_devclass, NULL, NULL);

static int	brgphy_service(struct mii_softc *, struct mii_data *, int);
static void 	brgphy_status(struct mii_softc *);
static void	brgphy_mii_phy_auto(struct mii_softc *);
static void	brgphy_reset(struct mii_softc *);
static void	brgphy_loop(struct mii_softc *);

static void	brgphy_bcm5401_dspcode(struct mii_softc *);
static void	brgphy_bcm5411_dspcode(struct mii_softc *);
static void	brgphy_bcm5421_dspcode(struct mii_softc *);
static void	brgphy_bcm54k2_dspcode(struct mii_softc *);

static void	brgphy_adc_bug(struct mii_softc *);
static void	brgphy_5704_a0_bug(struct mii_softc *);
static void	brgphy_ber_bug(struct mii_softc *);
static void	brgphy_crc_bug(struct mii_softc *);

static void	brgphy_disable_early_dac(struct mii_softc *);
static void	brgphy_jumbo_settings(struct mii_softc *, u_long);
static void	brgphy_eth_wirespeed(struct mii_softc *);

static int
brgphy_probe(device_t dev)
{
	struct mii_attach_args *ma = device_get_ivars(dev);
	const struct mii_phydesc *mpd;

	mpd = mii_phy_match(ma, brgphys);
	if (mpd != NULL) {
		device_set_desc(dev, mpd->mpd_name);
		return (0);
	}
	return(ENXIO);
}

static int
brgphy_attach(device_t dev)
{
	struct mii_softc *sc;
	struct mii_attach_args *ma;
	struct mii_data *mii;

	sc = device_get_softc(dev);
	ma = device_get_ivars(dev);
	mii_softc_init(sc, ma);
	sc->mii_dev = device_get_parent(dev);
	mii = device_get_softc(sc->mii_dev);
	LIST_INSERT_HEAD(&mii->mii_phys, sc, mii_list);

	sc->mii_inst = mii->mii_instance;
	sc->mii_service = brgphy_service;
	sc->mii_reset = brgphy_reset;
	sc->mii_pdata = mii;

	sc->mii_flags |= MIIF_NOISOLATE;
	mii->mii_instance++;

	brgphy_reset(sc);

#define	ADD(m, c)	ifmedia_add(&mii->mii_media, (m), (c), NULL)

	ADD(IFM_MAKEWORD(IFM_ETHER, IFM_NONE, 0, sc->mii_inst),
	    MII_MEDIA_NONE);
#if 0
	ADD(IFM_MAKEWORD(IFM_ETHER, IFM_100_TX, IFM_LOOP, sc->mii_inst),
	    MII_MEDIA_100_TX);
#endif

#undef ADD

	sc->mii_capabilities = PHY_READ(sc, MII_BMSR) & ma->mii_capmask;
	if (sc->mii_capabilities & BMSR_EXTSTAT)
		sc->mii_extcapabilities = PHY_READ(sc, MII_EXTSR);

	device_printf(dev, " ");
	if ((sc->mii_capabilities & BMSR_MEDIAMASK) ||
	    (sc->mii_extcapabilities & EXTSR_MEDIAMASK))
		mii_phy_add_media(sc);
	else
		kprintf("no media present");
	kprintf("\n");

	MIIBUS_MEDIAINIT(sc->mii_dev);
	return(0);
}

static int
brgphy_service(struct mii_softc *sc, struct mii_data *mii, int cmd)
{
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;
	int reg, speed, gig;

	switch (cmd) {
	case MII_POLLSTAT:
		/*
		 * If we're not polling our PHY instance, just return.
		 */
		if (IFM_INST(ife->ifm_media) != sc->mii_inst)
			return (0);
		break;

	case MII_MEDIACHG:
		/*
		 * If the media indicates a different PHY instance,
		 * isolate ourselves.
		 */
		if (IFM_INST(ife->ifm_media) != sc->mii_inst) {
			reg = PHY_READ(sc, MII_BMCR);
			PHY_WRITE(sc, MII_BMCR, reg | BMCR_ISO);
			return (0);
		}

		/*
		 * If the interface is not up, don't do anything.
		 */
		if ((mii->mii_ifp->if_flags & IFF_UP) == 0)
			break;

		brgphy_reset(sc);	/* XXX hardware bug work-around */

		switch (IFM_SUBTYPE(ife->ifm_media)) {
		case IFM_AUTO:
#ifdef foo
			/*
			 * If we're already in auto mode, just return.
			 */
			if (PHY_READ(sc, BRGPHY_MII_BMCR) & BRGPHY_BMCR_AUTOEN)
				return (0);
#endif
			brgphy_mii_phy_auto(sc);
			break;
		case IFM_1000_T:
			speed = BRGPHY_S1000;
			goto setit;
		case IFM_100_TX:
			speed = BRGPHY_S100;
			goto setit;
		case IFM_10_T:
			speed = BRGPHY_S10;
setit:
			brgphy_loop(sc);
			if ((ife->ifm_media & IFM_GMASK) == IFM_FDX) {
				speed |= BRGPHY_BMCR_FDX;
				gig = BRGPHY_1000CTL_AFD;
			} else {
				gig = BRGPHY_1000CTL_AHD;
			}

			PHY_WRITE(sc, BRGPHY_MII_1000CTL, 0);
			PHY_WRITE(sc, BRGPHY_MII_ANAR, BRGPHY_SEL_TYPE);
			PHY_WRITE(sc, BRGPHY_MII_BMCR, speed);

			if (IFM_SUBTYPE(ife->ifm_media) != IFM_1000_T)
				break;

			PHY_WRITE(sc, BRGPHY_MII_1000CTL, gig);
			PHY_WRITE(sc, BRGPHY_MII_BMCR,
			    speed|BRGPHY_BMCR_AUTOEN|BRGPHY_BMCR_STARTNEG);

			if (sc->mii_model != MII_MODEL_xxBROADCOM_BCM5701)
				break;

			/*
			 * When settning the link manually, one side must
			 * be the master and the other the slave. However
			 * ifmedia doesn't give us a good way to specify
			 * this, so we fake it by using one of the LINK
			 * flags. If LINK0 is set, we program the PHY to
			 * be a master, otherwise it's a slave.
			 */
			if ((mii->mii_ifp->if_flags & IFF_LINK0)) {
				PHY_WRITE(sc, BRGPHY_MII_1000CTL,
				    gig|BRGPHY_1000CTL_MSE|BRGPHY_1000CTL_MSC);
			} else {
				PHY_WRITE(sc, BRGPHY_MII_1000CTL,
				    gig|BRGPHY_1000CTL_MSE);
			}
			break;
#ifdef foo
		case IFM_NONE:
			PHY_WRITE(sc, MII_BMCR, BMCR_ISO|BMCR_PDOWN);
			break;
#endif
		case IFM_100_T4:
		default:
			return (EINVAL);
		}
		break;

	case MII_TICK:
		/*
		 * If we're not currently selected, just return.
		 */
		if (IFM_INST(ife->ifm_media) != sc->mii_inst)
			return (0);

		/*
		 * Is the interface even up?
		 */
		if ((mii->mii_ifp->if_flags & IFF_UP) == 0)
			return (0);

		/*
		 * Only used for autonegotiation.
		 */
		if (IFM_SUBTYPE(ife->ifm_media) != IFM_AUTO)
			break;

		/*
		 * Check to see if we have link.  If we do, we don't
		 * need to restart the autonegotiation process.
		 */
		reg = PHY_READ(sc, BRGPHY_MII_AUXSTS);
		if (reg & BRGPHY_AUXSTS_LINK) {
			sc->mii_ticks = 0;
			break;
		}

		/*
		 * Only retry autonegotiation every 5 seconds.
		 */
		if (++sc->mii_ticks <= sc->mii_anegticks)
			break;
		
		sc->mii_ticks = 0;
		brgphy_mii_phy_auto(sc);
		break;
	}

	/* Update the media status. */
	brgphy_status(sc);

	/*
	 * Callback if something changed. Note that we need to poke
	 * the DSP on the Broadcom PHYs if the media changes.
	 */
	if (sc->mii_media_active != mii->mii_media_active ||
	    sc->mii_media_status != mii->mii_media_status ||
	    cmd == MII_MEDIACHG) {
		switch (sc->mii_model) {
		case MII_MODEL_xxBROADCOM_BCM5400:
			brgphy_bcm5401_dspcode(sc);
			break;
		case MII_MODEL_xxBROADCOM_BCM5401:
			if (sc->mii_rev == 1 || sc->mii_rev == 3)
				brgphy_bcm5401_dspcode(sc);
			break;
		case MII_MODEL_xxBROADCOM_BCM5411:
			brgphy_bcm5411_dspcode(sc);
			break;
		}
	}
	mii_phy_update(sc, cmd);
	return (0);
}

static void
brgphy_status(struct mii_softc *sc)
{
	struct mii_data *mii = sc->mii_pdata;
	int bmcr, aux;

	mii->mii_media_status = IFM_AVALID;
	mii->mii_media_active = IFM_ETHER;

	aux = PHY_READ(sc, BRGPHY_MII_AUXSTS);
	if (aux & BRGPHY_AUXSTS_LINK)
		mii->mii_media_status |= IFM_ACTIVE;

	bmcr = PHY_READ(sc, BRGPHY_MII_BMCR);
	if (bmcr & BRGPHY_BMCR_LOOP)
		mii->mii_media_active |= IFM_LOOP;

	if (bmcr & BRGPHY_BMCR_AUTOEN) {
		if ((PHY_READ(sc, BRGPHY_MII_BMSR) & BRGPHY_BMSR_ACOMP) == 0) {
			/* Erg, still trying, I guess... */
			mii->mii_media_active |= IFM_NONE;
			return;
		}

		switch (aux & BRGPHY_AUXSTS_AN_RES) {
		case BRGPHY_RES_1000FD:
			mii->mii_media_active |= IFM_1000_T | IFM_FDX;
			break;
		case BRGPHY_RES_1000HD:
			mii->mii_media_active |= IFM_1000_T | IFM_HDX;
			break;
		case BRGPHY_RES_100FD:
			mii->mii_media_active |= IFM_100_TX | IFM_FDX;
			break;
		case BRGPHY_RES_100T4:
			mii->mii_media_active |= IFM_100_T4;
			break;
		case BRGPHY_RES_100HD:
			mii->mii_media_active |= IFM_100_TX | IFM_HDX;
			break;
		case BRGPHY_RES_10FD:
			mii->mii_media_active |= IFM_10_T | IFM_FDX;
			break;
		case BRGPHY_RES_10HD:
			mii->mii_media_active |= IFM_10_T | IFM_HDX;
			break;
		default:
			mii->mii_media_active |= IFM_NONE;
			break;
		}
	} else {
		mii->mii_media_active = mii->mii_media.ifm_cur->ifm_media;
	}
}


static void
brgphy_mii_phy_auto(struct mii_softc *sc)
{
	int ktcr = 0;

	brgphy_loop(sc);
	brgphy_reset(sc);
	ktcr = BRGPHY_1000CTL_AFD|BRGPHY_1000CTL_AHD;
	if (sc->mii_model == MII_MODEL_xxBROADCOM_BCM5701)
		ktcr |= BRGPHY_1000CTL_MSE|BRGPHY_1000CTL_MSC;
	PHY_WRITE(sc, BRGPHY_MII_1000CTL, ktcr);
	ktcr = PHY_READ(sc, BRGPHY_MII_1000CTL);
	DELAY(1000);
	PHY_WRITE(sc, BRGPHY_MII_ANAR,
	    BMSR_MEDIA_TO_ANAR(sc->mii_capabilities) | ANAR_CSMA);
	DELAY(1000);
	PHY_WRITE(sc, BRGPHY_MII_BMCR,
	    BRGPHY_BMCR_AUTOEN | BRGPHY_BMCR_STARTNEG);
	PHY_WRITE(sc, BRGPHY_MII_IMR, 0xFF00);
}

static void
brgphy_loop(struct mii_softc *sc)
{
	uint32_t bmsr;
	int i;

	PHY_WRITE(sc, BRGPHY_MII_BMCR, BRGPHY_BMCR_LOOP);
	for (i = 0; i < 15000; i++) {
		bmsr = PHY_READ(sc, BRGPHY_MII_BMSR);
		if (!(bmsr & BRGPHY_BMSR_LINK))
			break;
		DELAY(10);
	}
}

static void
brgphy_reset(struct mii_softc *sc)
{
	struct ifnet *ifp;

	mii_phy_reset(sc);

	switch (sc->mii_model) {
	case MII_MODEL_xxBROADCOM_BCM5400:
		brgphy_bcm5401_dspcode(sc);
			break;
	case MII_MODEL_xxBROADCOM_BCM5401:
		if (sc->mii_rev == 1 || sc->mii_rev == 3)
			brgphy_bcm5401_dspcode(sc);
		break;
	case MII_MODEL_xxBROADCOM_BCM5411:
		brgphy_bcm5411_dspcode(sc);
		break;
	case MII_MODEL_xxBROADCOM_BCM5421:
		brgphy_bcm5421_dspcode(sc);
		break;
	case MII_MODEL_xxBROADCOM_BCM54K2:
		brgphy_bcm54k2_dspcode(sc);
		break;
	}

	ifp = sc->mii_pdata->mii_ifp;
	if (strncmp(ifp->if_xname, "bge", 3) == 0) {
		struct bge_softc *bge_sc = ifp->if_softc;

		if (bge_sc->bge_flags & BGE_FLAG_ADC_BUG)
			brgphy_adc_bug(sc);
		if (bge_sc->bge_flags & BGE_FLAG_5704_A0_BUG)
			brgphy_5704_a0_bug(sc);
		if (bge_sc->bge_flags & BGE_FLAG_BER_BUG) {
			brgphy_ber_bug(sc);
		} else if (bge_sc->bge_flags & BGE_FLAG_JITTER_BUG) {
			PHY_WRITE(sc, BRGPHY_MII_AUXCTL, 0x0c00);
			PHY_WRITE(sc, BRGPHY_MII_DSP_ADDR_REG, 0x000a);

			if (bge_sc->bge_flags & BGE_FLAG_ADJUST_TRIM) {
				PHY_WRITE(sc, BRGPHY_MII_DSP_RW_PORT, 0x110b);
				PHY_WRITE(sc, BRGPHY_TEST1,
				    BRGPHY_TEST1_TRIM_EN | 0x4);
			} else {
				PHY_WRITE(sc, BRGPHY_MII_DSP_RW_PORT, 0x010b);
			}

			PHY_WRITE(sc, BRGPHY_MII_AUXCTL, 0x0400);
		}
		if (bge_sc->bge_flags & BGE_FLAG_CRC_BUG)
			brgphy_crc_bug(sc);

		/* Set Jumbo frame settings in the PHY. */
		brgphy_jumbo_settings(sc, ifp->if_mtu);

		/* Enable Ethernet@Wirespeed */
		if (bge_sc->bge_flags & BGE_FLAG_ETH_WIRESPEED)
			brgphy_eth_wirespeed(sc);

		/* Enable Link LED on Dell boxes */
		if (bge_sc->bge_flags & BGE_FLAG_NO_3LED) {
			PHY_WRITE(sc, BRGPHY_MII_PHY_EXTCTL, 
			PHY_READ(sc, BRGPHY_MII_PHY_EXTCTL)
				& ~BRGPHY_PHY_EXTCTL_3_LED);
		}

		/* Adjust output voltage (From Linux driver) */
		if (bge_sc->bge_asicrev == BGE_ASICREV_BCM5906)
			PHY_WRITE(sc, BRGPHY_MII_EPHY_PTEST, 0x12);
	} else if (strncmp(ifp->if_xname, "bce", 3) == 0) {
		struct bce_softc *bce_sc = ifp->if_softc;

		if (BCE_CHIP_NUM(bce_sc) == BCE_CHIP_NUM_5709) {
			if (BCE_CHIP_REV(bce_sc) == BCE_CHIP_REV_Ax ||
			    BCE_CHIP_REV(bce_sc) == BCE_CHIP_REV_Bx)
				brgphy_disable_early_dac(sc);
			brgphy_jumbo_settings(sc, ifp->if_mtu);
			brgphy_eth_wirespeed(sc);
		} else {
			brgphy_ber_bug(sc);
			brgphy_jumbo_settings(sc, ifp->if_mtu);
			brgphy_eth_wirespeed(sc);
		}
	}
}

/* Turn off tap power management on 5401. */
static void
brgphy_bcm5401_dspcode(struct mii_softc *sc)
{
	static const struct {
		int		reg;
		uint16_t	val;
	} dspcode[] = {
		{ BRGPHY_MII_AUXCTL,		0x0c20 },
		{ BRGPHY_MII_DSP_ADDR_REG,	0x0012 },
		{ BRGPHY_MII_DSP_RW_PORT,	0x1804 },
		{ BRGPHY_MII_DSP_ADDR_REG,	0x0013 },
		{ BRGPHY_MII_DSP_RW_PORT,	0x1204 },
		{ BRGPHY_MII_DSP_ADDR_REG,	0x8006 },
		{ BRGPHY_MII_DSP_RW_PORT,	0x0132 },
		{ BRGPHY_MII_DSP_ADDR_REG,	0x8006 },
		{ BRGPHY_MII_DSP_RW_PORT,	0x0232 },
		{ BRGPHY_MII_DSP_ADDR_REG,	0x201f },
		{ BRGPHY_MII_DSP_RW_PORT,	0x0a20 },
		{ 0,				0 },
	};
	int i;

	for (i = 0; dspcode[i].reg != 0; i++)
		PHY_WRITE(sc, dspcode[i].reg, dspcode[i].val);
	DELAY(40);
}

/* Setting some undocumented voltage */
static void
brgphy_bcm5411_dspcode(struct mii_softc *sc)
{
	static const struct {
		int		reg;
		uint16_t	val;
	} dspcode[] = {
		{ 0x1c,				0x8c23 },
		{ 0x1c,				0x8ca3 },
		{ 0x1c,				0x8c23 },
		{ 0,				0 },
	};
	int i;

	for (i = 0; dspcode[i].reg != 0; i++)
		PHY_WRITE(sc, dspcode[i].reg, dspcode[i].val);
}

static void
brgphy_bcm5421_dspcode(struct mii_softc *sc)
{
	uint16_t data;

	/* Set Class A mode */
	PHY_WRITE(sc, BRGPHY_MII_AUXCTL, 0x1007);
	data = PHY_READ(sc, BRGPHY_MII_AUXCTL);
	PHY_WRITE(sc, BRGPHY_MII_AUXCTL, data | 0x0400);

	/* Set FFE gamma override to -0.125 */
	PHY_WRITE(sc, BRGPHY_MII_AUXCTL, 0x0007);
	data = PHY_READ(sc, BRGPHY_MII_AUXCTL);
	PHY_WRITE(sc, BRGPHY_MII_AUXCTL, data | 0x0800);
	PHY_WRITE(sc, BRGPHY_MII_DSP_ADDR_REG, 0x000a);
	data = PHY_READ(sc, BRGPHY_MII_DSP_RW_PORT);
	PHY_WRITE(sc, BRGPHY_MII_DSP_RW_PORT, data | 0x0200);
}

static void
brgphy_bcm54k2_dspcode(struct mii_softc *sc)
{
	static const struct {
		int		reg;
		uint16_t	val;
	} dspcode[] = {
		{ 4,				0x01e1 },
		{ 9,				0x0300 },
		{ 0,				0 },
	};
	int i;

	for (i = 0; dspcode[i].reg != 0; i++)
		PHY_WRITE(sc, dspcode[i].reg, dspcode[i].val);
}

static void
brgphy_adc_bug(struct mii_softc *sc)
{
	static const struct {
		int		reg;
		uint16_t	val;
	} dspcode[] = {
		{ BRGPHY_MII_AUXCTL,		0x0c00 },
		{ BRGPHY_MII_DSP_ADDR_REG,	0x201f },
		{ BRGPHY_MII_DSP_RW_PORT,	0x2aaa },
		{ BRGPHY_MII_DSP_ADDR_REG,	0x000a },
		{ BRGPHY_MII_DSP_RW_PORT,	0x0323 },
		{ BRGPHY_MII_AUXCTL,		0x0400 },
		{ 0,				0 },
	};
	int i;

	for (i = 0; dspcode[i].reg != 0; i++)
		PHY_WRITE(sc, dspcode[i].reg, dspcode[i].val);
}

static void
brgphy_5704_a0_bug(struct mii_softc *sc)
{
	static const struct {
		int		reg;
		u_int16_t	val;
	} dspcode[] = {
		{ 0x1c,				0x8d68 },
		{ 0x1c,				0x8d68 },
		{ 0,				0 },
	};
	int i;

	for (i = 0; dspcode[i].reg != 0; i++)
		PHY_WRITE(sc, dspcode[i].reg, dspcode[i].val);
}

static void
brgphy_ber_bug(struct mii_softc *sc)
{
	static const struct {
		int		reg;
		uint16_t	val;
	} dspcode[] = {
		{ BRGPHY_MII_AUXCTL,		0x0c00 },
		{ BRGPHY_MII_DSP_ADDR_REG,	0x000a },
		{ BRGPHY_MII_DSP_RW_PORT,	0x310b },
		{ BRGPHY_MII_DSP_ADDR_REG,	0x201f },
		{ BRGPHY_MII_DSP_RW_PORT,	0x9506 },
		{ BRGPHY_MII_DSP_ADDR_REG,	0x401f },
		{ BRGPHY_MII_DSP_RW_PORT,	0x14e2 },
		{ BRGPHY_MII_AUXCTL,		0x0400 },
		{ 0,				0 },
	};
	int i;

	for (i = 0; dspcode[i].reg != 0; i++)
		PHY_WRITE(sc, dspcode[i].reg, dspcode[i].val);
}

static void
brgphy_crc_bug(struct mii_softc *sc)
{
	static const struct {
		int		reg;
		uint16_t	val;
	} dspcode[] = {
		{ BRGPHY_MII_DSP_ADDR_REG,	0x0a75 },
		{ 0x1c,				0x8c68 },
		{ 0x1c,				0x8d68 },
		{ 0x1c,				0x8c68 },
		{ 0,				0 },
	};
	int i;

	for (i = 0; dspcode[i].reg != 0; i++)
		PHY_WRITE(sc, dspcode[i].reg, dspcode[i].val);
}

static void
brgphy_jumbo_settings(struct mii_softc *sc, u_long mtu)
{
	uint32_t val;

	/* Set or clear jumbo frame settings in the PHY. */
	if (mtu > ETHER_MAX_LEN) {
		if (sc->mii_model == MII_MODEL_xxBROADCOM_BCM5401) {
			/* BCM5401 PHY cannot read-modify-write. */
			PHY_WRITE(sc, BRGPHY_MII_AUXCTL, 0x4c20);
		} else {
			PHY_WRITE(sc, BRGPHY_MII_AUXCTL, 0x7);
			val = PHY_READ(sc, BRGPHY_MII_AUXCTL);
			PHY_WRITE(sc, BRGPHY_MII_AUXCTL,
			    val | BRGPHY_AUXCTL_LONG_PKT);
		}

		val = PHY_READ(sc, BRGPHY_MII_PHY_EXTCTL);
		PHY_WRITE(sc, BRGPHY_MII_PHY_EXTCTL,
		    val | BRGPHY_PHY_EXTCTL_HIGH_LA);
	} else {
		PHY_WRITE(sc, BRGPHY_MII_AUXCTL, 0x7);
		val = PHY_READ(sc, BRGPHY_MII_AUXCTL);
		PHY_WRITE(sc, BRGPHY_MII_AUXCTL,
		    val & ~(BRGPHY_AUXCTL_LONG_PKT | 0x7));

		val = PHY_READ(sc, BRGPHY_MII_PHY_EXTCTL);
		PHY_WRITE(sc, BRGPHY_MII_PHY_EXTCTL,
		    val & ~BRGPHY_PHY_EXTCTL_HIGH_LA);
	}
}

static void
brgphy_eth_wirespeed(struct mii_softc *sc)
{
	u_int32_t val;

	/* Enable Ethernet@Wirespeed */
	PHY_WRITE(sc, BRGPHY_MII_AUXCTL, 0x7007);
	val = PHY_READ(sc, BRGPHY_MII_AUXCTL);
	PHY_WRITE(sc, BRGPHY_MII_AUXCTL, (val | (1 << 15) | (1 << 4)));
}

static void
brgphy_disable_early_dac(struct mii_softc *sc)
{
	uint32_t val;

	PHY_WRITE(sc, BRGPHY_MII_DSP_ADDR_REG, 0x0f08);
	val = PHY_READ(sc, BRGPHY_MII_DSP_RW_PORT);
	val &= ~(1 << 8);
	PHY_WRITE(sc, BRGPHY_MII_DSP_RW_PORT, val);
}
