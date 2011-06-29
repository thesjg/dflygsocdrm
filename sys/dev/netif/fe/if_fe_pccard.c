/*
 * All Rights Reserved, Copyright (C) Fujitsu Limited 1995
 *
 * This software may be used, modified, copied, distributed, and sold, in
 * both source and binary form provided that the above copyright, these
 * terms and the following disclaimer are retained.  The name of the author
 * and/or the contributor may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND THE CONTRIBUTOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR THE CONTRIBUTOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION.
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/dev/fe/if_fe_pccard.c,v 1.2.2.1 2000/09/22 10:01:47 nyan Exp $
 */

#include "opt_fe.h"
#include "opt_inet.h"
#include "opt_ipx.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <machine/clock.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_mib.h>
#include <net/if_media.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <machine_base/isa/ic/mb86960.h>
#include "if_fereg.h"
#include "if_fevar.h"

#include <bus/pccard/pccardvar.h>
#include <bus/pccard/pccarddevs.h>

#include "card_if.h"

/*
 *	PC-Card (PCMCIA) specific code.
 */
static int fe_pccard_probe(device_t);
static int fe_pccard_attach(device_t);
static int fe_pccard_detach(device_t);
static int fe_pccard_match(device_t);

static const struct fe_pccard_product {
        struct pccard_product mpp_product;
        u_int32_t mpp_ioalign;                  /* required alignment */
        int mpp_enet_maddr;
} fe_pccard_products[] = {
        { PCMCIA_CARD(TDK, LAK_CD021BX, 0), 0, -1 }, 
        { PCMCIA_CARD(TDK, LAK_CF010, 0), 0, -1 }, 
#if 0 /* XXX 86960-based? */
        { PCMCIA_CARD(TDK, LAK_DFL9610, 1), 0, -1 }, 
#endif
        { PCMCIA_CARD(CONTEC, CNETPC, 0), 0, -1 },
	{ PCMCIA_CARD(FUJITSU, LA501, 0), 0x20, -1 },
	{ PCMCIA_CARD(FUJITSU, LA10S, 0), 0, -1 },
	{ PCMCIA_CARD(RATOC, REX_R280, 0), 0, 0x1fc },
        { { NULL } }
};

static int
fe_pccard_match(device_t dev)
{
        const struct pccard_product *pp;

        if ((pp = pccard_product_lookup(dev,
	    (const struct pccard_product *)fe_pccard_products,
            sizeof(fe_pccard_products[0]), NULL)) != NULL) {
		if (pp->pp_name != NULL)
			device_set_desc(dev, pp->pp_name);
                return 0;
        }
        return ENXIO;
}

static device_method_t fe_pccard_methods[] = {
        /* Device interface */
        DEVMETHOD(device_probe,         pccard_compat_probe),
        DEVMETHOD(device_attach,        pccard_compat_attach),
        DEVMETHOD(device_detach,        fe_pccard_detach),

        /* Card interface */
        DEVMETHOD(card_compat_match,    fe_pccard_match),
        DEVMETHOD(card_compat_probe,    fe_pccard_probe),
        DEVMETHOD(card_compat_attach,   fe_pccard_attach),

	{ 0, 0 }
};

static driver_t fe_pccard_driver = {
	"fe",
	fe_pccard_methods,
	sizeof (struct fe_softc)
};

DRIVER_MODULE(if_fe, pccard, fe_pccard_driver, fe_devclass, NULL, NULL);


static int fe_probe_mbh(device_t);
static int fe_probe_tdk(device_t);

/*
 *      Initialize the device - called from Slot manager.
 */
static int
fe_pccard_probe(device_t dev)
{
	struct fe_softc *sc;
	int i, error;
	uint8_t sum;
	const uint8_t *ether_addr;

	/* Prepare for the device probe process.  */
	sc = device_get_softc(dev);
	sc->sc_unit = device_get_unit(dev);

	ether_addr = pccard_get_ether(dev);
	for (i = 0, sum = 0; i < ETHER_ADDR_LEN; i++)
		sum |= ether_addr[i];
	if (sum)
		bcopy(ether_addr, sc->sc_enaddr, ETHER_ADDR_LEN);

	/* Probe for supported cards.  */
	if ((error = fe_probe_mbh(dev)) == 0)
		goto end;
	fe_release_resource(dev);

	if ((error = fe_probe_tdk(dev)) == 0)
		goto end;
	fe_release_resource(dev);

end:
	if (error == 0)
		error = fe_alloc_irq(dev, 0);

	fe_release_resource(dev);
	return (error);
}

static int
fe_pccard_attach(device_t dev)
{
	struct fe_softc *sc = device_get_softc(dev);

	if (sc->port_used)
		fe_alloc_port(dev, sc->port_used);
	fe_alloc_irq(dev, 0);

	return fe_attach(dev);
}

/*
 *	feunload - unload the driver and clear the table.
 *	XXX TODO:
 *	This is usually called when the card is ejected, but
 *	can be caused by a modunload of a controller driver.
 *	The idea is to reset the driver's view of the device
 *	and ensure that any driver entry points such as
 *	read and write do not hang.
 */
static int
fe_pccard_detach(device_t dev)
{
	struct fe_softc *sc = device_get_softc(dev);
	struct ifnet *ifp = &sc->arpcom.ac_if;

	lwkt_serialize_enter(ifp->if_serializer);
	fe_stop(sc);
	bus_teardown_intr(dev, sc->irq_res, sc->irq_handle);
	lwkt_serialize_exit(ifp->if_serializer);

	ether_ifdetach(ifp);
	fe_release_resource(dev);

	return 0;
}


/*
 * Probe and initialization for Fujitsu MBH10302 PCMCIA Ethernet interface.
 * Note that this is for 10302 only; MBH10304 is handled by fe_probe_tdk().
 */
static void
fe_init_mbh(struct fe_softc *sc)
{
	/* Minimal initialization of 86960.  */
	DELAY(200);
	fe_outb(sc, FE_DLCR6, sc->proto_dlcr6 | FE_D6_DLC_DISABLE);
	DELAY(200);

	/* Disable all interrupts.  */
	fe_outb(sc, FE_DLCR2, 0);
	fe_outb(sc, FE_DLCR3, 0);

	/* Enable master interrupt flag.  */
	fe_outb(sc, FE_MBH0, FE_MBH0_MAGIC | FE_MBH0_INTR_ENABLE);
}

static int
fe_probe_mbh(device_t dev)
{
	struct fe_softc *sc = device_get_softc(dev);

	static struct fe_simple_probe_struct probe_table [] = {
		{ FE_DLCR2, 0x58, 0x00 },
		{ FE_DLCR4, 0x08, 0x00 },
		{ FE_DLCR6, 0xFF, 0xB6 },
		{ 0 }
	};

	/* MBH10302 occupies 32 I/O addresses. */
	if (fe_alloc_port(dev, 32))
		return ENXIO;

	/* Ethernet MAC address should *NOT* have been given by pccardd,
	   if this is a true MBH10302; i.e., Ethernet address must be
	   "all-zero" upon entry.  */
	if (sc->sc_enaddr[0] || sc->sc_enaddr[1] || sc->sc_enaddr[2] ||
	    sc->sc_enaddr[3] || sc->sc_enaddr[4] || sc->sc_enaddr[5])
		return ENXIO;

	/* Fill the softc struct with default values.  */
	fe_softc_defaults(sc);

	/*
	 * See if MBH10302 is on its address.
	 * I'm not sure the following probe code works.  FIXME.
	 */
	if (!fe_simple_probe(sc, probe_table))
		return ENXIO;

	/* Get our station address from EEPROM.  */
	fe_inblk(sc, FE_MBH10, sc->sc_enaddr, ETHER_ADDR_LEN);

	/* Make sure we got a valid station address.  */
	if (!valid_Ether_p(sc->sc_enaddr, 0))
		return ENXIO;

	/* Determine the card type.  */
	sc->type = FE_TYPE_MBH;
	sc->typestr = "MBH10302 (PCMCIA)";

	/* We seems to need our own IDENT bits...  FIXME.  */
	sc->proto_dlcr7 = FE_D7_BYTSWP_LH | FE_D7_IDENT_NICE;

	/* Setup hooks.  We need a special initialization procedure.  */
	sc->init = fe_init_mbh;

	return 0;
}

/*
 * Probe and initialization for TDK/CONTEC PCMCIA Ethernet interface.
 * by MASUI Kenji <masui@cs.titech.ac.jp>
 *
 * (Contec uses TDK Ethenet chip -- hosokawa)
 *
 * This version of fe_probe_tdk has been rewrote to handle
 * *generic* PC card implementation of Fujitsu MB8696x family.  The
 * name _tdk is just for a historical reason. :-)
 */
static int
fe_probe_tdk (device_t dev)
{
	struct fe_softc *sc = device_get_softc(dev);

        static struct fe_simple_probe_struct probe_table [] = {
                { FE_DLCR2, 0x50, 0x00 },
                { FE_DLCR4, 0x08, 0x00 },
            /*  { FE_DLCR5, 0x80, 0x00 },       Does not work well.  */
                { 0 }
        };

        /* C-NET(PC)C occupies 16 I/O addresses. */
	if (fe_alloc_port(dev, 16))
		return ENXIO;

	/* Fill the softc struct with default values.  */
	fe_softc_defaults(sc);

        /*
         * See if C-NET(PC)C is on its address.
         */
        if (!fe_simple_probe(sc, probe_table))
		return ENXIO;

        /* Determine the card type.  */
	sc->type = FE_TYPE_TDK;
        sc->typestr = "Generic MB8696x/78Q837x Ethernet (PCMCIA)";

        /* Make sure we got a valid station address.  */
        if (!valid_Ether_p(sc->sc_enaddr, 0))
		return ENXIO;

        return 0;
}
