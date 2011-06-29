/*
 * Copyright (c) 1999 M. Warner Losh <imp@village.org> 
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
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/dev/sn/if_sn_pccard.c,v 1.3.2.2 2001/01/25 19:40:27 imp Exp $
 */

/*
 * Modifications for Megahertz X-Jack Ethernet Card (XJ-10BT)
 * 
 * Copyright (c) 1996 by Tatsumi Hosokawa <hosokawa@jp.FreeBSD.org>
 *                       BSD-nomads, Tokyo, Japan.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/rman.h>
 
#include <net/ethernet.h> 
#include <net/if.h> 
#include <net/if_arp.h>
#include <net/if_media.h>

#include <machine/clock.h>

#include "if_snreg.h"
#include "if_snvar.h"
#include <bus/pccard/pccardvar.h>
#include <bus/pccard/pccarddevs.h>

#include "card_if.h"

static const struct pccard_product sn_pccard_products[] = {
	PCMCIA_CARD(DSPSI, XJACK, 0),
	PCMCIA_CARD(NEWMEDIA, BASICS, 0),
#if 0
	PCMCIA_CARD(SMC, 8020BT, 0),
#endif
	{ NULL }
};

static int
sn_pccard_match(device_t dev)
{
	const struct pccard_product *pp;

	if ((pp = pccard_product_lookup(dev, sn_pccard_products,
	    sizeof(sn_pccard_products[0]), NULL)) != NULL) {
		if (pp->pp_name != NULL)
			device_set_desc(dev, pp->pp_name);
		return 0;
	}
	return EIO;
}

/*
 * Initialize the device - called from Slot manager.
 */
static int
sn_pccard_probe(device_t dev)
{
	return (sn_probe(dev, 1));
}

static int
sn_pccard_attach(device_t dev)
{
	struct sn_softc *sc = device_get_softc(dev);
	int i;
	uint8_t sum;
	const uint8_t *ether_addr;

	sc->pccard_enaddr = 0;
	ether_addr = pccard_get_ether(dev);
	for (i = 0, sum = 0; i < ETHER_ADDR_LEN; i++)
		sum |= ether_addr[i];
	if (sum) {
		sc->pccard_enaddr = 1;
		bcopy(ether_addr, sc->arpcom.ac_enaddr, ETHER_ADDR_LEN);
	}

	return (sn_attach(dev));
}

static int
sn_pccard_detach(device_t dev)
{
	struct sn_softc *sc = device_get_softc(dev);
	struct ifnet *ifp = &sc->arpcom.ac_if;

	lwkt_serialize_enter(ifp->if_serializer);
	ifp->if_flags &= ~IFF_RUNNING;
	bus_teardown_intr(dev, sc->irq_res, sc->intrhand);
	lwkt_serialize_enter(ifp->if_serializer);

	ether_ifdetach(&sc->arpcom.ac_if);
	sn_deactivate(dev);

	return 0;
}

static device_method_t sn_pccard_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		pccard_compat_probe),
	DEVMETHOD(device_attach,	pccard_compat_attach),
	DEVMETHOD(device_detach,	sn_pccard_detach),

	/* Card interface */
	DEVMETHOD(card_compat_match,	sn_pccard_match),
	DEVMETHOD(card_compat_probe,	sn_pccard_probe),
	DEVMETHOD(card_compat_attach,	sn_pccard_attach),

	{ 0, 0 }
};

static driver_t sn_pccard_driver = {
	"sn",
	sn_pccard_methods,
	sizeof(struct sn_softc),
};

extern devclass_t sn_devclass;

DRIVER_MODULE(if_sn, pccard, sn_pccard_driver, sn_devclass, NULL, NULL);
