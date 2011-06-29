/*
 * Copyright (c) 1997, 1998, 1999
 *	Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
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
 * $FreeBSD: src/sys/dev/an/if_an_pccard.c,v 1.1.2.6 2003/02/01 03:25:12 ambrisko Exp $
 */

/*
 * Aironet 4500/4800 802.11 PCMCIA/ISA/PCI driver for FreeBSD.
 *
 * Written by Bill Paul <wpaul@ctr.columbia.edu>
 * Electrical Engineering Department
 * Columbia University, New York City
 */

#include "opt_inet.h"

#ifdef INET
#define ANCACHE
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/interrupt.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/rman.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_media.h>

#include <bus/pccard/pccardvar.h>
#include <bus/pccard/pccarddevs.h>
#include "card_if.h"

#include "if_aironet_ieee.h"
#include "if_anreg.h"

/*
 * Support for PCMCIA cards.
 */
static int  an_pccard_match(device_t);
static int  an_pccard_probe(device_t);
static int  an_pccard_attach(device_t);

static device_method_t an_pccard_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		pccard_compat_probe),
	DEVMETHOD(device_attach,	pccard_compat_attach),
	DEVMETHOD(device_shutdown,	an_shutdown),
	DEVMETHOD(device_detach,	an_detach),

	/* Card interface */
	DEVMETHOD(card_compat_match,	an_pccard_match),
	DEVMETHOD(card_compat_probe,	an_pccard_probe),
	DEVMETHOD(card_compat_attach,	an_pccard_attach),

	{ 0, 0 }
};

static driver_t an_pccard_driver = {
	"an",
	an_pccard_methods,
	sizeof(struct an_softc)
};

static devclass_t an_pccard_devclass;

DRIVER_MODULE(if_an, pccard, an_pccard_driver, an_pccard_devclass, NULL, NULL);

static const struct pccard_product an_pccard_products[] = {
	PCMCIA_CARD(AIRONET, PC4500, 0),
	PCMCIA_CARD(AIRONET, PC4800, 0),
	PCMCIA_CARD(AIRONET, 350, 0),
	PCMCIA_CARD(XIRCOM, CWE1130, 0), 
	{ NULL }
};

static int
an_pccard_match(device_t dev)
{
	const struct pccard_product *pp;

	if ((pp = pccard_product_lookup(dev, an_pccard_products,
	    sizeof(an_pccard_products[0]), NULL)) != NULL) {
		if (pp->pp_name != NULL)
			device_set_desc(dev, pp->pp_name);
		return (0);
	}
	return (ENXIO);
}

static int
an_pccard_probe(device_t dev)
{
	int     error;

	error = an_probe(dev);
	if (error == 0) {
		device_set_desc(dev, "Aironet PC4500/PC4800");
		error = an_alloc_irq(dev, 0, 0);
	}
	an_release_resources(dev);
	return (error);
}


static int
an_pccard_attach(device_t dev)
{
	struct an_softc *sc = device_get_softc(dev);
	struct ifnet *ifp = &sc->arpcom.ac_if;
	int flags = device_get_flags(dev);
	int error;

	an_alloc_port(dev, sc->port_rid, AN_IOSIZ);
	an_alloc_irq(dev, sc->irq_rid, 0);

	sc->an_bhandle = rman_get_bushandle(sc->port_res);
	sc->an_btag = rman_get_bustag(sc->port_res);

	error = an_attach(sc, dev, flags);
	if (error)
		goto fail;

	/*
	 * Must setup the interrupt after the an_attach to prevent racing.
	 */
	error = bus_setup_intr(dev, sc->irq_res, INTR_MPSAFE,
			       an_intr, sc, &sc->irq_handle,
			       sc->arpcom.ac_if.if_serializer);
	if (error) {
		ether_ifdetach(&sc->arpcom.ac_if);
		ifmedia_removeall(&sc->an_ifmedia);
		goto fail;
	}

	ifp->if_cpuid = ithread_cpuid(rman_get_start(sc->irq_res));
	KKASSERT(ifp->if_cpuid >= 0 && ifp->if_cpuid < ncpus);

	return 0;

fail:
	an_release_resources(dev);
	return (error);
}
