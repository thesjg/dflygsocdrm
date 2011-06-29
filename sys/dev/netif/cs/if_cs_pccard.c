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
 * $FreeBSD: src/sys/dev/cs/if_cs_pccard.c,v 1.1.2.1 2001/01/25 20:13:48 imp Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/module.h>
#include <sys/bus.h>

#include <net/ethernet.h> 
#include <net/if.h> 
#include <net/if_arp.h>

#include "if_csvar.h"
#include <bus/pccard/pccardvar.h>
#include <bus/pccard/pccarddevs.h>

#include "card_if.h"

static const struct pccard_product cs_pccard_products[] = {
	PCMCIA_CARD(IBM, ETHERJET, 0),
	{ NULL }
};
static int
cs_pccard_match(device_t dev)
{
	const struct pccard_product *pp;

	if ((pp = pccard_product_lookup(dev, cs_pccard_products,
	    sizeof(cs_pccard_products[0]), NULL)) != NULL) {
		if (pp->pp_name != NULL)
			device_set_desc(dev, pp->pp_name);
		return 0;
	}
	return EIO;
}

static int
cs_pccard_probe(device_t dev)
{
	int error;

	error = cs_cs89x0_probe(dev);
        cs_release_resources(dev);
        return (error);
}

static device_method_t cs_pccard_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		pccard_compat_probe),
	DEVMETHOD(device_attach,	pccard_compat_attach),
	DEVMETHOD(device_detach,	cs_detach),

	/* Card interface */
	DEVMETHOD(card_compat_match,	cs_pccard_match),
	DEVMETHOD(card_compat_probe,	cs_pccard_probe),
	DEVMETHOD(card_compat_attach,	cs_attach),

	{ 0, 0 }
};

static driver_t cs_pccard_driver = {
	"cs",
	cs_pccard_methods,
	sizeof(struct cs_softc),
};

extern devclass_t cs_devclass;

DRIVER_MODULE(if_cs, pccard, cs_pccard_driver, cs_devclass, NULL, NULL);
MODULE_DEPEND(if_cs, pccard, 1, 1, 1);
