/* $DragonFly: src/sys/dev/usbmisc/ugensa/ugensa.c,v 1.1 2008/02/11 18:13:58 hasso Exp $ */
/* $OpenBSD: umsm.c,v 1.15 2007/06/14 10:11:16 mbalmer Exp $ */

/*
 * Copyright (c) 2006 Jonathan Gray <jsg@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Generic USB serial driver used for devices where hardware specific
 * don't apply or doesn't make sense (for example Qualcomm MSM EVDO, UMTS
 * and other similar communication devices).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/conf.h>
#include <sys/tty.h>
#include <sys/types.h>
#include <sys/bus.h>
#include <sys/module.h>

#include <bus/usb/usb.h>
#include <bus/usb/usbdi.h>
#include <bus/usb/usbdi_util.h>
#include <dev/usbmisc/ucom/ucomvar.h>

#ifdef UGENSA_DEBUG
static int	ugensadebug = 1;
#define DPRINTFN(n, x)  do { if (ugensadebug > (n)) kprintf x; } while (0)
#else
#define DPRINTFN(n, x)
#endif
#define DPRINTF(x) DPRINTFN(0, x)

#define UGENSABUFSZ	4096

struct ugensa_softc {
	struct ucom_softc	 sc_ucom;
};

struct ucom_callback ugensa_callback = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

static const struct usb_devno ugensa_devs[] = {
	{ USB_DEVICE(0x05c6, 0x6613) }, /* Qualcomm HSDPA MSM */
	{ USB_DEVICE(0x0c88, 0x17da) }, /* Kyocera KPC650 */
	{ USB_DEVICE(0x0f3d, 0x0112) }, /* AirPrime PC5220 */
	{ USB_DEVICE(0x1199, 0x0017) }, /* Sierra Wireless EM5625 */
	{ USB_DEVICE(0x1199, 0x0018) }, /* Sierra Wireless MC5720 */
	{ USB_DEVICE(0x1199, 0x0019) }, /* Sierra Wireless AirCard 595 */
	{ USB_DEVICE(0x1199, 0x0020) }, /* Sierra Wireless MC5725 */
	{ USB_DEVICE(0x1199, 0x0112) }, /* Sierra Wireless Aircard 580 */
	{ USB_DEVICE(0x1199, 0x0218) }, /* Sierra Wireless MC5720 */
	{ USB_DEVICE(0x1199, 0x6802) }, /* Sierra Wireless MC8755 */
	{ USB_DEVICE(0x1199, 0x6803) }, /* Sierra Wireless MC8765 */
	{ USB_DEVICE(0x1199, 0x6804) }, /* Sierra Wireless MC8755 */
	{ USB_DEVICE(0x1199, 0x6812) }, /* Sierra Wireless MC8775 */
	{ USB_DEVICE(0x1199, 0x6813) }, /* Sierra Wireless MC8755 */
	{ USB_DEVICE(0x1199, 0x6820) }, /* Sierra Wireless Aircard 875 */
	{ USB_DEVICE(0x12d1, 0x1001) }, /* Huawei Mobile Connect */
	{ USB_DEVICE(0x1410, 0x1100) }, /* Novatel Wireless ExpressCard 3G */
	{ USB_DEVICE(0x1410, 0x1110) }, /* Novatel Wireless Merlin V620 */
	{ USB_DEVICE(0x1410, 0x1130) }, /* Novatel Wireless S720 */
	{ USB_DEVICE(0x1410, 0x1410) }, /* Novatel Wireless U740 */
	{ USB_DEVICE(0x1410, 0x1430) }, /* Novatel Wireless XU870 */
	{ USB_DEVICE(0x1410, 0x2100) }, /* Novatel Wireless ES620 */
	{ USB_DEVICE(0x1410, 0x2110) }, /* Novatel Wireless U720 */
	{ USB_DEVICE(0x413c, 0x8115) }, /* Dell W5500 */
};

static device_probe_t ugensa_match;
static device_attach_t ugensa_attach;
static device_detach_t ugensa_detach;

static device_method_t ugensa_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, ugensa_match),
	DEVMETHOD(device_attach, ugensa_attach),
	DEVMETHOD(device_detach, ugensa_detach),
	{ 0, 0 }
};

static driver_t ugensa_driver = { 
	"ucom",
	ugensa_methods,
	sizeof (struct ugensa_softc)
};

DRIVER_MODULE(ugensa, uhub, ugensa_driver, ucom_devclass, usbd_driver_load, 0);
MODULE_DEPEND(ugensa, usb, 1, 1, 1);
MODULE_DEPEND(ugensa, ucom, UCOM_MINVER, UCOM_PREFVER, UCOM_MAXVER);
MODULE_VERSION(ugensa, 1);

static int
ugensa_match(device_t self)
{
	struct usb_attach_arg *uaa = device_get_ivars(self);

	if (uaa->iface == NULL)
		return UMATCH_NONE;

	return (usb_lookup(ugensa_devs, uaa->vendor, uaa->product) != NULL) ?
	    UMATCH_VENDOR_IFACESUBCLASS : UMATCH_NONE;
}

static int
ugensa_attach(device_t self)
{
	struct ugensa_softc *sc = device_get_softc(self);
	struct usb_attach_arg *uaa = device_get_ivars(self);
	struct ucom_softc *ucom;
	usb_interface_descriptor_t *id;
	usb_endpoint_descriptor_t *ed;
	int i;

	ucom = &sc->sc_ucom;
	bzero(sc, sizeof (struct ugensa_softc));

	ucom->sc_dev = self;
	ucom->sc_udev = uaa->device;
	ucom->sc_iface = uaa->iface;

	id = usbd_get_interface_descriptor(ucom->sc_iface);

	ucom->sc_bulkin_no = ucom->sc_bulkout_no = -1;
	for (i = 0; i < id->bNumEndpoints; i++) {
		ed = usbd_interface2endpoint_descriptor(ucom->sc_iface, i);
		if (ed == NULL) {
			device_printf(ucom->sc_dev, "no endpoint descriptor "
				      "found for %d\n", i);
			goto error;
		}

		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN &&
		    UE_GET_XFERTYPE(ed->bmAttributes) == UE_BULK)
			ucom->sc_bulkin_no = ed->bEndpointAddress;
		else if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT &&
		    UE_GET_XFERTYPE(ed->bmAttributes) == UE_BULK)
			ucom->sc_bulkout_no = ed->bEndpointAddress;
	}
	if (ucom->sc_bulkin_no == -1 || ucom->sc_bulkout_no == -1) {
		device_printf(ucom->sc_dev, "missing endpoint\n");
		goto error;
	}

	ucom->sc_parent = sc;
	ucom->sc_portno = UCOM_UNK_PORTNO;
	ucom->sc_ibufsize = UGENSABUFSZ;
	ucom->sc_obufsize = UGENSABUFSZ;
	ucom->sc_ibufsizepad = UGENSABUFSZ;
	ucom->sc_opkthdrlen = 0;
	ucom->sc_callback = &ugensa_callback;

	usbd_add_drv_event(USB_EVENT_DRIVER_ATTACH, ucom->sc_udev,
			   ucom->sc_dev);

	DPRINTF(("%s: in = 0x%x, out = 0x%x\n",
		 device_get_nameunit(ucom->sc_dev), ucom->sc_bulkin_no,
		 ucom->sc_bulkout_no));

	ucom_attach(&sc->sc_ucom);

	return 0;

error:
	ucom->sc_dying = 1;
	return ENXIO;
}

static int
ugensa_detach(device_t self)
{
	struct ugensa_softc *sc = device_get_softc(self);
	int rv = 0;

	DPRINTF(("ugensa_detach: sc=%p\n", sc));
	sc->sc_ucom.sc_dying = 1;
	rv = ucom_detach(&sc->sc_ucom);
	usbd_add_drv_event(USB_EVENT_DRIVER_DETACH, sc->sc_ucom.sc_udev,
			   sc->sc_ucom.sc_dev);

	return (rv);
}

#if 0 /* not yet */
int
ugensa_activate(struct device *self, enum devact act)
{
	struct ugensa_softc *sc = (struct ugensa_softc *)self;
	int rv = 0;

	switch (act) {
	case DVACT_ACTIVATE:
		break;

	case DVACT_DEACTIVATE:
		if (sc->sc_subdev != NULL)
			rv = config_deactivate(sc->sc_subdev);
		sc->sc_dying = 1;
		break;
	}
	return (rv);
}
#endif