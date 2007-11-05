/*-
 * Copyright (c) 2003 Scott Long
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
 * $FreeBSD: src/sys/dev/usb/umct.c,v 1.12 2006/09/07 00:06:42 imp Exp $
 * $DragonFly: src/sys/dev/usbmisc/umct/umct.c,v 1.13 2007/11/05 13:32:28 hasso Exp $
 */

/*
 * Driver for the MCT (Magic Control Technology) USB-RS232 Converter.
 * Based on the superb documentation from the linux mct_u232 driver by
 * Wolfgang Grandeggar <wolfgang@cec.ch>.
 * This device smells a lot like the Belkin F5U103, except that it has
 * suffered some mild brain-damage.  This driver is based off of the ubsa.c
 * driver from Alexander Kabaev <kan@freebsd.org>.  Merging the two together
 * might be useful, though the subtle differences might lead to lots of
 * #ifdef's.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/bus.h>
#include <sys/tty.h>
#include <sys/taskqueue.h>

#include <bus/usb/usb.h>
#include <bus/usb/usbdi.h>
#include <bus/usb/usbdi_util.h>
#include <bus/usb/usbdevs.h>
#include "../ucom/ucomvar.h"

/* The UMCT advertises the standard 8250 UART registers */
#define UMCT_GET_MSR		2	/* Get Modem Status Register */
#define UMCT_GET_MSR_SIZE	1
#define UMCT_GET_LCR		6	/* Get Line Control Register */
#define UMCT_GET_LCR_SIZE	1
#define UMCT_SET_BAUD		5	/* Set the Baud Rate Divisor */
#define UMCT_SET_BAUD_SIZE	4
#define UMCT_SET_LCR		7	/* Set Line Control Register */
#define UMCT_SET_LCR_SIZE	1
#define UMCT_SET_MCR		10	/* Set Modem Control Register */
#define UMCT_SET_MCR_SIZE	1
#define UMCT_SET_UNKNOWN1	11
#define UMCT_SET_UNKNOWN1_SIZE	1
#define UMCT_SET_UNKNOWN2	12
#define UMCT_SET_UNKNOWN2_SIZE	1


#define UMCT_INTR_INTERVAL	100
#define UMCT_IFACE_INDEX	0
#define UMCT_CONFIG_INDEX	1

struct umct_softc {
	struct ucom_softc	sc_ucom;
	int			sc_iface_number;
	usbd_interface_handle	sc_intr_iface;
	int			sc_intr_number;
	usbd_pipe_handle	sc_intr_pipe;
	u_char			*sc_intr_buf;
	int			sc_isize;
	uint8_t			sc_lsr;
	uint8_t			sc_msr;
	uint8_t			sc_lcr;
	uint8_t			sc_mcr;
	struct task		sc_task;
};

static void umct_intr(usbd_xfer_handle, usbd_private_handle, usbd_status);
static void umct_get_status(void *, int, u_char *, u_char *);
static void umct_set(void *, int, int, int);
static int  umct_param(void *, int, struct termios *);
static int  umct_open(void *, int);
static void umct_close(void *, int);
static void umct_notify(void *, int);

static struct ucom_callback umct_callback = {
	umct_get_status,	/* ucom_get_status */
	umct_set,		/* ucom_set */
	umct_param,		/* ucom_param */
	NULL,			/* ucom_ioctl */
	umct_open,		/* ucom_open */
	umct_close,		/* ucom_close */
	NULL,			/* ucom_read */
	NULL			/* ucom_write */
};

static const struct usb_devno umct_products[] = {
	{ USB_DEVICE(0x050d, 0x0109) }, /* Belkin F5U109 */
	{ USB_DEVICE(0x050d, 0x0409) }, /* Belkin F5U409 */
	{ USB_DEVICE(0x0711, 0x0200) }, /* D-Link DU-H3SP USB BAY Hub */
	{ USB_DEVICE(0x0711, 0x0210) }, /* MCT USB-232 */
	{ USB_DEVICE(0x0711, 0x0230) }, /* Sitecom USB-232 */
};

static device_probe_t	umct_match;
static device_attach_t	umct_attach;
static device_detach_t	umct_detach;

static device_method_t umct_methods[] = {
	DEVMETHOD(device_probe, umct_match),
	DEVMETHOD(device_attach, umct_attach),
	DEVMETHOD(device_detach, umct_detach),
	{ 0, 0 }
};

static driver_t umct_driver = {
	"ucom",
	umct_methods,
	sizeof(struct umct_softc)
};

DRIVER_MODULE(umct, uhub, umct_driver, ucom_devclass, usbd_driver_load, 0);
MODULE_DEPEND(umct, usb, 1, 1, 1);
MODULE_DEPEND(umct, ucom, UCOM_MINVER, UCOM_PREFVER, UCOM_MAXVER);
MODULE_VERSION(umct, 1);

static int
umct_match(device_t self)
{
	struct usb_attach_arg *uaa = device_get_ivars(self);

	if (uaa->iface != NULL)
		return (UMATCH_NONE);

	return (usb_lookup(umct_products, uaa->vendor, uaa->product) != NULL) ?
	    UMATCH_VENDOR_PRODUCT : UMATCH_NONE;
}

static int
umct_attach(device_t self)
{
	struct umct_softc *sc = device_get_softc(self);
	struct usb_attach_arg *uaa = device_get_ivars(self);
	usbd_device_handle dev;
	struct ucom_softc *ucom;
	usb_config_descriptor_t *cdesc;
	usb_interface_descriptor_t *id;
	usb_endpoint_descriptor_t *ed;
	char *devinfo;
	usbd_status err;
	int i;

	dev = uaa->device;
	devinfo = kmalloc(1024, M_USBDEV, M_INTWAIT | M_ZERO);
	bzero(sc, sizeof(struct umct_softc));
	ucom = &sc->sc_ucom;
	ucom->sc_dev = self;
	ucom->sc_udev = dev;
	ucom->sc_iface = uaa->iface;

	usbd_devinfo(dev, 0, devinfo);
	device_set_desc_copy(self, devinfo);
	device_printf(ucom->sc_dev, "%s\n", devinfo);

	ucom->sc_bulkout_no = -1;
	ucom->sc_bulkin_no = -1;
	sc->sc_intr_number = -1;
	sc->sc_intr_pipe = NULL;

	err = usbd_set_config_index(dev, UMCT_CONFIG_INDEX, 1);
	if (err) {
		device_printf(ucom->sc_dev, "failed to set configuration: %s\n",
			      usbd_errstr(err));
		ucom->sc_dying = 1;
		goto error;
	}

	cdesc = usbd_get_config_descriptor(ucom->sc_udev);
	if (cdesc == NULL) {
		device_printf(ucom->sc_dev, "failed to get configuration "
			      "descriptor\n");
		ucom->sc_dying = 1;
		goto error;
	}

	err = usbd_device2interface_handle(dev, UMCT_IFACE_INDEX,
	    &ucom->sc_iface);
	if (err) {
		device_printf(ucom->sc_dev, "failed to get interface: %s\n",
			      usbd_errstr(err));
		ucom->sc_dying = 1;
		goto error;
	}

	id = usbd_get_interface_descriptor(ucom->sc_iface);
	sc->sc_iface_number = id->bInterfaceNumber;

	for (i = 0; i < id->bNumEndpoints; i++) {
		ed = usbd_interface2endpoint_descriptor(ucom->sc_iface, i);
		if (ed == NULL) {
			device_printf(ucom->sc_dev, "no endpoint descriptor "
				      "for %d\n", i);
			ucom->sc_dying = 1;
			goto error;
		}

		/*
		 * The real bulk-in endpoint is also marked as an interrupt.
		 * The only way to differentiate it from the real interrupt
                 * endpoint is to look at the wMaxPacketSize field.
		 */
		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN) {
			if (UGETW(ed->wMaxPacketSize) == 0x2) {
				sc->sc_intr_number = ed->bEndpointAddress;
				sc->sc_isize = UGETW(ed->wMaxPacketSize);
			} else {
				ucom->sc_bulkin_no = ed->bEndpointAddress;
				ucom->sc_ibufsize = UGETW(ed->wMaxPacketSize);
			}
			continue;
		}

		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT) {
			ucom->sc_bulkout_no = ed->bEndpointAddress;
			/* MCT Sitecom USB-232 device is broken. The bulk out
			 * endpoint descriptor reports 32 bytes, but data will
			 * get dropped if this value is used. */
			if (uaa->vendor == 0x0711 && uaa->product == 0x0230)
				ucom->sc_obufsize = 16;
			else
				ucom->sc_obufsize = UGETW(ed->wMaxPacketSize);
			continue;
		}

		device_printf(ucom->sc_dev, "warning - unsupported endpoint "
			      "0x%x\n", ed->bEndpointAddress);
	}

	if (sc->sc_intr_number == -1) {
		device_printf(ucom->sc_dev, "could not find interrupt in\n");
		ucom->sc_dying = 1;
		goto error;
	}

	sc->sc_intr_iface = ucom->sc_iface;

	if (ucom->sc_bulkout_no == -1) {
		device_printf(ucom->sc_dev, "rould not find data bulk out\n");
		ucom->sc_dying = 1;
		goto error;
	}

	ucom->sc_parent = sc;
	ucom->sc_portno = UCOM_UNK_PORTNO;
	ucom->sc_opkthdrlen = 0;
	ucom->sc_callback = &umct_callback;
	TASK_INIT(&sc->sc_task, 0, umct_notify, sc);
	ucom_attach(ucom);

	kfree(devinfo, M_USBDEV);
	return 0;

error:
	kfree(devinfo, M_USBDEV);
	return ENXIO;
}

static int
umct_detach(device_t self)
{
	struct umct_softc *sc = device_get_softc(self);
	int rv;

	if (sc->sc_intr_pipe != NULL) {
		usbd_abort_pipe(sc->sc_intr_pipe);
		usbd_close_pipe(sc->sc_intr_pipe);
		kfree(sc->sc_intr_buf, M_USBDEV);
		sc->sc_intr_pipe = NULL;
	}

	sc->sc_ucom.sc_dying = 1;
	rv = ucom_detach(&sc->sc_ucom);
	return (rv);
}

static int
umct_request(struct umct_softc *sc, uint8_t request, int len, uint32_t value)
{
	usb_device_request_t req;
	usbd_status err;
	uint8_t oval[4];

	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = request;
	USETW(req.wValue, 0);
	USETW(req.wIndex, sc->sc_iface_number);
	USETW(req.wLength, len);
	USETDW(oval, value);

	err = usbd_do_request(sc->sc_ucom.sc_udev, &req, oval);
	if (err)
		device_printf(sc->sc_ucom.sc_dev, "ubsa_request: %s\n",
			      usbd_errstr(err));
	return (err);
}

static void
umct_intr(usbd_xfer_handle xfer, usbd_private_handle priv, usbd_status status)
{
	struct umct_softc *sc;
	u_char *buf;

	sc = (struct umct_softc *)priv;
	buf = sc->sc_intr_buf;
	if (sc->sc_ucom.sc_dying)
		return;

	if (status != USBD_NORMAL_COMPLETION) {
		if (status == USBD_NOT_STARTED || status == USBD_CANCELLED)
			return;

		usbd_clear_endpoint_stall_async(sc->sc_intr_pipe);
		return;
	}

	sc->sc_msr = buf[0];
	sc->sc_lsr = buf[1];

	/*
	 * Defer notifying the ucom layer as it doesn't like to be bothered
         * from an interrupt context.
	 */
	taskqueue_enqueue(taskqueue_swi, &sc->sc_task);
}

static void
umct_notify(void *arg, int count)
{
	struct umct_softc *sc;

	sc = (struct umct_softc *)arg;
	if (sc->sc_ucom.sc_dying == 0)
		ucom_status_change(&sc->sc_ucom);
}

static void
umct_get_status(void *addr, int portno, u_char *lsr, u_char *msr)
{
	struct umct_softc *sc;

	sc = addr;
	if (lsr != NULL)
		*lsr = sc->sc_lsr;
	if (msr != NULL)
		*msr = sc->sc_msr;

	return;
}

static void
umct_set(void *addr, int portno, int reg, int onoff)
{
	struct umct_softc *sc;

	sc = addr;
	switch (reg) {
	case UCOM_SET_BREAK:
		sc->sc_lcr &= ~0x40;
		sc->sc_lcr |= (onoff) ? 0x40 : 0;
		umct_request(sc, UMCT_SET_LCR, UMCT_SET_LCR_SIZE, sc->sc_lcr);
		break;
	case UCOM_SET_DTR:
		sc->sc_mcr &= ~0x01;
		sc->sc_mcr |= (onoff) ? 0x01 : 0;
		umct_request(sc, UMCT_SET_MCR, UMCT_SET_MCR_SIZE, sc->sc_mcr);
		break;
	case UCOM_SET_RTS:
		sc->sc_mcr &= ~0x2;
		sc->sc_mcr |= (onoff) ? 0x02 : 0;
		umct_request(sc, UMCT_SET_MCR, UMCT_SET_MCR_SIZE, sc->sc_mcr);
		break;
	default:
		break;
	}
}

static int
umct_calc_baud(u_int baud)
{
	switch(baud) {
	case B300: return (0x1);
	case B600: return (0x2);
	case B1200: return (0x3);
	case B2400: return (0x4);
	case B4800: return (0x6);
	case B9600: return (0x8);
	case B19200: return (0x9);
	case B38400: return (0xa);
	case B57600: return (0xb);
	case B115200: return (0xc);
	case B0:
	default:
		break;
	}

	return (0x0);
}

static int
umct_param(void *addr, int portno, struct termios *ti)
{
	struct umct_softc *sc;
	uint32_t value;

	sc = addr;
	value = umct_calc_baud(ti->c_ospeed);
	umct_request(sc, UMCT_SET_BAUD, UMCT_SET_BAUD_SIZE, value);
	umct_request(sc, UMCT_SET_UNKNOWN1, UMCT_SET_UNKNOWN1_SIZE, 0);
	umct_request(sc, UMCT_SET_UNKNOWN2, UMCT_SET_UNKNOWN2_SIZE, 0);

	value = sc->sc_lcr & 0x40;

	switch (ti->c_cflag & CSIZE) {
	case CS5: value |= 0x0; break;
	case CS6: value |= 0x1; break;
	case CS7: value |= 0x2; break;
	case CS8: value |= 0x3; break;
	default: value |= 0x0; break;
	}

	value |= (ti->c_cflag & CSTOPB) ? 0x4 : 0;
	if (ti->c_cflag & PARENB) {
		value |= 0x8;
		value |= (ti->c_cflag & PARODD) ? 0x0 : 0x10;
	}

	/*
	 * XXX There doesn't seem to be a way to tell the device to use flow
         * control.
	 */

	sc->sc_lcr = value;
	umct_request(sc, UMCT_SET_LCR, UMCT_SET_LCR_SIZE, value);

	return (0);
}

static int
umct_open(void *addr, int portno)
{
	struct umct_softc *sc;
	int err;

	sc = addr;
	if (sc->sc_ucom.sc_dying) {
		return (ENXIO);
	}

	if (sc->sc_intr_number != -1 && sc->sc_intr_pipe == NULL) {
		sc->sc_intr_buf = kmalloc(sc->sc_isize, M_USBDEV, M_WAITOK);
		err = usbd_open_pipe_intr(sc->sc_intr_iface, sc->sc_intr_number,
		    USBD_SHORT_XFER_OK, &sc->sc_intr_pipe, sc, sc->sc_intr_buf,
		    sc->sc_isize, umct_intr, UMCT_INTR_INTERVAL);
		if (err) {
			device_printf(sc->sc_ucom.sc_dev, "cannot open "
				      "interrupt pipe (addr %d)\n",
				      sc->sc_intr_number);
			kfree(sc->sc_intr_buf, M_USBDEV);
			return (EIO);
		}
	}

	return (0);
}

static void
umct_close(void *addr, int portno)
{
	struct umct_softc *sc;
	int err;

	sc = addr;
	if (sc->sc_ucom.sc_dying)
		return;

	if (sc->sc_intr_pipe != NULL) {
		err = usbd_abort_pipe(sc->sc_intr_pipe);
		if (err)
			device_printf(sc->sc_ucom.sc_dev, "abort interrupt "
				      "pipe failed: %s\n", usbd_errstr(err));
		err = usbd_close_pipe(sc->sc_intr_pipe);
		if (err)
			device_printf(sc->sc_ucom.sc_dev, "close interrupt "
				      "pipe failed: %s\n", usbd_errstr(err));
		kfree(sc->sc_intr_buf, M_USBDEV);
		sc->sc_intr_pipe = NULL;
	}
}
