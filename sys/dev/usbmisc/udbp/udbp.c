/*
 * Copyright (c) 1996-2000 Whistle Communications, Inc.
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
 * 3. Neither the name of author nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NICK HIBMA AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/dev/usb/udbp.c,v 1.24 2003/08/24 17:55:55 obrien Exp $
 * $DragonFly: src/sys/dev/usbmisc/udbp/Attic/udbp.c,v 1.16 2007/11/05 13:32:28 hasso Exp $
 */

/* Driver for arbitrary double bulk pipe devices.
 * The driver assumes that there will be the same driver on the other side.
 *
 * XXX Some more information on what the framing of the IP packets looks like.
 *
 * To take full advantage of bulk transmission, packets should be chosen
 * between 1k and 5k in size (1k to make sure the sending side starts
 * straming, and <5k to avoid overflowing the system with small TDs).
 */


/* probe/attach/detach:
 *  Connect the driver to the hardware and netgraph
 *
 * udbp_setup_out_transfer(sc);
 *  Setup an outbound transfer. Only one transmit can be active at the same
 *  time.
 *  XXX If it is required that the driver is able to queue multiple requests
 *      let me know. That is slightly difficult, due to the fact that we
 *	cannot call usbd_alloc_xfer in int context.
 *
 * udbp_setup_in_transfer(sc)
 *  Prepare an in transfer that will be waiting for data to come in. It
 *  is submitted and sits there until data is available.
 *  The callback resubmits a new transfer on completion.
 *
 *  The reason we submit a bulk in transfer is that USB does not know about
 *  interrupts. The bulk transfer continuously polls the device for data.
 *  While the device has no data available, the device NAKs the TDs. As soon
 *  as there is data, the transfer happens and the data comes flowing in.
 *
 *  In case you were wondering, interrupt transfers happen exactly that way.
 *  It therefore doesn't make sense to use the interrupt pipe to signal
 *  'data ready' and then schedule a bulk transfer to fetch it. That would
 *  incur a 2ms delay at least, without reducing bandwidth requirements.
 *
 */



#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/ctype.h>
#include <sys/errno.h>
#include <sys/sysctl.h>
#include <sys/thread2.h>

#include <net/if.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usbhid.h>

#include <dev/usb/usbdevs.h>


#include <netgraph/ng_message.h>
#include <netgraph/ng_parse.h>
#include <dev/usb/udbp.h>
#include <netgraph/netgraph.h>

#ifdef USB_DEBUG
#define DPRINTF(x)	if (udbpdebug) kprintf x
#define DPRINTFN(n,x)	if (udbpdebug>(n)) kprintf x
int	udbpdebug = 0;
SYSCTL_NODE(_hw_usb, OID_AUTO, udbp, CTLFLAG_RW, 0, "USB udbp");
SYSCTL_INT(_hw_usb_udbp, OID_AUTO, debug, CTLFLAG_RW,
	   &udbpdebug, 0, "udbp debug level");
#else
#define DPRINTF(x)
#define DPRINTFN(n,x)
#endif

#define MS_TO_TICKS(ms) ((ms) * hz / 1000)

#define UDBP_TIMEOUT	2000	/* timeout on outbound transfers, in msecs */
#define UDBP_BUFFERSIZE	2048	/* maximum number of bytes in one transfer */


struct udbp_softc {
	device_t		sc_dev;		/* base device */
	usbd_interface_handle	sc_iface;

	usbd_pipe_handle	sc_bulkin_pipe;
	int			sc_bulkin;
	usbd_xfer_handle	sc_bulkin_xfer;
	void 			*sc_bulkin_buffer;
	int			sc_bulkin_bufferlen;
	int			sc_bulkin_datalen;

	usbd_pipe_handle	sc_bulkout_pipe;
	int			sc_bulkout;
	usbd_xfer_handle	sc_bulkout_xfer;
	void 			*sc_bulkout_buffer;
	int			sc_bulkout_bufferlen;
	int			sc_bulkout_datalen;

	int			flags;
#	define			DISCONNECTED		0x01
#	define			OUT_BUSY		0x02
#	define			NETGRAPH_INITIALISED	0x04
	node_p		node;		/* back pointer to node */
	hook_p  	hook;		/* pointer to the hook */
	u_int   	packets_in;	/* packets in from downstream */
	u_int   	packets_out;	/* packets out towards downstream */
	struct	ifqueue	xmitq_hipri;	/* hi-priority transmit queue */
	struct	ifqueue	xmitq;		/* low-priority transmit queue */

};
typedef struct udbp_softc *udbp_p;



static ng_constructor_t	ng_udbp_constructor;
static ng_rcvmsg_t	ng_udbp_rcvmsg;
static ng_shutdown_t	ng_udbp_rmnode;
static ng_newhook_t	ng_udbp_newhook;
static ng_connect_t	ng_udbp_connect;
static ng_rcvdata_t	ng_udbp_rcvdata;
static ng_disconnect_t	ng_udbp_disconnect;

/* Parse type for struct ngudbpstat */
static const struct ng_parse_struct_field
	ng_udbp_stat_type_fields[] = NG_UDBP_STATS_TYPE_INFO;
static const struct ng_parse_type ng_udbp_stat_type = {
	&ng_parse_struct_type,
	&ng_udbp_stat_type_fields
};

/* List of commands and how to convert arguments to/from ASCII */
static const struct ng_cmdlist ng_udbp_cmdlist[] = {
	{
	  NGM_UDBP_COOKIE,
	  NGM_UDBP_GET_STATUS,
	  "getstatus",
	  NULL,
	  &ng_udbp_stat_type,
	},
	{
	  NGM_UDBP_COOKIE,
	  NGM_UDBP_SET_FLAG,
	  "setflag",
	  &ng_parse_int32_type,
	  NULL
	},
	{ 0 }
};

/* Netgraph node type descriptor */
static struct ng_type ng_udbp_typestruct = {
	NG_ABI_VERSION,
	NG_UDBP_NODE_TYPE,
	NULL,
	ng_udbp_constructor,
	ng_udbp_rcvmsg,
	ng_udbp_rmnode,
	ng_udbp_newhook,
	NULL,
	ng_udbp_connect,
	ng_udbp_rcvdata,
	ng_udbp_disconnect,
	ng_udbp_cmdlist
};

static int udbp_setup_in_transfer	(udbp_p sc);
static void udbp_in_transfer_cb		(usbd_xfer_handle xfer,
					usbd_private_handle priv,
					usbd_status err);

static int udbp_setup_out_transfer	(udbp_p sc);
static void udbp_out_transfer_cb	(usbd_xfer_handle xfer,
					usbd_private_handle priv,
					usbd_status err);

static const struct usb_devno udbp_devs[] = {
	{ USB_DEVICE(0x0525, 0x1080) }, /* NetChip Turbo-Connect */
	{ USB_DEVICE(0x0547, 0x2720) }, /* Anchor EZLINK */
	{ USB_DEVICE(0x067b, 0x0000) }, /* Prolific PL2301 */
	{ USB_DEVICE(0x067b, 0x0001) }, /* Prolofic PL2302 */
};

static device_probe_t udbp_match;
static device_attach_t udbp_attach;
static device_detach_t udbp_detach;

static devclass_t udbp_devclass;

static kobj_method_t udbp_methods[] = {
	DEVMETHOD(device_probe, udbp_match),
	DEVMETHOD(device_attach, udbp_attach),
	DEVMETHOD(device_detach, udbp_detach),
	{0,0}
};

static driver_t udbp_driver = {
	"udbp",
	udbp_methods,
	sizeof(struct udbp_softc)
};

MODULE_DEPEND(udbp, usb, 1, 1, 1);

static int
udbp_match(device_t self)
{
	struct usb_attach_arg *uaa = device_get_ivars(self);

	if (uaa->iface == NULL)
		return (UMATCH_NONE);

	return (usb_lookup(udbp_devs, uaa->vendor, uaa->product) != NULL) ?
	    UMATCH_VENDOR_PRODUCT : UMATCH_NONE;
}

static int
udbp_attach(device_t self)
{
	struct udbp_softc *sc = device_get_softc(self);
	struct usb_attach_arg *uaa = device_get_ivars(self);
	usbd_interface_handle iface = uaa->iface;
	usb_interface_descriptor_t *id;
	usb_endpoint_descriptor_t *ed, *ed_bulkin = NULL, *ed_bulkout = NULL;
	usbd_status err;
	char devinfo[1024];
	int i;
	static int ngudbp_done_init=0;

	sc->flags |= DISCONNECTED;
	/* fetch the interface handle for the first interface */
	(void) usbd_device2interface_handle(uaa->device, 0, &iface);
	id = usbd_get_interface_descriptor(iface);
	usbd_devinfo(uaa->device, 0, devinfo);
	sc->sc_dev = self;
	device_set_desc_copy(self, devinfo);
	kprintf("%s: %s, iclass %d/%d\n", device_get_nameunit(sc->sc_dev),
	       devinfo, id->bInterfaceClass, id->bInterfaceSubClass);

	/* Find the two first bulk endpoints */
	for (i = 0 ; i < id->bNumEndpoints; i++) {
		ed = usbd_interface2endpoint_descriptor(iface, i);
		if (!ed) {
			kprintf("%s: could not read endpoint descriptor\n",
			       device_get_nameunit(sc->sc_dev));
			return ENXIO;
		}

		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN
		    && (ed->bmAttributes & UE_XFERTYPE) == UE_BULK) {
			ed_bulkin = ed;
		} else if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT
		    && (ed->bmAttributes & UE_XFERTYPE) == UE_BULK) {
		        ed_bulkout = ed;
		}

		if (ed_bulkin && ed_bulkout)	/* found all we need */
			break;
	}

	/* Verify that we goething sensible */
	if (ed_bulkin == NULL || ed_bulkout == NULL) {
		kprintf("%s: bulk-in and/or bulk-out endpoint not found\n",
			device_get_nameunit(sc->sc_dev));
		return ENXIO;
	}

	if (ed_bulkin->wMaxPacketSize[0] != ed_bulkout->wMaxPacketSize[0] ||
	   ed_bulkin->wMaxPacketSize[1] != ed_bulkout->wMaxPacketSize[1]) {
		kprintf("%s: bulk-in and bulk-out have different packet sizes %d %d %d %d\n",
			device_get_nameunit(sc->sc_dev),
		       ed_bulkin->wMaxPacketSize[0],
		       ed_bulkout->wMaxPacketSize[0],
		       ed_bulkin->wMaxPacketSize[1],
		       ed_bulkout->wMaxPacketSize[1]);
		return ENXIO;
	}

	sc->sc_bulkin = ed_bulkin->bEndpointAddress;
	sc->sc_bulkout = ed_bulkout->bEndpointAddress;

	DPRINTF(("%s: Bulk-in: 0x%02x, bulk-out 0x%02x, packet size = %d\n",
		device_get_nameunit(sc->sc_dev), sc->sc_bulkin, sc->sc_bulkout,
		ed_bulkin->wMaxPacketSize[0]));

	/* Allocate the in transfer struct */
	sc->sc_bulkin_xfer = usbd_alloc_xfer(uaa->device);
	if (!sc->sc_bulkin_xfer) {
		goto bad;
	}
	sc->sc_bulkout_xfer = usbd_alloc_xfer(uaa->device);
	if (!sc->sc_bulkout_xfer) {
		goto bad;
	}
	sc->sc_bulkin_buffer = kmalloc(UDBP_BUFFERSIZE, M_USBDEV, M_INTWAIT);
	if (!sc->sc_bulkin_buffer) {
		goto bad;
	}
	sc->sc_bulkout_buffer = kmalloc(UDBP_BUFFERSIZE, M_USBDEV, M_INTWAIT);
	if (!sc->sc_bulkout_xfer || !sc->sc_bulkout_buffer) {
		goto bad;
	}
	sc->sc_bulkin_bufferlen = UDBP_BUFFERSIZE;
	sc->sc_bulkout_bufferlen = UDBP_BUFFERSIZE;

	/* We have decided on which endpoints to use, now open the pipes */
	err = usbd_open_pipe(iface, sc->sc_bulkin,
				USBD_EXCLUSIVE_USE, &sc->sc_bulkin_pipe);
	if (err) {
		kprintf("%s: cannot open bulk-in pipe (addr %d)\n",
			device_get_nameunit(sc->sc_dev), sc->sc_bulkin);
		goto bad;
	}
	err = usbd_open_pipe(iface, sc->sc_bulkout,
				USBD_EXCLUSIVE_USE, &sc->sc_bulkout_pipe);
	if (err) {
		kprintf("%s: cannot open bulk-out pipe (addr %d)\n",
			device_get_nameunit(sc->sc_dev), sc->sc_bulkout);
		goto bad;
	}

	if (!ngudbp_done_init){
		ngudbp_done_init=1;
		if (ng_newtype(&ng_udbp_typestruct)) {
			kprintf("ngudbp install failed\n");
			goto bad;
		}
	}

	if ((err = ng_make_node_common(&ng_udbp_typestruct, &sc->node)) == 0) {
		char	nodename[128];
		ksprintf(nodename, "%s", device_get_nameunit(sc->sc_dev));
		if ((err = ng_name_node(sc->node, nodename))) {
			NG_NODE_UNREF(sc->node);
			sc->node = NULL;
			goto bad;
		} else {
			NG_NODE_SET_PRIVATE(sc->node, sc);
			sc->xmitq.ifq_maxlen = IFQ_MAXLEN;
			sc->xmitq_hipri.ifq_maxlen = IFQ_MAXLEN;
			mtx_init(&sc->xmitq.ifq_mtx, "usb_xmitq", NULL,
			    MTX_DEF);
			mtx_init(&sc->xmitq_hipri.ifq_mtx,
			    "usb_xmitq_hipri", NULL, MTX_DEF);
		}
	}
	sc->flags = NETGRAPH_INITIALISED;
	/* sc->flags &= ~DISCONNECTED; */ /* XXX */


	/* the device is now operational */


	/* schedule the first incoming xfer */
	err = udbp_setup_in_transfer(sc);
	if (err) {
		goto bad;
	}
	return 0;
bad:
#if 0 /* probably done in udbp_detach() */
		if (sc->sc_bulkout_buffer) {
			FREE(sc->sc_bulkout_buffer, M_USBDEV);
		}
		if (sc->sc_bulkin_buffer) {
			FREE(sc->sc_bulkin_buffer, M_USBDEV);
		}
		if (sc->sc_bulkout_xfer) {
			usbd_free_xfer(sc->sc_bulkout_xfer);
		}
		if (sc->sc_bulkin_xfer) {
			usbd_free_xfer(sc->sc_bulkin_xfer);
		}
#endif
		udbp_detach(self);
		return ENXIO;
}


static int
udbp_detach(device_t self)
{
	struct udbp_softc *sc = device_get_softc(self);

	sc->flags |= DISCONNECTED;

	DPRINTF(("%s: disconnected\n", device_get_nameunit(self)));

	if (sc->sc_bulkin_pipe) {
		usbd_abort_pipe(sc->sc_bulkin_pipe);
		usbd_close_pipe(sc->sc_bulkin_pipe);
	}
	if (sc->sc_bulkout_pipe) {
		usbd_abort_pipe(sc->sc_bulkout_pipe);
		usbd_close_pipe(sc->sc_bulkout_pipe);
	}

	if (sc->flags & NETGRAPH_INITIALISED) {
		ng_rmnode_self(sc->node);
		NG_NODE_SET_PRIVATE(sc->node, NULL);
		NG_NODE_UNREF(sc->node);
		sc->node = NULL;	/* Paranoid */
	}

	if (sc->sc_bulkin_xfer)
		usbd_free_xfer(sc->sc_bulkin_xfer);
	if (sc->sc_bulkout_xfer)
		usbd_free_xfer(sc->sc_bulkout_xfer);

	if (sc->sc_bulkin_buffer)
		kfree(sc->sc_bulkin_buffer, M_USBDEV);
	if (sc->sc_bulkout_buffer)
		kfree(sc->sc_bulkout_buffer, M_USBDEV);
	return 0;
}


static int
udbp_setup_in_transfer(udbp_p sc)
{
	void *priv = sc;	/* XXX this should probably be some pointer to
				 * struct describing the transfer (mbuf?)
				 * See also below.
				 */
	usbd_status err;

	/* XXX
	 * How should we arrange for 2 extra bytes at the start of the
	 * packet?
	 */

	/* Initialise a USB transfer and then schedule it */

	(void) usbd_setup_xfer( sc->sc_bulkin_xfer,
				sc->sc_bulkin_pipe,
				priv,
				sc->sc_bulkin_buffer,
				sc->sc_bulkin_bufferlen,
				USBD_SHORT_XFER_OK,
				USBD_NO_TIMEOUT,
				udbp_in_transfer_cb);

	err = usbd_transfer(sc->sc_bulkin_xfer);
	if (err && err != USBD_IN_PROGRESS) {
		DPRINTF(("%s: failed to setup in-transfer, %s\n",
			device_get_nameunit(sc->sc_dev), usbd_errstr(err)));
		return(err);
	}

	return (USBD_NORMAL_COMPLETION);
}

static void
udbp_in_transfer_cb(usbd_xfer_handle xfer, usbd_private_handle priv,
			usbd_status err)
{
	udbp_p 		sc = priv;		/* XXX see priv above */
	int		s;
	int		len;
	struct		mbuf *m;

	if (err) {
		if (err != USBD_CANCELLED) {
			DPRINTF(("%s: bulk-out transfer failed: %s\n",
				device_get_nameunit(sc->sc_dev), usbd_errstr(err)));
		} else {
			/* USBD_CANCELLED happens at unload of the driver */
			return;
		}

		/* Transfer has failed, packet is not received */
	} else {

		len = xfer->actlen;

		crit_enter();
		if (sc->hook) {
			/* get packet from device and send on */
			m = m_devget(sc->sc_bulkin_buffer, len, 0, NULL, NULL);
	    		NG_SEND_DATA_ONLY(err, sc->hook, m);
		}
		crit_exit();

	}
	/* schedule the next in transfer */
	udbp_setup_in_transfer(sc);
}


static int
udbp_setup_out_transfer(udbp_p sc)
{
	void *priv = sc;	/* XXX this should probably be some pointer to
				 * struct describing the transfer (mbuf?)
				 * See also below.
				 */
	int pktlen;
	usbd_status err;
	struct mbuf *m;

	crit_enter();
	if (sc->flags & OUT_BUSY)
		panic("out transfer already in use, we should add queuing");
	sc->flags |= OUT_BUSY;
	crit_exit();
	crit_enter();
	IF_DEQUEUE(&sc->xmitq_hipri, m);
	if (m == NULL) {
		IF_DEQUEUE(&sc->xmitq, m);
	}
	crit_exit();

	if (!m) {
		sc->flags &= ~OUT_BUSY;
		return (USBD_NORMAL_COMPLETION);
	}

	pktlen = m->m_pkthdr.len;
	if (pktlen > sc->sc_bulkout_bufferlen) {
		kprintf("%s: Packet too large, %d > %d\n",
			device_get_nameunit(sc->sc_dev), pktlen,
			sc->sc_bulkout_bufferlen);
		return (USBD_IOERROR);
	}

	m_copydata(m, 0, pktlen, sc->sc_bulkout_buffer);
	m_freem(m);

	/* Initialise a USB transfer and then schedule it */

	(void) usbd_setup_xfer( sc->sc_bulkout_xfer,
				sc->sc_bulkout_pipe,
				priv,
				sc->sc_bulkout_buffer,
				pktlen,
				USBD_SHORT_XFER_OK,
				UDBP_TIMEOUT,
				udbp_out_transfer_cb);

	err = usbd_transfer(sc->sc_bulkout_xfer);
	if (err && err != USBD_IN_PROGRESS) {
		DPRINTF(("%s: failed to setup out-transfer, %s\n",
			device_get_nameunit(sc->sc_dev), usbd_errstr(err)));
		return(err);
	}

	return (USBD_NORMAL_COMPLETION);
}

static void
udbp_out_transfer_cb(usbd_xfer_handle xfer, usbd_private_handle priv,
			usbd_status err)
{
	udbp_p sc = priv;		/* XXX see priv above */

	if (err) {
		DPRINTF(("%s: bulk-out transfer failed: %s\n",
			device_get_nameunit(sc->sc_dev), usbd_errstr(err)));
		/* Transfer has failed, packet is not transmitted */
		/* XXX Invalidate packet */
		return;
	}

	/* packet has been transmitted */

	crit_enter();
	sc->flags &= ~OUT_BUSY;
	udbp_setup_out_transfer(sc);
	crit_exit();
}

DRIVER_MODULE(udbp, uhub, udbp_driver, udbp_devclass, usbd_driver_load, 0);
MODULE_DEPEND(udbp, netgraph, NG_ABI_VERSION, NG_ABI_VERSION, NG_ABI_VERSION);


/***********************************************************************
 * Start of Netgraph methods
 **********************************************************************/

/*
 * If this is a device node so this work is done in the attach()
 * routine and the constructor will return EINVAL as you should not be able
 * to create nodes that depend on hardware (unless you can add the hardware :)
 */
static int
ng_udbp_constructor(node_p node)
{
	return (EINVAL);
}

/*
 * Give our ok for a hook to be added...
 * If we are not running this might kick a device into life.
 * Possibly decode information out of the hook name.
 * Add the hook's private info to the hook structure.
 * (if we had some). In this example, we assume that there is a
 * an array of structs, called 'channel' in the private info,
 * one for each active channel. The private
 * pointer of each hook points to the appropriate UDBP_hookinfo struct
 * so that the source of an input packet is easily identified.
 */
static int
ng_udbp_newhook(node_p node, hook_p hook, const char *name)
{
	const udbp_p sc = NG_NODE_PRIVATE(node);

#if 0
	/* Possibly start up the device if it's not already going */
	if ((sc->flags & SCF_RUNNING) == 0) {
		ng_udbp_start_hardware(sc);
	}
#endif

	if (strcmp(name, NG_UDBP_HOOK_NAME) == 0) {
		sc->hook = hook;
		NG_HOOK_SET_PRIVATE(hook, NULL);
	} else {
		return (EINVAL);	/* not a hook we know about */
	}
	return(0);
}

/*
 * Get a netgraph control message.
 * Check it is one we understand. If needed, send a response.
 * We could save the address for an async action later, but don't here.
 * Always free the message.
 * The response should be in a malloc'd region that the caller can 'free'.
 * A response is not required.
 * Theoretically you could respond defferently to old message types if
 * the cookie in the header didn't match what we consider to be current
 * (so that old userland programs could continue to work).
 */
static int
ng_udbp_rcvmsg(node_p node, item_p item, hook_p lasthook)
{
	const udbp_p sc = NG_NODE_PRIVATE(node);
	struct ng_mesg *resp = NULL;
	int error = 0;
	struct ng_mesg *msg;

	NGI_GET_MSG(item, msg);
	/* Deal with message according to cookie and command */
	switch (msg->header.typecookie) {
	case NGM_UDBP_COOKIE:
		switch (msg->header.cmd) {
		case NGM_UDBP_GET_STATUS:
		    {
			struct ngudbpstat *stats;

			NG_MKRESPONSE(resp, msg, sizeof(*stats), M_NOWAIT);
			if (!resp) {
				error = ENOMEM;
				break;
			}
			stats = (struct ngudbpstat *) resp->data;
			stats->packets_in = sc->packets_in;
			stats->packets_out = sc->packets_out;
			break;
		    }
		case NGM_UDBP_SET_FLAG:
			if (msg->header.arglen != sizeof(u_int32_t)) {
				error = EINVAL;
				break;
			}
			sc->flags = *((u_int32_t *) msg->data);
			break;
		default:
			error = EINVAL;		/* unknown command */
			break;
		}
		break;
	default:
		error = EINVAL;			/* unknown cookie type */
		break;
	}

	/* Take care of synchronous response, if any */
	NG_RESPOND_MSG(error, node, item, resp);
	NG_FREE_MSG(msg);
	return(error);
}

/*
 * Accept data from the hook and queue it for output.
 */
static int
ng_udbp_rcvdata(hook_p hook, item_p item)
{
	const udbp_p sc = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	int error;
	struct ifqueue	*xmitq_p;
	struct mbuf *m;
	meta_p meta;

	NGI_GET_M(item, m);
	NGI_GET_META(item, meta);
	NG_FREE_ITEM(item);
	/*
	 * Now queue the data for when it can be sent
	 */
	if (meta && meta->priority > 0) {
		xmitq_p = (&sc->xmitq_hipri);
	} else {
		xmitq_p = (&sc->xmitq);
	}
	crit_enter();
	if (IF_QFULL(xmitq_p)) {
		IF_DROP(xmitq_p);
		crit_exit();
		error = ENOBUFS;
		goto bad;
	}
	IF_ENQUEUE(xmitq_p, m);
	if (!(sc->flags & OUT_BUSY))
		udbp_setup_out_transfer(sc);
	crit_exit();
	return (0);

bad:	/*
         * It was an error case.
	 * check if we need to free the mbuf, and then return the error
	 */
	NG_FREE_M(m);
	NG_FREE_META(meta);
	return (error);
}

/*
 * Do local shutdown processing..
 * We are a persistant device, we refuse to go away, and
 * only remove our links and reset ourself.
 */
static int
ng_udbp_rmnode(node_p node)
{
	const udbp_p sc = NG_NODE_PRIVATE(node);
	int err;

	if (sc->flags & DISCONNECTED) {
		/*
		 * WE are really going away.. hardware must have gone.
		 * Assume that the hardware drive part will clear up the
		 * sc, in fact it may already have done so..
		 * In which case we may have just segfaulted..XXX
		 */
		return (0);
	}

	/* stolen from attach routine */
	/* Drain the queues */
	IF_DRAIN(&sc->xmitq_hipri);
	IF_DRAIN(&sc->xmitq);

	sc->packets_in = 0;		/* reset stats */
	sc->packets_out = 0;
	NG_NODE_UNREF(node);			/* forget it ever existed */

	if ((err = ng_make_node_common(&ng_udbp_typestruct, &sc->node)) == 0) {
		char	nodename[128];
		ksprintf(nodename, "%s", device_get_nameunit(sc->sc_dev));
		if ((err = ng_name_node(sc->node, nodename))) {
			NG_NODE_UNREF(sc->node); /* out damned spot! */
			sc->flags &= ~NETGRAPH_INITIALISED;
			sc->node = NULL;
		} else {
			NG_NODE_SET_PRIVATE(sc->node, sc);
		}
	}
	return (err);
}

/*
 * This is called once we've already connected a new hook to the other node.
 * It gives us a chance to balk at the last minute.
 */
static int
ng_udbp_connect(hook_p hook)
{
	/* probably not at splnet, force outward queueing */
	NG_HOOK_FORCE_QUEUE(NG_HOOK_PEER(hook));
	/* be really amiable and just say "YUP that's OK by me! " */
	return (0);
}

/*
 * Dook disconnection
 *
 * For this type, removal of the last link destroys the node
 */
static int
ng_udbp_disconnect(hook_p hook)
{
	const udbp_p sc = NG_NODE_PRIVATE(NG_HOOK_NODE(hook));
	sc->hook = NULL;

	if ((NG_NODE_NUMHOOKS(NG_HOOK_NODE(hook)) == 0)
	&& (NG_NODE_IS_VALID(NG_HOOK_NODE(hook))))
		ng_rmnode_self(NG_HOOK_NODE(hook));
	return (0);
}

