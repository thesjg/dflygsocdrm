/*-
 * (MPSAFE)
 *
 * Copyright (c) 2001 Brian Somers <brian@Awfulhak.org>
 *   based on work by Slawa Olhovchenkov
 *                    John Prince <johnp@knight-trosoft.com>
 *                    Eric Hernes
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
 * $FreeBSD: src/sys/dev/digi/digi.c,v 1.36 2003/09/26 09:05:57 phk Exp $
 */

/*-
 * TODO:
 *	Figure out what the con bios stuff is supposed to do
 *	Test with *LOTS* more cards - I only have a PCI8r and an ISA Xem.
 */

#include "opt_compat.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/conf.h>
#include <sys/linker.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/tty.h>
#include <sys/syslog.h>
#include <sys/fcntl.h>
#include <sys/bus.h>
#include <sys/bus.h>
#include <sys/thread2.h>

#include <vm/vm.h>
#include <vm/pmap.h>

#include <dev/serial/digi/digiio.h>
#include <dev/serial/digi/digireg.h>
#include <dev/serial/digi/digi.h>
#include <dev/serial/digi/digi_pci.h>
#include <dev/serial/digi/digi_bios.h>

#define	CTRL_DEV		0x800000
#define	CALLOUT_MASK		0x400000
#define	CONTROL_INIT_STATE	0x100000
#define	CONTROL_LOCK_STATE	0x200000
#define	CONTROL_MASK		(CTRL_DEV|CONTROL_INIT_STATE|CONTROL_LOCK_STATE)
#define UNIT_MASK		0x030000
#define PORT_MASK		0x0000FF
#define	DEV_TO_UNIT(dev)	(MINOR_TO_UNIT(minor(dev)))
#define	MINOR_MAGIC_MASK	(CALLOUT_MASK | CONTROL_MASK)
#define	MINOR_TO_UNIT(mynor)	(((mynor) & UNIT_MASK)>>16)
#define MINOR_TO_PORT(mynor)	((mynor) & PORT_MASK)

static d_open_t		digiopen;
static d_close_t	digiclose;
static d_read_t		digiread;
static d_write_t	digiwrite;
static d_ioctl_t	digiioctl;

static void	digistop(struct tty *tp, int rw);
static int	digimctl(struct digi_p *port, int bits, int how);
static void	digi_poll(void *ptr);
static void	digi_freedata(struct digi_softc *);
static void	fepcmd(struct digi_p *port, int cmd, int op, int ncmds);
static void	digistart(struct tty *tp);
static int	digiparam(struct tty *tp, struct termios *t);
static void	digihardclose(struct digi_p *port);
static void	digi_intr(void *);
static int	digi_init(struct digi_softc *_sc);
static int	digi_loaddata(struct digi_softc *);
static int	digi_inuse(struct digi_softc *);
static void	digi_free_state(struct digi_softc *);

#define	fepcmd_b(port, cmd, op1, op2, ncmds) \
	fepcmd(port, cmd, (op2 << 8) | op1, ncmds)
#define	fepcmd_w	fepcmd


static speed_t digidefaultrate = TTYDEF_SPEED;

struct con_bios {
	struct con_bios *next;
	u_char *bios;
	size_t size;
};

static struct con_bios *con_bios_list;
devclass_t	 digi_devclass;
unsigned 	 digi_debug = 0;

static struct speedtab digispeedtab[] = {
	{ 0,		0},			/* old (sysV-like) Bx codes */
	{ 50,		1},
	{ 75,		2},
	{ 110,		3},
	{ 134,		4},
	{ 150,		5},
	{ 200,		6},
	{ 300,		7},
	{ 600,		8},
	{ 1200,		9},
	{ 1800,		10},
	{ 2400,		11},
	{ 4800,		12},
	{ 9600,		13},
	{ 19200,	14},
	{ 38400,	15},
	{ 57600,	(02000 | 1)},
	{ 76800,	(02000 | 2)},
	{ 115200,	(02000 | 3)},
	{ 230400,	(02000 | 6)},
	{ -1,		-1}
};

const struct digi_control_signals digi_xixe_signals = {
	0x02, 0x08, 0x10, 0x20, 0x40, 0x80
};

const struct digi_control_signals digi_normal_signals = {
	0x02, 0x80, 0x20, 0x10, 0x40, 0x01
};

static struct dev_ops digi_ops = {
	{ "dgm", 0, D_TTY },
	.d_open =	digiopen,
	.d_close =	digiclose,
	.d_read =	digiread,
	.d_write =	digiwrite,
	.d_ioctl =	digiioctl,
	.d_kqfilter =	ttykqfilter,
	.d_revoke =	ttyrevoke
};

static void
digi_poll(void *ptr)
{
	struct digi_softc *sc;

	sc = (struct digi_softc *)ptr;
	callout_init_mp(&sc->callout);
	digi_intr(sc);
	callout_reset(&sc->callout, (hz >= 200) ? hz / 100 : 1, digi_poll, sc);
}

static void
digi_int_test(void *v)
{
	struct digi_softc *sc = v;

	callout_init_mp(&sc->inttest);
#ifdef DIGI_INTERRUPT
	if (sc->intr_timestamp.tv_sec || sc->intr_timestamp.tv_usec) {
		/* interrupt OK! */
		return;
	}
	log(LOG_ERR, "digi%d: Interrupt didn't work, use polled mode\n", unit);
#endif
	callout_reset(&sc->callout, (hz >= 200) ? hz / 100 : 1, digi_poll, sc);
}

static void
digi_freedata(struct digi_softc *sc)
{
	if (sc->fep.data != NULL) {
		kfree(sc->fep.data, M_TTYS);
		sc->fep.data = NULL;
	}
	if (sc->link.data != NULL) {
		kfree(sc->link.data, M_TTYS);
		sc->link.data = NULL;
	}
	if (sc->bios.data != NULL) {
		kfree(sc->bios.data, M_TTYS);
		sc->bios.data = NULL;
	}
}

static int
digi_bcopy(const void *vfrom, void *vto, size_t sz)
{
	volatile const char *from = (volatile const char *)vfrom;
	volatile char *to = (volatile char *)vto;
	size_t i;

	for (i = 0; i < sz; i++)
		*to++ = *from++;

	from = (const volatile char *)vfrom;
	to = (volatile char *)vto;
	for (i = 0; i < sz; i++)
		if (*to++ != *from++)
			return (0);
	return (1);
}

void
digi_delay(struct digi_softc *sc, const char *txt, u_long timo)
{
	if (cold)
		DELAY(timo * 1000000 / hz);
	else
		tsleep(sc, PCATCH, txt, timo);
}

/*
 * NOTE: Must be called with tty_token held
 */
static int
digi_init(struct digi_softc *sc)
{
	int i, cnt, resp;
	u_char *ptr;
	int lowwater;
	struct digi_p *port;
	volatile struct board_chan *bc;

	ASSERT_LWKT_TOKEN_HELD(&tty_token);
	ptr = NULL;

	if (sc->status == DIGI_STATUS_DISABLED) {
		log(LOG_ERR, "digi%d: Cannot init a disabled card\n",
		    sc->res.unit);
		return (EIO);
	}
	if (sc->bios.data == NULL) {
		log(LOG_ERR, "digi%d: Cannot init without BIOS\n",
		    sc->res.unit);
		return (EIO);
	}
#if 0
	if (sc->link.data == NULL && sc->model >= PCCX) {
		log(LOG_ERR, "digi%d: Cannot init without link info\n",
		    sc->res.unit);
		return (EIO);
	}
#endif
	if (sc->fep.data == NULL) {
		log(LOG_ERR, "digi%d: Cannot init without fep code\n",
		    sc->res.unit);
		return (EIO);
	}
	sc->status = DIGI_STATUS_NOTINIT;

	if (sc->numports) {
		/*
		 * We're re-initialising - maybe because someone's attached
		 * another port module.  For now, we just re-initialise
		 * everything.
		 */
		if (digi_inuse(sc))
			return (EBUSY);

		digi_free_state(sc);
	}

	ptr = sc->setwin(sc, MISCGLOBAL);
	for (i = 0; i < 16; i += 2)
		vW(ptr + i) = 0;

	switch (sc->model) {
	case PCXEVE:
		outb(sc->wport, 0xff);		/* window 7 */
		ptr = sc->vmem + (BIOSCODE & 0x1fff);

		if (!digi_bcopy(sc->bios.data, ptr, sc->bios.size)) {
			device_printf(sc->dev, "BIOS upload failed\n");
			return (EIO);
		}

		outb(sc->port, FEPCLR);
		break;

	case PCXE:
	case PCXI:
	case PCCX:
		ptr = sc->setwin(sc, BIOSCODE + ((0xf000 - sc->mem_seg) << 4));
		if (!digi_bcopy(sc->bios.data, ptr, sc->bios.size)) {
			device_printf(sc->dev, "BIOS upload failed\n");
			return (EIO);
		}
		break;

	case PCXEM:
	case PCIEPCX:
	case PCIXR:
		if (sc->pcibus)
			PCIPORT = FEPRST;
		else
			outb(sc->port, FEPRST | FEPMEM);

		for (i = 0; ((sc->pcibus ? PCIPORT : inb(sc->port)) &
		    FEPMASK) != FEPRST; i++) {
			if (i > hz) {
				log(LOG_ERR, "digi%d: %s init reset failed\n",
				    sc->res.unit, sc->name);
				return (EIO);
			}
			digi_delay(sc, "digiinit0", 5);
		}
		DLOG(DIGIDB_INIT, (sc->dev, "Got init reset after %d us\n", i));

		/* Now upload the BIOS */
		cnt = (sc->bios.size < sc->win_size - BIOSOFFSET) ?
		    sc->bios.size : sc->win_size - BIOSOFFSET;

		ptr = sc->setwin(sc, BIOSOFFSET);
		if (!digi_bcopy(sc->bios.data, ptr, cnt)) {
			device_printf(sc->dev, "BIOS upload (1) failed\n");
			return (EIO);
		}

		if (cnt != sc->bios.size) {
			/* and the second part */
			ptr = sc->setwin(sc, sc->win_size);
			if (!digi_bcopy(sc->bios.data + cnt, ptr,
			    sc->bios.size - cnt)) {
				device_printf(sc->dev, "BIOS upload failed\n");
				return (EIO);
			}
		}

		ptr = sc->setwin(sc, 0);
		vW(ptr + 0) = 0x0401;
		vW(ptr + 2) = 0x0bf0;
		vW(ptr + 4) = 0x0000;
		vW(ptr + 6) = 0x0000;

		break;
	}

	DLOG(DIGIDB_INIT, (sc->dev, "BIOS uploaded\n"));

	ptr = sc->setwin(sc, MISCGLOBAL);
	W(ptr) = 0;

	if (sc->pcibus) {
		PCIPORT = FEPCLR;
		resp = FEPRST;
	} else if (sc->model == PCXEVE) {
		outb(sc->port, FEPCLR);
		resp = FEPRST;
	} else {
		outb(sc->port, FEPCLR | FEPMEM);
		resp = FEPRST | FEPMEM;
	}

	for (i = 0; ((sc->pcibus ? PCIPORT : inb(sc->port)) & FEPMASK)
	    == resp; i++) {
		if (i > hz) {
			log(LOG_ERR, "digi%d: BIOS start failed\n",
			    sc->res.unit);
			return (EIO);
		}
		digi_delay(sc, "digibios0", 5);
	}

	DLOG(DIGIDB_INIT, (sc->dev, "BIOS started after %d us\n", i));

	for (i = 0; vW(ptr) != *(u_short *)"GD"; i++) {
		if (i > 2*hz) {
			log(LOG_ERR, "digi%d: BIOS boot failed "
			    "(0x%02x != 0x%02x)\n",
			    sc->res.unit, vW(ptr), *(u_short *)"GD");
			return (EIO);
		}
		digi_delay(sc, "digibios1", 5);
	}

	DLOG(DIGIDB_INIT, (sc->dev, "BIOS booted after %d iterations\n", i));

	if (sc->link.data != NULL) {
		DLOG(DIGIDB_INIT, (sc->dev, "Loading link data\n"));
		ptr = sc->setwin(sc, 0xcd0);
		digi_bcopy(sc->link.data, ptr, 21);	/* XXX 21 ? */
	}

	/* load FEP/OS */

	switch (sc->model) {
	case PCXE:
	case PCXEVE:
	case PCXI:
		ptr = sc->setwin(sc, sc->model == PCXI ? 0x2000 : 0x0);
		digi_bcopy(sc->fep.data, ptr, sc->fep.size);

		/* A BIOS request to move our data to 0x2000 */
		ptr = sc->setwin(sc, MBOX);
		vW(ptr + 0) = 2;
		vW(ptr + 2) = sc->mem_seg + FEPCODESEG;
		vW(ptr + 4) = 0;
		vW(ptr + 6) = FEPCODESEG;
		vW(ptr + 8) = 0;
		vW(ptr + 10) = sc->fep.size;

		/* Run the BIOS request */
		outb(sc->port, FEPREQ | FEPMEM);
		outb(sc->port, FEPCLR | FEPMEM);

		for (i = 0; W(ptr); i++) {
			if (i > hz) {
				log(LOG_ERR, "digi%d: FEP/OS move failed\n",
				    sc->res.unit);
				sc->hidewin(sc);
				return (EIO);
			}
			digi_delay(sc, "digifep0", 5);
		}
		DLOG(DIGIDB_INIT,
		    (sc->dev, "FEP/OS moved after %d iterations\n", i));

		/* Clear the confirm word */
		ptr = sc->setwin(sc, FEPSTAT);
		vW(ptr + 0) = 0;

		/* A BIOS request to execute the FEP/OS */
		ptr = sc->setwin(sc, MBOX);
		vW(ptr + 0) = 0x01;
		vW(ptr + 2) = FEPCODESEG;
		vW(ptr + 4) = 0x04;

		/* Run the BIOS request */
		outb(sc->port, FEPREQ);
		outb(sc->port, FEPCLR);

		ptr = sc->setwin(sc, FEPSTAT);

		break;

	case PCXEM:
	case PCIEPCX:
	case PCIXR:
		DLOG(DIGIDB_INIT, (sc->dev, "Loading FEP/OS\n"));

		cnt = (sc->fep.size < sc->win_size - BIOSOFFSET) ?
		    sc->fep.size : sc->win_size - BIOSOFFSET;

		ptr = sc->setwin(sc, BIOSOFFSET);
		digi_bcopy(sc->fep.data, ptr, cnt);

		if (cnt != sc->fep.size) {
			ptr = sc->setwin(sc, BIOSOFFSET + cnt);
			digi_bcopy(sc->fep.data + cnt, ptr,
			    sc->fep.size - cnt);
		}

		DLOG(DIGIDB_INIT, (sc->dev, "FEP/OS loaded\n"));

		ptr = sc->setwin(sc, 0xc30);
		W(ptr + 4) = 0x1004;
		W(ptr + 6) = 0xbfc0;
		W(ptr + 0) = 0x03;
		W(ptr + 2) = 0x00;

		/* Clear the confirm word */
		ptr = sc->setwin(sc, FEPSTAT);
		W(ptr + 0) = 0;

		if (sc->port)
			outb(sc->port, 0);		/* XXX necessary ? */

		break;

	case PCCX:
		ptr = sc->setwin(sc, 0xd000);
		digi_bcopy(sc->fep.data, ptr, sc->fep.size);

		/* A BIOS request to execute the FEP/OS */
		ptr = sc->setwin(sc, 0xc40);
		W(ptr + 0) = 1;
		W(ptr + 2) = FEPCODE >> 4;
		W(ptr + 4) = 4;

		/* Clear the confirm word */
		ptr = sc->setwin(sc, FEPSTAT);
		W(ptr + 0) = 0;

		/* Run the BIOS request */
		outb(sc->port, FEPREQ | FEPMEM); /* send interrupt to BIOS */
		outb(sc->port, FEPCLR | FEPMEM);
		break;
	}

	/* Now wait 'till the FEP/OS has booted */
	for (i = 0; vW(ptr) != *(u_short *)"OS"; i++) {
		if (i > 2*hz) {
			log(LOG_ERR, "digi%d: FEP/OS start failed "
			    "(0x%02x != 0x%02x)\n",
			    sc->res.unit, vW(ptr), *(u_short *)"OS");
			sc->hidewin(sc);
			return (EIO);
		}
		digi_delay(sc, "digifep1", 5);
	}

	DLOG(DIGIDB_INIT, (sc->dev, "FEP/OS started after %d iterations\n", i));

	if (sc->model >= PCXEM) {
		ptr = sc->setwin(sc, 0xe04);
		vW(ptr) = 2;
		ptr = sc->setwin(sc, 0xc02);
		sc->numports = vW(ptr);
	} else {
		ptr = sc->setwin(sc, 0xc22);
		sc->numports = vW(ptr);
	}

	if (sc->numports == 0) {
		device_printf(sc->dev, "%s, 0 ports found\n", sc->name);
		sc->hidewin(sc);
		return (0);
	}

	if (sc->numports > 256) {
		/* Our minor numbering scheme is broken for more than 256 */
		device_printf(sc->dev, "%s, 256 ports (%d ports found)\n",
		    sc->name, sc->numports);
		sc->numports = 256;
	} else
		device_printf(sc->dev, "%s, %d ports found\n", sc->name,
		    sc->numports);

	if (sc->ports)
		kfree(sc->ports, M_TTYS);
	sc->ports = kmalloc(sizeof(struct digi_p) * sc->numports,
	    M_TTYS, M_WAITOK | M_ZERO);

	if (sc->ttys)
		kfree(sc->ttys, M_TTYS);
	sc->ttys = kmalloc(sizeof(struct tty) * sc->numports,
	    M_TTYS, M_WAITOK | M_ZERO);

	/*
	 * XXX Should read port 0xc90 for an array of 2byte values, 1 per
	 * port.  If the value is 0, the port is broken....
	 */

	ptr = sc->setwin(sc, 0);

	/* We should now init per-port structures */
	bc = (volatile struct board_chan *)(ptr + CHANSTRUCT);
	sc->gdata = (volatile struct global_data *)(ptr + FEP_GLOBAL);

	sc->memcmd = ptr + sc->gdata->cstart;
	sc->memevent = ptr + sc->gdata->istart;

	for (i = 0; i < sc->numports; i++, bc++) {
		port = sc->ports + i;
		port->pnum = i;
		port->sc = sc;
		port->status = ENABLED;
		port->tp = sc->ttys + i;
		port->bc = bc;

		if (sc->model == PCXEVE) {
			port->txbuf = ptr +
			    (((bc->tseg - sc->mem_seg) << 4) & 0x1fff);
			port->rxbuf = ptr +
			    (((bc->rseg - sc->mem_seg) << 4) & 0x1fff);
			port->txwin = FEPWIN | ((bc->tseg - sc->mem_seg) >> 9);
			port->rxwin = FEPWIN | ((bc->rseg - sc->mem_seg) >> 9);
		} else if (sc->model == PCXI || sc->model == PCXE) {
			port->txbuf = ptr + ((bc->tseg - sc->mem_seg) << 4);
			port->rxbuf = ptr + ((bc->rseg - sc->mem_seg) << 4);
			port->txwin = port->rxwin = 0;
		} else {
			port->txbuf = ptr +
			    (((bc->tseg - sc->mem_seg) << 4) % sc->win_size);
			port->rxbuf = ptr +
			    (((bc->rseg - sc->mem_seg) << 4) % sc->win_size);
			port->txwin = FEPWIN |
			    (((bc->tseg - sc->mem_seg) << 4) / sc->win_size);
			port->rxwin = FEPWIN |
			    (((bc->rseg - sc->mem_seg) << 4) / sc->win_size);
		}
		port->txbufsize = bc->tmax + 1;
		port->rxbufsize = bc->rmax + 1;

		lowwater = port->txbufsize >> 2;
		if (lowwater > 1024)
			lowwater = 1024;
		sc->setwin(sc, 0);
		fepcmd_w(port, STXLWATER, lowwater, 10);
		fepcmd_w(port, SRXLWATER, port->rxbufsize >> 2, 10);
		fepcmd_w(port, SRXHWATER, (3 * port->rxbufsize) >> 2, 10);

		bc->edelay = 100;
		port->dtr_wait = 3 * hz;

		/*
		 * We don't use all the flags from <sys/ttydefaults.h> since
		 * they are only relevant for logins.  It's important to have
		 * echo off initially so that the line doesn't start blathering
		 * before the echo flag can be turned off.
		 */
		port->it_in.c_iflag = 0;
		port->it_in.c_oflag = 0;
		port->it_in.c_cflag = TTYDEF_CFLAG;
		port->it_in.c_lflag = 0;
		termioschars(&port->it_in);
		port->it_in.c_ispeed = port->it_in.c_ospeed = digidefaultrate;
		port->it_out = port->it_in;
		port->send_ring = 1;	/* Default action on signal RI */

		port->dev[0] = make_dev(&digi_ops, (sc->res.unit << 16) + i,
		    UID_ROOT, GID_WHEEL, 0600, "ttyD%d.%d", sc->res.unit, i);
		port->dev[1] = make_dev(&digi_ops, ((sc->res.unit << 16) + i) |
		    CONTROL_INIT_STATE, UID_ROOT, GID_WHEEL,
		    0600, "ttyiD%d.%d", sc->res.unit, i);
		port->dev[2] = make_dev(&digi_ops, ((sc->res.unit << 16) + i) |
		    CONTROL_LOCK_STATE, UID_ROOT, GID_WHEEL,
		    0600, "ttylD%d.%d", sc->res.unit, i);
		port->dev[3] = make_dev(&digi_ops, ((sc->res.unit << 16) + i) |
		    CALLOUT_MASK, UID_UUCP, GID_DIALER,
		    0660, "cuaD%d.%d", sc->res.unit, i);
		port->dev[4] = make_dev(&digi_ops, ((sc->res.unit << 16) + i) |
		    CALLOUT_MASK | CONTROL_INIT_STATE, UID_UUCP, GID_DIALER,
		    0660, "cuaiD%d.%d", sc->res.unit, i);
		port->dev[5] = make_dev(&digi_ops, ((sc->res.unit << 16) + i) |
		    CALLOUT_MASK | CONTROL_LOCK_STATE, UID_UUCP, GID_DIALER,
		    0660, "cualD%d.%d", sc->res.unit, i);
	}

	sc->hidewin(sc);
	callout_reset(&sc->inttest, hz, digi_int_test, sc);
	/* fepcmd_w(&sc->ports[0], 0xff, 0, 0); */
	sc->status = DIGI_STATUS_ENABLED;

	return (0);
}

/*
 * NOTE: Must be called with tty_token held
 */
static int
digimctl(struct digi_p *port, int bits, int how)
{
	int mstat;

	ASSERT_LWKT_TOKEN_HELD(&tty_token);
	if (how == DMGET) {
		port->sc->setwin(port->sc, 0);
		mstat = port->bc->mstat;
		port->sc->hidewin(port->sc);
		bits = TIOCM_LE;
		if (mstat & port->sc->csigs->rts)
			bits |= TIOCM_RTS;
		if (mstat & port->cd)
			bits |= TIOCM_CD;
		if (mstat & port->dsr)
			bits |= TIOCM_DSR;
		if (mstat & port->sc->csigs->cts)
			bits |= TIOCM_CTS;
		if (mstat & port->sc->csigs->ri)
			bits |= TIOCM_RI;
		if (mstat & port->sc->csigs->dtr)
			bits |= TIOCM_DTR;
		return (bits);
	}

	/* Only DTR and RTS may be set */
	mstat = 0;
	if (bits & TIOCM_DTR)
		mstat |= port->sc->csigs->dtr;
	if (bits & TIOCM_RTS)
		mstat |= port->sc->csigs->rts;

	switch (how) {
	case DMSET:
		fepcmd_b(port, SETMODEM, mstat, ~mstat, 0);
		break;
	case DMBIS:
		fepcmd_b(port, SETMODEM, mstat, 0, 0);
		break;
	case DMBIC:
		fepcmd_b(port, SETMODEM, 0, mstat, 0);
		break;
	}

	return (0);
}

static void
digi_disc_optim(struct tty *tp, struct termios *t, struct digi_p *port)
{
	lwkt_gettoken(&tty_token);
	if (!(t->c_iflag & (ICRNL | IGNCR | IMAXBEL | INLCR | ISTRIP)) &&
	    (!(t->c_iflag & BRKINT) || (t->c_iflag & IGNBRK)) &&
	    (!(t->c_iflag & PARMRK) ||
	    (t->c_iflag & (IGNPAR | IGNBRK)) == (IGNPAR | IGNBRK)) &&
	    !(t->c_lflag & (ECHO | ICANON | IEXTEN | ISIG | PENDIN)) &&
	    linesw[tp->t_line].l_rint == ttyinput)
		tp->t_state |= TS_CAN_BYPASS_L_RINT;
	else
		tp->t_state &= ~TS_CAN_BYPASS_L_RINT;
	lwkt_reltoken(&tty_token);
}

static int
digiopen(struct dev_open_args *ap)
{
	cdev_t dev = ap->a_head.a_dev;
	struct digi_softc *sc;
	struct tty *tp;
	int unit;
	int pnum;
	struct digi_p *port;
	int error, mynor;
	volatile struct board_chan *bc;

	error = 0;
	mynor = minor(dev);
	unit = MINOR_TO_UNIT(minor(dev));
	pnum = MINOR_TO_PORT(minor(dev));

	sc = (struct digi_softc *)devclass_get_softc(digi_devclass, unit);
	if (!sc)
		return (ENXIO);

	lwkt_gettoken(&tty_token);
	if (sc->status != DIGI_STATUS_ENABLED) {
		DLOG(DIGIDB_OPEN, (sc->dev, "Cannot open a disabled card\n"));
		lwkt_reltoken(&tty_token);
		return (ENXIO);
	}
	if (pnum >= sc->numports) {
		DLOG(DIGIDB_OPEN, (sc->dev, "port%d: Doesn't exist\n", pnum));
		lwkt_reltoken(&tty_token);
		return (ENXIO);
	}
	if (mynor & (CTRL_DEV | CONTROL_MASK)) {
		sc->opencnt++;
		lwkt_reltoken(&tty_token);
		return (0);
	}
	port = &sc->ports[pnum];
	tp = dev->si_tty = port->tp;
	bc = port->bc;

	crit_enter();

open_top:
	while (port->status & DIGI_DTR_OFF) {
		port->wopeners++;
		error = tsleep(&port->dtr_wait, PCATCH, "digidtr", 0);
		port->wopeners--;
		if (error)
			goto out;
	}

	if (tp->t_state & TS_ISOPEN) {
		/*
		 * The device is open, so everything has been initialized.
		 * Handle conflicts.
		 */
		if (mynor & CALLOUT_MASK) {
			if (!port->active_out) {
				error = EBUSY;
				DLOG(DIGIDB_OPEN, (sc->dev, "port %d:"
				    " BUSY error = %d\n", pnum, error));
				goto out;
			}
		} else if (port->active_out) {
			if (ap->a_oflags & O_NONBLOCK) {
				error = EBUSY;
				DLOG(DIGIDB_OPEN, (sc->dev,
				    "port %d: BUSY error = %d\n", pnum, error));
				goto out;
			}
			port->wopeners++;
			error = tsleep(&port->active_out, PCATCH, "digibi", 0);
			port->wopeners--;
			if (error != 0) {
				DLOG(DIGIDB_OPEN, (sc->dev,
				    "port %d: tsleep(digibi) error = %d\n",
				    pnum, error));
				goto out;
			}
			goto open_top;
		}
		if (tp->t_state & TS_XCLUDE && priv_check_cred(ap->a_cred, PRIV_ROOT, 0) != 0) {
			error = EBUSY;
			goto out;
		}
	} else {
		/*
		 * The device isn't open, so there are no conflicts.
		 * Initialize it.  Initialization is done twice in many
		 * cases: to preempt sleeping callin opens if we are callout,
		 * and to complete a callin open after DCD rises.
		 */
		callout_init_mp(&port->wakeupco);
		tp->t_oproc = digistart;
		tp->t_param = digiparam;
		tp->t_stop = digistop;
		tp->t_dev = dev;
		tp->t_termios = (mynor & CALLOUT_MASK) ?
		    port->it_out : port->it_in;
		sc->setwin(sc, 0);

		bc->rout = bc->rin;	/* clear input queue */
		bc->idata = 1;
		bc->iempty = 1;
		bc->ilow = 1;
		bc->mint = port->cd | port->sc->csigs->ri;
		bc->tin = bc->tout;
		if (port->ialtpin) {
			port->cd = sc->csigs->dsr;
			port->dsr = sc->csigs->cd;
		} else {
			port->cd = sc->csigs->cd;
			port->dsr = sc->csigs->dsr;
		}
		port->wopeners++;			/* XXX required ? */
		error = digiparam(tp, &tp->t_termios);
		port->wopeners--;

		if (error != 0) {
			DLOG(DIGIDB_OPEN, (sc->dev,
			    "port %d: cxpparam error = %d\n", pnum, error));
			goto out;
		}
		ttsetwater(tp);

		/* handle fake and initial DCD for callout devices */

		if (bc->mstat & port->cd || mynor & CALLOUT_MASK)
			linesw[tp->t_line].l_modem(tp, 1);
	}

	/* Wait for DCD if necessary */
	if (!(tp->t_state & TS_CARR_ON) && !(mynor & CALLOUT_MASK) &&
	    !(tp->t_cflag & CLOCAL) && !(ap->a_oflags & O_NONBLOCK)) {
		port->wopeners++;
		error = tsleep(TSA_CARR_ON(tp), PCATCH, "digidcd", 0);
		port->wopeners--;
		if (error != 0) {
			DLOG(DIGIDB_OPEN, (sc->dev,
			    "port %d: tsleep(digidcd) error = %d\n",
			    pnum, error));
			goto out;
		}
		goto open_top;
	}
	error = linesw[tp->t_line].l_open(dev, tp);
	DLOG(DIGIDB_OPEN, (sc->dev, "port %d: l_open error = %d\n",
	    pnum, error));

	digi_disc_optim(tp, &tp->t_termios, port);

	if (tp->t_state & TS_ISOPEN && mynor & CALLOUT_MASK)
		port->active_out = TRUE;

	if (tp->t_state & TS_ISOPEN)
		sc->opencnt++;
out:
	crit_exit();

	if (!(tp->t_state & TS_ISOPEN))
		digihardclose(port);

	DLOG(DIGIDB_OPEN, (sc->dev, "port %d: open() returns %d\n",
	    pnum, error));

	lwkt_reltoken(&tty_token);
	return (error);
}

static int
digiclose(struct dev_close_args *ap)
{
	cdev_t dev = ap->a_head.a_dev;
	int mynor;
	struct tty *tp;
	int unit, pnum;
	struct digi_softc *sc;
	struct digi_p *port;

	lwkt_gettoken(&tty_token);
	mynor = minor(dev);
	unit = MINOR_TO_UNIT(mynor);
	pnum = MINOR_TO_PORT(mynor);

	sc = (struct digi_softc *)devclass_get_softc(digi_devclass, unit);
	KASSERT(sc, ("digi%d: softc not allocated in digiclose", unit));

	if (mynor & (CTRL_DEV | CONTROL_MASK)) {
		sc->opencnt--;
		lwkt_reltoken(&tty_token);
		return (0);
	}

	port = sc->ports + pnum;
	tp = port->tp;

	DLOG(DIGIDB_CLOSE, (sc->dev, "port %d: closing\n", pnum));

	crit_enter();
	linesw[tp->t_line].l_close(tp, ap->a_fflag);
	digi_disc_optim(tp, &tp->t_termios, port);
	digistop(tp, FREAD | FWRITE);
	digihardclose(port);
	ttyclose(tp);
	--sc->opencnt;
	crit_exit();
	lwkt_reltoken(&tty_token);
	return (0);
}

static void
digidtrwakeup(void *chan)
{
	struct digi_p *port = chan;

	lwkt_gettoken(&tty_token);
	port->status &= ~DIGI_DTR_OFF;
	wakeup(&port->dtr_wait);
	port->wopeners--;
	lwkt_reltoken(&tty_token);
}

/*
 * NOTE: Must be called with tty_token held
 */
static void
digihardclose(struct digi_p *port)
{
	volatile struct board_chan *bc;

	ASSERT_LWKT_TOKEN_HELD(&tty_token);
	bc = port->bc;

	crit_enter();
	port->sc->setwin(port->sc, 0);
	bc->idata = 0;
	bc->iempty = 0;
	bc->ilow = 0;
	bc->mint = 0;
	if ((port->tp->t_cflag & HUPCL) ||
	    (!port->active_out && !(bc->mstat & port->cd) &&
	    !(port->it_in.c_cflag & CLOCAL)) ||
	    !(port->tp->t_state & TS_ISOPEN)) {
		digimctl(port, TIOCM_DTR | TIOCM_RTS, DMBIC);
		if (port->dtr_wait != 0) {
			/* Schedule a wakeup of any callin devices */
			port->wopeners++;
			callout_reset(&port->wakeupco, port->dtr_wait,
				      digidtrwakeup, port);
			port->status |= DIGI_DTR_OFF;
		}
	}
	port->active_out = FALSE;
	wakeup(&port->active_out);
	wakeup(TSA_CARR_ON(port->tp));
	crit_exit();
}

static int
digiread(struct dev_read_args *ap)
{
	cdev_t dev = ap->a_head.a_dev;
	int mynor;
	struct tty *tp;
	int error, unit, pnum;
	struct digi_softc *sc;

	mynor = minor(dev);
	if (mynor & CONTROL_MASK)
		return (ENODEV);

	lwkt_gettoken(&tty_token);
	unit = MINOR_TO_UNIT(mynor);
	pnum = MINOR_TO_PORT(mynor);

	sc = (struct digi_softc *)devclass_get_softc(digi_devclass, unit);
	KASSERT(sc, ("digi%d: softc not allocated in digiclose", unit));
	tp = &sc->ttys[pnum];

	error = linesw[tp->t_line].l_read(tp, ap->a_uio, ap->a_ioflag);
	DLOG(DIGIDB_READ, (sc->dev, "port %d: read() returns %d\n",
	    pnum, error));

	lwkt_reltoken(&tty_token);
	return (error);
}

static int
digiwrite(struct dev_write_args *ap)
{
	cdev_t dev = ap->a_head.a_dev;
	int mynor;
	struct tty *tp;
	int error, unit, pnum;
	struct digi_softc *sc;

	mynor = minor(dev);
	if (mynor & CONTROL_MASK)
		return (ENODEV);

	lwkt_gettoken(&tty_token);
	unit = MINOR_TO_UNIT(mynor);
	pnum = MINOR_TO_PORT(mynor);

	sc = (struct digi_softc *)devclass_get_softc(digi_devclass, unit);
	KASSERT(sc, ("digi%d: softc not allocated in digiclose", unit));
	tp = &sc->ttys[pnum];

	error = linesw[tp->t_line].l_write(tp, ap->a_uio, ap->a_ioflag);
	DLOG(DIGIDB_WRITE, (sc->dev, "port %d: write() returns %d\n",
	    pnum, error));

	lwkt_reltoken(&tty_token);
	return (error);
}

/*
 * Load module "digi_<mod>.ko" and look for a symbol called digi_mod_<mod>.
 *
 * Populate sc->bios, sc->fep, and sc->link from this data.
 *
 * sc->fep.data, sc->bios.data and sc->link.data are malloc()d according
 * to their respective sizes.
 *
 * The module is unloaded when we're done.
 */
static int
digi_loaddata(struct digi_softc *sc)
{
	struct digi_bios *bios;

	KASSERT(sc->bios.data == NULL, ("Uninitialised BIOS variable"));
	KASSERT(sc->fep.data == NULL, ("Uninitialised FEP variable"));
	KASSERT(sc->link.data == NULL, ("Uninitialised LINK variable"));
	KASSERT(sc->module != NULL, ("Uninitialised module name"));

	for (bios = digi_bioses; bios->model != NULL; bios++) {
		if (!strcmp(bios->model, sc->module))
			break;
	}
	if (bios->model == NULL) {
		kprintf("digi.ko: driver %s not found", sc->module);
		return(EINVAL);
	}

	sc->bios.size = bios->bios_size;
	if (sc->bios.size != 0 && bios->bios != NULL) {
		sc->bios.data = kmalloc(sc->bios.size, M_TTYS, M_WAITOK);
		bcopy(bios->bios, sc->bios.data, sc->bios.size);
	}

	sc->fep.size = bios->fep_size;
	if (sc->fep.size != 0 && bios->fep != NULL) {
		sc->fep.data = kmalloc(sc->fep.size, M_TTYS, M_WAITOK);
		bcopy(bios->fep, sc->fep.data, sc->fep.size);
	}

	return (0);
}

static int
digiioctl(struct dev_ioctl_args *ap)
{
	cdev_t dev = ap->a_head.a_dev;
	u_long cmd = ap->a_cmd;
	caddr_t data = ap->a_data;
	int unit, pnum, mynor, error, ret;
	struct digi_softc *sc;
	struct digi_p *port;
	struct tty *tp;
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
	int oldcmd;
	struct termios term;
#endif

	mynor = minor(dev);
	unit = MINOR_TO_UNIT(mynor);
	pnum = MINOR_TO_PORT(mynor);

	lwkt_gettoken(&tty_token);
	sc = (struct digi_softc *)devclass_get_softc(digi_devclass, unit);
	KASSERT(sc, ("digi%d: softc not allocated in digiioctl", unit));

	if (sc->status == DIGI_STATUS_DISABLED) {
		lwkt_reltoken(&tty_token);
		return (ENXIO);
	}

	if (mynor & CTRL_DEV) {
		switch (cmd) {
		case DIGIIO_DEBUG:
#ifdef DEBUG
			digi_debug = *(int *)data;
			lwkt_reltoken(&tty_token);
			return (0);
#else
			device_printf(sc->dev, "DEBUG not defined\n");
			lwkt_reltoken(&tty_token);
			return (ENXIO);
#endif
		case DIGIIO_REINIT:
			digi_loaddata(sc);
			error = digi_init(sc);
			digi_freedata(sc);
			lwkt_reltoken(&tty_token);
			return (error);

		case DIGIIO_MODEL:
			*(enum digi_model *)data = sc->model;
			lwkt_reltoken(&tty_token);
			return (0);

		case DIGIIO_IDENT:
			ret = copyout(sc->name, *(char **)data,
			    strlen(sc->name) + 1);
			lwkt_reltoken(&tty_token);
			return ret;
		}
	}

	if (pnum >= sc->numports) {
		lwkt_reltoken(&tty_token);
		return (ENXIO);
	}

	port = sc->ports + pnum;
	if (!(port->status & ENABLED)) {
		lwkt_reltoken(&tty_token);
		return (ENXIO);
	}

	tp = port->tp;

	if (mynor & CONTROL_MASK) {
		struct termios *ct;

		switch (mynor & CONTROL_MASK) {
		case CONTROL_INIT_STATE:
			ct = (mynor & CALLOUT_MASK) ?
			    &port->it_out : &port->it_in;
			break;
		case CONTROL_LOCK_STATE:
			ct = (mynor & CALLOUT_MASK) ?
			    &port->lt_out : &port->lt_in;
			break;
		default:
			lwkt_reltoken(&tty_token);
			return (ENODEV);	/* /dev/nodev */
		}

		switch (cmd) {
		case TIOCSETA:
			error = priv_check_cred(ap->a_cred, PRIV_ROOT, 0);
			if (error != 0) {
				lwkt_reltoken(&tty_token);
				return (error);
			}
			*ct = *(struct termios *)data;
			lwkt_reltoken(&tty_token);
			return (0);

		case TIOCGETA:
			*(struct termios *)data = *ct;
			lwkt_reltoken(&tty_token);
			return (0);

		case TIOCGETD:
			*(int *)data = TTYDISC;
			lwkt_reltoken(&tty_token);
			return (0);

		case TIOCGWINSZ:
			bzero(data, sizeof(struct winsize));
			lwkt_reltoken(&tty_token);
			return (0);

		case DIGIIO_GETALTPIN:
			switch (mynor & CONTROL_MASK) {
			case CONTROL_INIT_STATE:
				*(int *)data = port->ialtpin;
				break;

			case CONTROL_LOCK_STATE:
				*(int *)data = port->laltpin;
				break;

			default:
				panic("Confusion when re-testing minor");
				lwkt_reltoken(&tty_token);
				return (ENODEV);
			}
			lwkt_reltoken(&tty_token);
			return (0);

		case DIGIIO_SETALTPIN:
			switch (mynor & CONTROL_MASK) {
			case CONTROL_INIT_STATE:
				if (!port->laltpin) {
					port->ialtpin = !!*(int *)data;
					DLOG(DIGIDB_SET, (sc->dev,
					    "port%d: initial ALTPIN %s\n", pnum,
					    port->ialtpin ? "set" : "cleared"));
				}
				break;

			case CONTROL_LOCK_STATE:
				port->laltpin = !!*(int *)data;
				DLOG(DIGIDB_SET, (sc->dev,
				    "port%d: ALTPIN %slocked\n",
				    pnum, port->laltpin ? "" : "un"));
				break;

			default:
				panic("Confusion when re-testing minor");
				lwkt_reltoken(&tty_token);
				return (ENODEV);
			}
			lwkt_reltoken(&tty_token);
			return (0);

		default:
			lwkt_reltoken(&tty_token);
			return (ENOTTY);
		}
	}

	switch (cmd) {
	case DIGIIO_GETALTPIN:
		*(int *)data = !!(port->dsr == sc->csigs->cd);
		lwkt_reltoken(&tty_token);
		return (0);

	case DIGIIO_SETALTPIN:
		if (!port->laltpin) {
			if (*(int *)data) {
				DLOG(DIGIDB_SET, (sc->dev,
				    "port%d: ALTPIN set\n", pnum));
				port->cd = sc->csigs->dsr;
				port->dsr = sc->csigs->cd;
			} else {
				DLOG(DIGIDB_SET, (sc->dev,
				    "port%d: ALTPIN cleared\n", pnum));
				port->cd = sc->csigs->cd;
				port->dsr = sc->csigs->dsr;
			}
		}
		lwkt_reltoken(&tty_token);
		return (0);
	}

	tp = port->tp;
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
	term = tp->t_termios;
	oldcmd = cmd;
	error = ttsetcompat(tp, &cmd, data, &term);
	if (error != 0) {
		lwkt_reltoken(&tty_token);
		return (error);
	}
	if (cmd != oldcmd)
		data = (caddr_t) & term;
#endif
	if (cmd == TIOCSETA || cmd == TIOCSETAW || cmd == TIOCSETAF) {
		int cc;
		struct termios *dt;
		struct termios *lt;

		dt = (struct termios *)data;
		lt = (mynor & CALLOUT_MASK) ? &port->lt_out : &port->lt_in;

		dt->c_iflag =
		    (tp->t_iflag & lt->c_iflag) | (dt->c_iflag & ~lt->c_iflag);
		dt->c_oflag =
		    (tp->t_oflag & lt->c_oflag) | (dt->c_oflag & ~lt->c_oflag);
		dt->c_cflag =
		    (tp->t_cflag & lt->c_cflag) | (dt->c_cflag & ~lt->c_cflag);
		dt->c_lflag =
		    (tp->t_lflag & lt->c_lflag) | (dt->c_lflag & ~lt->c_lflag);
		port->c_iflag = dt->c_iflag & (IXOFF | IXON | IXANY);
		dt->c_iflag &= ~(IXOFF | IXON | IXANY);
		for (cc = 0; cc < NCCS; ++cc)
			if (lt->c_cc[cc] != 0)
				dt->c_cc[cc] = tp->t_cc[cc];
		if (lt->c_ispeed != 0)
			dt->c_ispeed = tp->t_ispeed;
		if (lt->c_ospeed != 0)
			dt->c_ospeed = tp->t_ospeed;
	}
	error = linesw[tp->t_line].l_ioctl(tp, cmd, data, 
					   ap->a_fflag, ap->a_cred);
	if (error == 0 && cmd == TIOCGETA)
		((struct termios *)data)->c_iflag |= port->c_iflag;

	if (error >= 0 && error != ENOIOCTL) {
		lwkt_reltoken(&tty_token);
		return (error);
	}
	crit_enter();
	error = ttioctl(tp, cmd, data, ap->a_fflag);
	if (error == 0 && cmd == TIOCGETA)
		((struct termios *)data)->c_iflag |= port->c_iflag;

	digi_disc_optim(tp, &tp->t_termios, port);
	if (error >= 0 && error != ENOIOCTL) {
		crit_exit();
		lwkt_reltoken(&tty_token);
		return (error);
	}
	sc->setwin(sc, 0);
	switch (cmd) {
	case DIGIIO_RING:
		port->send_ring = *(u_char *)data;
		break;
	case TIOCSBRK:
		/*
		 * now it sends 400 millisecond break because I don't know
		 * how to send an infinite break
		 */
		fepcmd_w(port, SENDBREAK, 400, 10);
		break;
	case TIOCCBRK:
		/* now it's empty */
		break;
	case TIOCSDTR:
		digimctl(port, TIOCM_DTR, DMBIS);
		break;
	case TIOCCDTR:
		digimctl(port, TIOCM_DTR, DMBIC);
		break;
	case TIOCMSET:
		digimctl(port, *(int *)data, DMSET);
		break;
	case TIOCMBIS:
		digimctl(port, *(int *)data, DMBIS);
		break;
	case TIOCMBIC:
		digimctl(port, *(int *)data, DMBIC);
		break;
	case TIOCMGET:
		*(int *)data = digimctl(port, 0, DMGET);
		break;
	case TIOCMSDTRWAIT:
		error = priv_check_cred(ap->a_cred, PRIV_ROOT, 0);
		if (error != 0) {
			crit_exit();
			lwkt_reltoken(&tty_token);
			return (error);
		}
		port->dtr_wait = *(int *)data *hz / 100;

		break;
	case TIOCMGDTRWAIT:
		*(int *)data = port->dtr_wait * 100 / hz;
		break;
#ifdef DIGI_INTERRUPT
	case TIOCTIMESTAMP:
		*(struct timeval *)data = sc->intr_timestamp;

		break;
#endif
	default:
		crit_exit();
		lwkt_reltoken(&tty_token);
		return (ENOTTY);
	}
	crit_exit();
	lwkt_reltoken(&tty_token);
	return (0);
}

static int
digiparam(struct tty *tp, struct termios *t)
{
	int mynor;
	int unit;
	int pnum;
	struct digi_softc *sc;
	struct digi_p *port;
	int cflag;
	int iflag;
	int hflow;
	int window;

	lwkt_gettoken(&tty_token);
	mynor = minor(tp->t_dev);
	unit = MINOR_TO_UNIT(mynor);
	pnum = MINOR_TO_PORT(mynor);

	sc = (struct digi_softc *)devclass_get_softc(digi_devclass, unit);
	KASSERT(sc, ("digi%d: softc not allocated in digiparam", unit));

	port = &sc->ports[pnum];

	DLOG(DIGIDB_SET, (sc->dev, "port%d: setting parameters\n", pnum));

	if (t->c_ispeed == 0)
		t->c_ispeed = t->c_ospeed;

	cflag = ttspeedtab(t->c_ospeed, digispeedtab);

	if (cflag < 0 || (cflag > 0 && t->c_ispeed != t->c_ospeed)) {
		lwkt_reltoken(&tty_token);
		return (EINVAL);
	}

	crit_enter();

	window = sc->window;
	sc->setwin(sc, 0);

	if (cflag == 0) {				/* hangup */
		DLOG(DIGIDB_SET, (sc->dev, "port%d: hangup\n", pnum));
		digimctl(port, TIOCM_DTR | TIOCM_RTS, DMBIC);
	} else {
		digimctl(port, TIOCM_DTR | TIOCM_RTS, DMBIS);

		DLOG(DIGIDB_SET, (sc->dev, "port%d: CBAUD = %d\n", pnum,
		    cflag));

#if 0
		/* convert flags to sysV-style values */
		if (t->c_cflag & PARODD)
			cflag |= 0x0200;
		if (t->c_cflag & PARENB)
			cflag |= 0x0100;
		if (t->c_cflag & CSTOPB)
			cflag |= 0x0080;
#else
		/* convert flags to sysV-style values */
		if (t->c_cflag & PARODD)
			cflag |= FEP_PARODD;
		if (t->c_cflag & PARENB)
			cflag |= FEP_PARENB;
		if (t->c_cflag & CSTOPB)
			cflag |= FEP_CSTOPB;
		if (t->c_cflag & CLOCAL)
			cflag |= FEP_CLOCAL;
#endif

		cflag |= (t->c_cflag & CSIZE) >> 4;
		DLOG(DIGIDB_SET, (sc->dev, "port%d: CFLAG = 0x%x\n", pnum,
		    cflag));
		fepcmd_w(port, SETCFLAGS, (unsigned)cflag, 0);
	}

	iflag =
	    t->c_iflag & (IGNBRK | BRKINT | IGNPAR | PARMRK | INPCK | ISTRIP);
	if (port->c_iflag & IXON)
		iflag |= 0x400;
	if (port->c_iflag & IXANY)
		iflag |= 0x800;
	if (port->c_iflag & IXOFF)
		iflag |= 0x1000;

	DLOG(DIGIDB_SET, (sc->dev, "port%d: set iflag = 0x%x\n", pnum, iflag));
	fepcmd_w(port, SETIFLAGS, (unsigned)iflag, 0);

	hflow = 0;
	if (t->c_cflag & CDTR_IFLOW)
		hflow |= sc->csigs->dtr;
	if (t->c_cflag & CRTS_IFLOW)
		hflow |= sc->csigs->rts;
	if (t->c_cflag & CCTS_OFLOW)
		hflow |= sc->csigs->cts;
	if (t->c_cflag & CDSR_OFLOW)
		hflow |= port->dsr;
	if (t->c_cflag & CCAR_OFLOW)
		hflow |= port->cd;

	DLOG(DIGIDB_SET, (sc->dev, "port%d: set hflow = 0x%x\n", pnum, hflow));
	fepcmd_w(port, SETHFLOW, 0xff00 | (unsigned)hflow, 0);

	DLOG(DIGIDB_SET, (sc->dev, "port%d: set startc(0x%x), stopc(0x%x)\n",
	    pnum, t->c_cc[VSTART], t->c_cc[VSTOP]));
	fepcmd_b(port, SONOFFC, t->c_cc[VSTART], t->c_cc[VSTOP], 0);

	if (sc->window != 0)
		sc->towin(sc, 0);
	if (window != 0)
		sc->towin(sc, window);
	crit_exit();

	lwkt_reltoken(&tty_token);
	return (0);
}

static void
digi_intr(void *vp)
{
	struct digi_p *port;
	char *cxcon;
	struct digi_softc *sc;
	int ehead, etail;
	volatile struct board_chan *bc;
	struct tty *tp;
	int head, tail;
	int wrapmask;
	int size, window;
	struct event {
		u_char pnum;
		u_char event;
		u_char mstat;
		u_char lstat;
	} event;

	lwkt_gettoken(&tty_token);
	sc = vp;

	if (sc->status != DIGI_STATUS_ENABLED) {
		DLOG(DIGIDB_IRQ, (sc->dev, "interrupt on disabled board !\n"));
		lwkt_reltoken(&tty_token);
		return;
	}

#ifdef DIGI_INTERRUPT
	microtime(&sc->intr_timestamp);
#endif

	window = sc->window;
	sc->setwin(sc, 0);

	if (sc->model >= PCXEM && W(sc->vmem + 0xd00)) {
		struct con_bios *con = con_bios_list;
		u_char *ptr;

		ptr = sc->vmem + W(sc->vmem + 0xd00);
		while (con) {
			if (ptr[1] && W(ptr + 2) == W(con->bios + 2))
				/* Not first block -- exact match */
				break;

			if (W(ptr + 4) >= W(con->bios + 4) &&
			    W(ptr + 4) <= W(con->bios + 6))
				/* Initial search concetrator BIOS */
				break;
		}

		if (con == NULL) {
			log(LOG_ERR, "digi%d: wanted bios LREV = 0x%04x"
			    " not found!\n", sc->res.unit, W(ptr + 4));
			W(ptr + 10) = 0;
			W(sc->vmem + 0xd00) = 0;
			goto eoi;
		}
		cxcon = con->bios;
		W(ptr + 4) = W(cxcon + 4);
		W(ptr + 6) = W(cxcon + 6);
		if (ptr[1] == 0)
			W(ptr + 2) = W(cxcon + 2);
		W(ptr + 8) = (ptr[1] << 6) + W(cxcon + 8);
		size = W(cxcon + 10) - (ptr[1] << 10);
		if (size <= 0) {
			W(ptr + 8) = W(cxcon + 8);
			W(ptr + 10) = 0;
		} else {
			if (size > 1024)
				size = 1024;
			W(ptr + 10) = size;
			bcopy(cxcon + (ptr[1] << 10), ptr + 12, size);
		}
		W(sc->vmem + 0xd00) = 0;
		goto eoi;
	}

	ehead = sc->gdata->ein;
	etail = sc->gdata->eout;
	if (ehead == etail) {
#ifdef DEBUG
		sc->intr_count++;
		if (sc->intr_count % 6000 == 0) {
			DLOG(DIGIDB_IRQ, (sc->dev,
			    "6000 useless polls %x %x\n", ehead, etail));
			sc->intr_count = 0;
		}
#endif
		goto eoi;
	}
	while (ehead != etail) {
		event = *(volatile struct event *)(sc->memevent + etail);

		etail = (etail + 4) & sc->gdata->imax;

		if (event.pnum >= sc->numports) {
			log(LOG_ERR, "digi%d: port %d: got event"
			    " on nonexisting port\n", sc->res.unit,
			    event.pnum);
			continue;
		}
		port = &sc->ports[event.pnum];
		bc = port->bc;
		tp = port->tp;

		if (!(tp->t_state & TS_ISOPEN) && !port->wopeners) {
			DLOG(DIGIDB_IRQ, (sc->dev,
			    "port %d: event 0x%x on closed port\n",
			    event.pnum, event.event));
			bc->rout = bc->rin;
			bc->idata = 0;
			bc->iempty = 0;
			bc->ilow = 0;
			bc->mint = 0;
			continue;
		}
		if (event.event & ~ALL_IND)
			log(LOG_ERR, "digi%d: port%d: ? event 0x%x mstat 0x%x"
			    " lstat 0x%x\n", sc->res.unit, event.pnum,
			    event.event, event.mstat, event.lstat);

		if (event.event & DATA_IND) {
			DLOG(DIGIDB_IRQ, (sc->dev, "port %d: DATA_IND\n",
			    event.pnum));
			wrapmask = port->rxbufsize - 1;
			head = bc->rin;
			tail = bc->rout;

			size = 0;
			if (!(tp->t_state & TS_ISOPEN)) {
				bc->rout = head;
				goto end_of_data;
			}
			while (head != tail) {
				int top;

				DLOG(DIGIDB_INT, (sc->dev,
				    "port %d: p rx head = %d tail = %d\n",
				    event.pnum, head, tail));
				top = (head > tail) ? head : wrapmask + 1;
				sc->towin(sc, port->rxwin);
				size = top - tail;
				if (tp->t_state & TS_CAN_BYPASS_L_RINT) {
					size = b_to_q((char *)port->rxbuf +
					    tail, size, &tp->t_rawq);
					tail = top - size;
					ttwakeup(tp);
				} else for (; tail < top;) {
					linesw[tp->t_line].
					    l_rint(port->rxbuf[tail], tp);
					sc->towin(sc, port->rxwin);
					size--;
					tail++;
					if (tp->t_state & TS_TBLOCK)
						break;
				}
				tail &= wrapmask;
				sc->setwin(sc, 0);
				bc->rout = tail;
				head = bc->rin;
				if (size)
					break;
			}

			if (bc->orun) {
				CE_RECORD(port, CE_OVERRUN);
				log(LOG_ERR, "digi%d: port%d: %s\n",
				    sc->res.unit, event.pnum,
				    digi_errortxt(CE_OVERRUN));
				bc->orun = 0;
			}
end_of_data:
			if (size) {
				tp->t_state |= TS_TBLOCK;
				port->status |= PAUSE_RX;
				DLOG(DIGIDB_RX, (sc->dev, "port %d: pause RX\n",
				    event.pnum));
			} else {
				bc->idata = 1;
			}
		}

		if (event.event & MODEMCHG_IND) {
			DLOG(DIGIDB_MODEM, (sc->dev, "port %d: MODEMCHG_IND\n",
			    event.pnum));

			if ((event.mstat ^ event.lstat) & port->cd) {
				sc->hidewin(sc);
				linesw[tp->t_line].l_modem
				    (tp, event.mstat & port->cd);
				sc->setwin(sc, 0);
				wakeup(TSA_CARR_ON(tp));
			}

			if (event.mstat & sc->csigs->ri) {
				DLOG(DIGIDB_RI, (sc->dev, "port %d: RING\n",
				    event.pnum));
				if (port->send_ring) {
					linesw[tp->t_line].l_rint('R', tp);
					linesw[tp->t_line].l_rint('I', tp);
					linesw[tp->t_line].l_rint('N', tp);
					linesw[tp->t_line].l_rint('G', tp);
					linesw[tp->t_line].l_rint('\r', tp);
					linesw[tp->t_line].l_rint('\n', tp);
				}
			}
		}
		if (event.event & BREAK_IND) {
			DLOG(DIGIDB_MODEM, (sc->dev, "port %d: BREAK_IND\n",
			    event.pnum));
			linesw[tp->t_line].l_rint(TTY_BI, tp);
		}
		if (event.event & (LOWTX_IND | EMPTYTX_IND)) {
			DLOG(DIGIDB_IRQ, (sc->dev, "port %d:%s%s\n",
			    event.pnum,
			    event.event & LOWTX_IND ? " LOWTX" : "",
			    event.event & EMPTYTX_IND ?  " EMPTYTX" : ""));
			(*linesw[tp->t_line].l_start)(tp);
		}
	}
	sc->gdata->eout = etail;
eoi:
	if (sc->window != 0)
		sc->towin(sc, 0);
	if (window != 0)
		sc->towin(sc, window);
	lwkt_reltoken(&tty_token);
}

static void
digistart(struct tty *tp)
{
	int unit;
	int pnum;
	struct digi_p *port;
	struct digi_softc *sc;
	volatile struct board_chan *bc;
	int head, tail;
	int size, ocount, totcnt = 0;
	int wmask;

	lwkt_gettoken(&tty_token);
	unit = MINOR_TO_UNIT(minor(tp->t_dev));
	pnum = MINOR_TO_PORT(minor(tp->t_dev));

	sc = (struct digi_softc *)devclass_get_softc(digi_devclass, unit);
	KASSERT(sc, ("digi%d: softc not allocated in digistart", unit));

	port = &sc->ports[pnum];
	bc = port->bc;

	wmask = port->txbufsize - 1;

	crit_enter();
	port->lcc = tp->t_outq.c_cc;
	sc->setwin(sc, 0);
	if (!(tp->t_state & TS_TBLOCK)) {
		if (port->status & PAUSE_RX) {
			DLOG(DIGIDB_RX, (sc->dev, "port %d: resume RX\n",
			    pnum));
			/*
			 * CAREFUL - braces are needed here if the DLOG is
			 * optimised out!
			 */
		}
		port->status &= ~PAUSE_RX;
		bc->idata = 1;
	}
	if (!(tp->t_state & TS_TTSTOP) && port->status & PAUSE_TX) {
		DLOG(DIGIDB_TX, (sc->dev, "port %d: resume TX\n", pnum));
		port->status &= ~PAUSE_TX;
		fepcmd_w(port, RESUMETX, 0, 10);
	}
	if (tp->t_outq.c_cc == 0)
		tp->t_state &= ~TS_BUSY;
	else
		tp->t_state |= TS_BUSY;

	head = bc->tin;
	while (tp->t_outq.c_cc != 0) {
		tail = bc->tout;
		DLOG(DIGIDB_INT, (sc->dev, "port%d: s tx head = %d tail = %d\n",
		    pnum, head, tail));

		if (head < tail)
			size = tail - head - 1;
		else {
			size = port->txbufsize - head;
			if (tail == 0)
				size--;
		}

		if (size == 0)
			break;
		sc->towin(sc, port->txwin);
		ocount = q_to_b(&tp->t_outq, port->txbuf + head, size);
		totcnt += ocount;
		head += ocount;
		head &= wmask;
		sc->setwin(sc, 0);
		bc->tin = head;
		bc->iempty = 1;
		bc->ilow = 1;
	}
	port->lostcc = tp->t_outq.c_cc;
	tail = bc->tout;
	if (head < tail)
		size = port->txbufsize - tail + head;
	else
		size = head - tail;

	port->lbuf = size;
	DLOG(DIGIDB_INT, (sc->dev, "port%d: s total cnt = %d\n", pnum, totcnt));
	ttwwakeup(tp);
	crit_exit();
	lwkt_reltoken(&tty_token);
}

static void
digistop(struct tty *tp, int rw)
{
	struct digi_softc *sc;
	int unit;
	int pnum;
	struct digi_p *port;

	lwkt_gettoken(&tty_token);
	unit = MINOR_TO_UNIT(minor(tp->t_dev));
	pnum = MINOR_TO_PORT(minor(tp->t_dev));

	sc = (struct digi_softc *)devclass_get_softc(digi_devclass, unit);
	KASSERT(sc, ("digi%d: softc not allocated in digistop", unit));
	port = sc->ports + pnum;

	DLOG(DIGIDB_TX, (sc->dev, "port %d: pause TX\n", pnum));
	port->status |= PAUSE_TX;
	fepcmd_w(port, PAUSETX, 0, 10);
	lwkt_reltoken(&tty_token);
}

/*
 * NOTE: Must be called with tty_token held
 */
static void
fepcmd(struct digi_p *port, int cmd, int op1, int ncmds)
{
	u_char *mem;
	unsigned tail, head;
	int count, n;

	ASSERT_LWKT_TOKEN_HELD(&tty_token);
	mem = port->sc->memcmd;

	port->sc->setwin(port->sc, 0);

	head = port->sc->gdata->cin;
	mem[head + 0] = cmd;
	mem[head + 1] = port->pnum;
	*(u_short *)(mem + head + 2) = op1;

	head = (head + 4) & port->sc->gdata->cmax;
	port->sc->gdata->cin = head;

	for (count = FEPTIMEOUT; count > 0; count--) {
		head = port->sc->gdata->cin;
		tail = port->sc->gdata->cout;
		n = (head - tail) & port->sc->gdata->cmax;

		if (n <= ncmds * sizeof(short) * 4)
			break;
	}
	if (count == 0)
		log(LOG_ERR, "digi%d: port%d: timeout on FEP command\n",
		    port->sc->res.unit, port->pnum);
}

const char *
digi_errortxt(int id)
{
	static const char *error_desc[] = {
		"silo overflow",
		"interrupt-level buffer overflow",
		"tty-level buffer overflow",
	};

	KASSERT(id >= 0 && id < NELEM(error_desc),
	    ("Unexpected digi error id %d\n", id));

	return (error_desc[id]);
}

int
digi_attach(struct digi_softc *sc)
{
	lwkt_gettoken(&tty_token);
	sc->res.ctldev = make_dev(&digi_ops,
	    (sc->res.unit << 16) | CTRL_DEV, UID_ROOT, GID_WHEEL,
	    0600, "digi%r.ctl", sc->res.unit);

	digi_loaddata(sc);
	digi_init(sc);
	digi_freedata(sc);

	lwkt_reltoken(&tty_token);
	return (0);
}

/*
 * NOTE: Must be called with tty_token held
 */
static int
digi_inuse(struct digi_softc *sc)
{
	int i;

	ASSERT_LWKT_TOKEN_HELD(&tty_token);
	for (i = 0; i < sc->numports; i++)
		if (sc->ttys[i].t_state & TS_ISOPEN) {
			DLOG(DIGIDB_INIT, (sc->dev, "port%d: busy\n", i));
			return (1);
		} else if (sc->ports[i].wopeners || sc->ports[i].opencnt) {
			DLOG(DIGIDB_INIT, (sc->dev, "port%d: blocked in open\n",
			    i));
			return (1);
		}
	return (0);
}

/*
 * NOTE: Must be called with tty_token held
 */
static void
digi_free_state(struct digi_softc *sc)
{
	int d, i;

	ASSERT_LWKT_TOKEN_HELD(&tty_token);
	/* Blow it all away */

	for (i = 0; i < sc->numports; i++)
		for (d = 0; d < 6; d++)
			destroy_dev(sc->ports[i].dev[d]);

	callout_stop(&sc->callout);
	callout_stop(&sc->inttest);

	bus_teardown_intr(sc->dev, sc->res.irq, sc->res.irqHandler);
#ifdef DIGI_INTERRUPT
	if (sc->res.irq != NULL) {
		bus_release_resource(dev, SYS_RES_IRQ, sc->res.irqrid,
		    sc->res.irq);
		sc->res.irq = NULL;
	}
#endif
	if (sc->numports) {
		KASSERT(sc->ports, ("digi%d: Lost my ports ?", sc->res.unit));
		KASSERT(sc->ttys, ("digi%d: Lost my ttys ?", sc->res.unit));
		kfree(sc->ports, M_TTYS);
		sc->ports = NULL;
		kfree(sc->ttys, M_TTYS);
		sc->ttys = NULL;
		sc->numports = 0;
	}

	sc->status = DIGI_STATUS_NOTINIT;
}

int
digi_detach(device_t dev)
{
	struct digi_softc *sc = device_get_softc(dev);

	lwkt_gettoken(&tty_token);
	DLOG(DIGIDB_INIT, (sc->dev, "detaching\n"));

	/* If we're INIT'd, numports must be 0 */
	KASSERT(sc->numports == 0 || sc->status != DIGI_STATUS_NOTINIT,
	    ("digi%d: numports(%d) & status(%d) are out of sync",
	    sc->res.unit, sc->numports, (int)sc->status));

	if (digi_inuse(sc)) {
		lwkt_reltoken(&tty_token);
		return (EBUSY);
	}

	digi_free_state(sc);

	destroy_dev(sc->res.ctldev);

	if (sc->res.mem != NULL) {
		bus_release_resource(dev, SYS_RES_MEMORY, sc->res.mrid,
		    sc->res.mem);
		sc->res.mem = NULL;
	}
	if (sc->res.io != NULL) {
		bus_release_resource(dev, SYS_RES_IOPORT, sc->res.iorid,
		    sc->res.io);
		sc->res.io = NULL;
	}
	if (sc->msize) {
		pmap_unmapdev((vm_offset_t)sc->vmem, sc->msize);
		sc->msize = 0;
	}

	lwkt_reltoken(&tty_token);
	return (0);
}

int
digi_shutdown(device_t dev)
{
	return (0);
}

MODULE_VERSION(digi, 1);
