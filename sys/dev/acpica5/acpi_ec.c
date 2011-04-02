/*-
 * Copyright (c) 2003-2007 Nate Lawson
 * Copyright (c) 2000 Michael Smith
 * Copyright (c) 2000 BSDi
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
 * $FreeBSD: src/sys/dev/acpica/acpi_ec.c,v 1.76.2.1.6.1 2009/04/15 03:14:26 kensmith Exp $
 */

#include "opt_acpi.h"
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/rman.h>

#include "acpi.h"
#include <dev/acpica5/acpivar.h>
#include "acutils.h"

#define ACPI_LENOVO_S10 1

/* Hooks for the ACPI CA debugging infrastructure */
#define _COMPONENT	ACPI_EC
ACPI_MODULE_NAME("EC")

#define rebooting 0
#define PZERO 0
/*
 * EC_COMMAND:
 * -----------
 */
typedef UINT8				EC_COMMAND;

#define EC_COMMAND_UNKNOWN		((EC_COMMAND) 0x00)
#define EC_COMMAND_READ			((EC_COMMAND) 0x80)
#define EC_COMMAND_WRITE		((EC_COMMAND) 0x81)
#define EC_COMMAND_BURST_ENABLE		((EC_COMMAND) 0x82)
#define EC_COMMAND_BURST_DISABLE	((EC_COMMAND) 0x83)
#define EC_COMMAND_QUERY		((EC_COMMAND) 0x84)

/*
 * EC_STATUS:
 * ----------
 * The encoding of the EC status register is illustrated below.
 * Note that a set bit (1) indicates the property is TRUE
 * (e.g. if bit 0 is set then the output buffer is full).
 * +-+-+-+-+-+-+-+-+
 * |7|6|5|4|3|2|1|0|
 * +-+-+-+-+-+-+-+-+
 *  | | | | | | | |
 *  | | | | | | | +- Output Buffer Full?
 *  | | | | | | +--- Input Buffer Full?
 *  | | | | | +----- <reserved>
 *  | | | | +------- Data Register is Command Byte?
 *  | | | +--------- Burst Mode Enabled?
 *  | | +----------- SCI Event?
 *  | +------------- SMI Event?
 *  +--------------- <reserved>
 *
 */
typedef UINT8				EC_STATUS;

#define EC_FLAG_OUTPUT_BUFFER		((EC_STATUS) 0x01)
#define EC_FLAG_INPUT_BUFFER		((EC_STATUS) 0x02)
#define EC_FLAG_DATA_IS_CMD		((EC_STATUS) 0x08)
#define EC_FLAG_BURST_MODE		((EC_STATUS) 0x10)

/*
 * EC_EVENT:
 * ---------
 */
typedef UINT8				EC_EVENT;

#define EC_EVENT_UNKNOWN		((EC_EVENT) 0x00)
#define EC_EVENT_OUTPUT_BUFFER_FULL	((EC_EVENT) 0x01)
#define EC_EVENT_INPUT_BUFFER_EMPTY	((EC_EVENT) 0x02)
#define EC_EVENT_SCI			((EC_EVENT) 0x20)
#define EC_EVENT_SMI			((EC_EVENT) 0x40)

/* Data byte returned after burst enable indicating it was successful. */
#define EC_BURST_ACK			0x90

/*
 * Register access primitives
 */
#define EC_GET_DATA(sc)							\
	bus_space_read_1((sc)->ec_data_tag, (sc)->ec_data_handle, 0)

#define EC_SET_DATA(sc, v)						\
	bus_space_write_1((sc)->ec_data_tag, (sc)->ec_data_handle, 0, (v))

#define EC_GET_CSR(sc)							\
	bus_space_read_1((sc)->ec_csr_tag, (sc)->ec_csr_handle, 0)

#define EC_SET_CSR(sc, v)						\
	bus_space_write_1((sc)->ec_csr_tag, (sc)->ec_csr_handle, 0, (v))

/* Additional params to pass from the probe routine */
struct acpi_ec_params {
    int		glk;
    int		gpe_bit;
    ACPI_HANDLE	gpe_handle;
    int		uid;
};

/* Indicate that this device has already been probed via ECDT. */
#define DEV_ECDT(x)	(acpi_get_magic(x) == (uintptr_t)&acpi_ec_devclass)

/*
 * Driver softc.
 */
struct acpi_ec_softc {
    device_t		ec_dev;
    ACPI_HANDLE		ec_handle;
    int			ec_uid;
    ACPI_HANDLE		ec_gpehandle;
    UINT8		ec_gpebit;

    int			ec_data_rid;
    struct resource	*ec_data_res;
    bus_space_tag_t	ec_data_tag;
    bus_space_handle_t	ec_data_handle;

    int			ec_csr_rid;
    struct resource	*ec_csr_res;
    bus_space_tag_t	ec_csr_tag;
    bus_space_handle_t	ec_csr_handle;

    int			ec_glk;
    int			ec_glkhandle;
    int			ec_burstactive;
    int			ec_sci_pend;
#ifdef ACPI_LENOVO_S10
    volatile u_int	ec_gencount;
#else
    u_int		ec_gencount;
#endif
    int			ec_suspending;
};

/*
 * XXX njl
 * I couldn't find it in the spec but other implementations also use a
 * value of 1 ms for the time to acquire global lock.
 */
#define EC_LOCK_TIMEOUT	1000

/* Default delay in microseconds between each run of the status polling loop. */
#ifdef ACPI_LENOVO_S10
#define EC_POLL_DELAY	50
#else
#define EC_POLL_DELAY	5
#endif

/* Total time in ms spent waiting for a response from EC. */
#define EC_TIMEOUT	750

#define EVENT_READY(event, status)			\
	(((event) == EC_EVENT_OUTPUT_BUFFER_FULL &&	\
	 ((status) & EC_FLAG_OUTPUT_BUFFER) != 0) ||	\
	 ((event) == EC_EVENT_INPUT_BUFFER_EMPTY && 	\
	 ((status) & EC_FLAG_INPUT_BUFFER) == 0))

ACPI_SERIAL_DECL(ec, "ACPI embedded controller");

SYSCTL_DECL(_debug_acpi);
SYSCTL_NODE(_debug_acpi, OID_AUTO, ec, CTLFLAG_RD, NULL, "EC debugging");

static int	ec_burst_mode;
TUNABLE_INT("debug.acpi.ec.burst", &ec_burst_mode);
SYSCTL_INT(_debug_acpi_ec, OID_AUTO, burst, CTLFLAG_RW, &ec_burst_mode, 0,
    "Enable use of burst mode (faster for nearly all systems)");
static int	ec_polled_mode;
TUNABLE_INT("debug.acpi.ec.polled", &ec_polled_mode);
SYSCTL_INT(_debug_acpi_ec, OID_AUTO, polled, CTLFLAG_RW, &ec_polled_mode, 0,
    "Force use of polled mode (only if interrupt mode doesn't work)");
static int	ec_timeout = EC_TIMEOUT;
TUNABLE_INT("debug.acpi.ec.timeout", &ec_timeout);
SYSCTL_INT(_debug_acpi_ec, OID_AUTO, timeout, CTLFLAG_RW, &ec_timeout,
    EC_TIMEOUT, "Total time spent waiting for a response (poll+sleep)");

static ACPI_STATUS
EcLock(struct acpi_ec_softc *sc)
{
    ACPI_STATUS	status;

    ACPI_SERIAL_BEGIN(ec);
    /* If _GLK is non-zero, acquire the global lock. */
    status = AE_OK;
    if (sc->ec_glk) {
	status = AcpiAcquireGlobalLock(EC_LOCK_TIMEOUT, &sc->ec_glkhandle);
	if (ACPI_FAILURE(status))
	    ACPI_SERIAL_END(ec);
    }
    return (status);
}

static void
EcUnlock(struct acpi_ec_softc *sc)
{
    if (sc->ec_glk)
	AcpiReleaseGlobalLock(sc->ec_glkhandle);
    ACPI_SERIAL_END(ec);
}

static uint32_t		EcGpeHandler(ACPI_HANDLE GpeDevice,
                                 UINT32 GpeNumber, void *Context);
static ACPI_STATUS	EcSpaceSetup(ACPI_HANDLE Region, UINT32 Function,
				void *Context, void **return_Context);
static ACPI_STATUS	EcSpaceHandler(UINT32 Function,
				ACPI_PHYSICAL_ADDRESS Address,
				UINT32 width, ACPI_INTEGER *Value,
				void *Context, void *RegionContext);
static ACPI_STATUS	EcWaitEvent(struct acpi_ec_softc *sc, EC_EVENT Event,
				u_int gen_count);
static ACPI_STATUS	EcCommand(struct acpi_ec_softc *sc, EC_COMMAND cmd);
static ACPI_STATUS	EcRead(struct acpi_ec_softc *sc, UINT8 Address,
				UINT8 *Data);
static ACPI_STATUS	EcWrite(struct acpi_ec_softc *sc, UINT8 Address,
				UINT8 *Data);
static int		acpi_ec_probe(device_t dev);
static int		acpi_ec_attach(device_t dev);
static int		acpi_ec_suspend(device_t dev);
static int		acpi_ec_resume(device_t dev);
static int		acpi_ec_shutdown(device_t dev);
static int		acpi_ec_read_method(device_t dev, u_int addr,
				ACPI_INTEGER *val, int width);
static int		acpi_ec_write_method(device_t dev, u_int addr,
				ACPI_INTEGER val, int width);

static device_method_t acpi_ec_methods[] = {
    /* Device interface */
    DEVMETHOD(device_probe,	acpi_ec_probe),
    DEVMETHOD(device_attach,	acpi_ec_attach),
    DEVMETHOD(device_suspend,	acpi_ec_suspend),
    DEVMETHOD(device_resume,	acpi_ec_resume),
    DEVMETHOD(device_shutdown,	acpi_ec_shutdown),

    /* Embedded controller interface */
    DEVMETHOD(acpi_ec_read,	acpi_ec_read_method),
    DEVMETHOD(acpi_ec_write,	acpi_ec_write_method),

    {0, 0}
};

static driver_t acpi_ec_driver = {
    "acpi_ec",
    acpi_ec_methods,
    sizeof(struct acpi_ec_softc),
};

static devclass_t acpi_ec_devclass;
DRIVER_MODULE(acpi_ec, acpi, acpi_ec_driver, acpi_ec_devclass, 0, 0);
MODULE_DEPEND(acpi_ec, acpi, 1, 1, 1);

/*
 * Look for an ECDT and if we find one, set up default GPE and
 * space handlers to catch attempts to access EC space before
 * we have a real driver instance in place.
 *
 * TODO: Some old Gateway laptops need us to fake up an ECDT or
 * otherwise attach early so that _REG methods can run.
 */
void
acpi_ec_ecdt_probe(device_t parent)
{
    ACPI_TABLE_ECDT *ecdt;
    ACPI_STATUS	     status;
    device_t	     child;
    ACPI_HANDLE	     h;
    struct acpi_ec_params *params;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);

    /* Find and validate the ECDT. */
    status = AcpiGetTable(ACPI_SIG_ECDT, 1, (ACPI_TABLE_HEADER **)&ecdt);
    if (ACPI_FAILURE(status) ||
	ecdt->Control.BitWidth != 8 ||
	ecdt->Data.BitWidth != 8) {
	return;
    }

    /* Create the child device with the given unit number. */
    child = BUS_ADD_CHILD(parent, parent, 0, "acpi_ec", ecdt->Uid);
    if (child == NULL) {
	kprintf("%s: can't add child\n", __func__);
	return;
    }

    /* Find and save the ACPI handle for this device. */
    status = AcpiGetHandle(NULL, ecdt->Id, &h);
    if (ACPI_FAILURE(status)) {
	device_delete_child(parent, child);
	kprintf("%s: can't get handle\n", __func__);
	return;
    }
    acpi_set_handle(child, h);

    /* Set the data and CSR register addresses. */
    bus_set_resource(child, SYS_RES_IOPORT, 0, ecdt->Data.Address,
	/*count*/1);
    bus_set_resource(child, SYS_RES_IOPORT, 1, ecdt->Control.Address,
	/*count*/1);

    /*
     * Store values for the probe/attach routines to use.  Store the
     * ECDT GPE bit and set the global lock flag according to _GLK.
     * Note that it is not perfectly correct to be evaluating a method
     * before initializing devices, but in practice this function
     * should be safe to call at this point.
     */
    params = kmalloc(sizeof(struct acpi_ec_params), M_TEMP, M_WAITOK | M_ZERO);
    params->gpe_handle = NULL;
    params->gpe_bit = ecdt->Gpe;
    params->uid = ecdt->Uid;
    acpi_GetInteger(h, "_GLK", &params->glk);
    acpi_set_private(child, params);
    acpi_set_magic(child, (uintptr_t)&acpi_ec_devclass);

    /* Finish the attach process. */
    if (device_probe_and_attach(child) != 0)
	device_delete_child(parent, child);
}

static int
acpi_ec_probe(device_t dev)
{
    ACPI_BUFFER buf;
    ACPI_HANDLE h;
    ACPI_OBJECT *obj;
    ACPI_STATUS status;
    device_t	peer;
    char	desc[64];
    int		ret;
    struct acpi_ec_params *params;
    static char *ec_ids[] = { "PNP0C09", NULL };

    /* Check that this is a device and that EC is not disabled. */
    if (acpi_get_type(dev) != ACPI_TYPE_DEVICE || acpi_disabled("ec"))
	return (ENXIO);

    /*
     * If probed via ECDT, set description and continue.  Otherwise,
     * we can access the namespace and make sure this is not a
     * duplicate probe.
     */
    ret = ENXIO;
    params = NULL;
    buf.Pointer = NULL;
    buf.Length = ACPI_ALLOCATE_BUFFER;
    if (DEV_ECDT(dev)) {
	params = acpi_get_private(dev);
	ret = 0;
    } else if (!acpi_disabled("ec") &&
	ACPI_ID_PROBE(device_get_parent(dev), dev, ec_ids)) {
	params = kmalloc(sizeof(struct acpi_ec_params), M_TEMP,
			M_WAITOK | M_ZERO);
	h = acpi_get_handle(dev);

	/*
	 * Read the unit ID to check for duplicate attach and the
	 * global lock value to see if we should acquire it when
	 * accessing the EC.
	 */
	status = acpi_GetInteger(h, "_UID", &params->uid);
	if (ACPI_FAILURE(status))
	    params->uid = 0;
	status = acpi_GetInteger(h, "_GLK", &params->glk);
	if (ACPI_FAILURE(status))
	    params->glk = 0;

	/*
	 * Evaluate the _GPE method to find the GPE bit used by the EC to
	 * signal status (SCI).  If it's a package, it contains a reference
	 * and GPE bit, similar to _PRW.
	 */
	status = AcpiEvaluateObject(h, "_GPE", NULL, &buf);
	if (ACPI_FAILURE(status)) {
	    device_printf(dev, "can't evaluate _GPE - %s\n",
			  AcpiFormatException(status));
	    goto out;
	}
	obj = (ACPI_OBJECT *)buf.Pointer;
	if (obj == NULL)
	    goto out;

	switch (obj->Type) {
	case ACPI_TYPE_INTEGER:
	    params->gpe_handle = NULL;
	    params->gpe_bit = obj->Integer.Value;
	    break;
	case ACPI_TYPE_PACKAGE:
	    if (!ACPI_PKG_VALID(obj, 2))
		goto out;
	    params->gpe_handle =
		acpi_GetReference(NULL, &obj->Package.Elements[0]);
	    if (params->gpe_handle == NULL ||
		acpi_PkgInt32(obj, 1, &params->gpe_bit) != 0)
		goto out;
	    break;
	default:
	    device_printf(dev, "_GPE has invalid type %d\n", obj->Type);
	    goto out;
	}

	/* Store the values we got from the namespace for attach. */
	acpi_set_private(dev, params);

	/*
	 * Check for a duplicate probe.  This can happen when a probe
	 * via ECDT succeeded already.  If this is a duplicate, disable
	 * this device.
	 */
	peer = devclass_get_device(acpi_ec_devclass, params->uid);
	if (peer == NULL || !device_is_alive(peer))
	    ret = 0;
	else
	    device_disable(dev);
    }

out:
    if (ret == 0) {
	ksnprintf(desc, sizeof(desc), "Embedded Controller: GPE %#x%s%s",
		 params->gpe_bit, (params->glk) ? ", GLK" : "",
		 DEV_ECDT(dev) ? ", ECDT" : "");
	device_set_desc_copy(dev, desc);
    }

    if (ret > 0 && params)
	kfree(params, M_TEMP);
    if (buf.Pointer)
	AcpiOsFree(buf.Pointer);
    return (ret);
}

static int
acpi_ec_attach(device_t dev)
{
    struct acpi_ec_softc	*sc;
    struct acpi_ec_params	*params;
    ACPI_STATUS			Status;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);

    /* Fetch/initialize softc (assumes softc is pre-zeroed). */
    sc = device_get_softc(dev);
    params = acpi_get_private(dev);
    sc->ec_dev = dev;
    sc->ec_handle = acpi_get_handle(dev);
    ACPI_SERIAL_INIT(ec);

    /* Retrieve previously probed values via device ivars. */
    sc->ec_glk = params->glk;
    sc->ec_gpebit = params->gpe_bit;
    sc->ec_gpehandle = params->gpe_handle;
    sc->ec_uid = params->uid;
    sc->ec_suspending = FALSE;
    kfree(params, M_TEMP);

    /* Attach bus resources for data and command/status ports. */
    sc->ec_data_rid = 0;
    sc->ec_data_res = bus_alloc_resource_any(sc->ec_dev, SYS_RES_IOPORT,
			&sc->ec_data_rid, RF_ACTIVE);
    if (sc->ec_data_res == NULL) {
	device_printf(dev, "can't allocate data port\n");
	goto error;
    }
    sc->ec_data_tag = rman_get_bustag(sc->ec_data_res);
    sc->ec_data_handle = rman_get_bushandle(sc->ec_data_res);

    sc->ec_csr_rid = 1;
    sc->ec_csr_res = bus_alloc_resource_any(sc->ec_dev, SYS_RES_IOPORT,
			&sc->ec_csr_rid, RF_ACTIVE);
    if (sc->ec_csr_res == NULL) {
	device_printf(dev, "can't allocate command/status port\n");
	goto error;
    }
    sc->ec_csr_tag = rman_get_bustag(sc->ec_csr_res);
    sc->ec_csr_handle = rman_get_bushandle(sc->ec_csr_res);

    /*
     * Install a handler for this EC's GPE bit.  We want edge-triggered
     * behavior.
     */
    ACPI_DEBUG_PRINT((ACPI_DB_RESOURCES, "attaching GPE handler\n"));
    Status = AcpiInstallGpeHandler(sc->ec_gpehandle, sc->ec_gpebit,
		ACPI_GPE_EDGE_TRIGGERED, &EcGpeHandler, sc);
    if (ACPI_FAILURE(Status)) {
	device_printf(dev, "can't install GPE handler for %s - %s\n",
		      acpi_name(sc->ec_handle), AcpiFormatException(Status));
	goto error;
    }

    /*
     * Install address space handler
     */
    ACPI_DEBUG_PRINT((ACPI_DB_RESOURCES, "attaching address space handler\n"));
    Status = AcpiInstallAddressSpaceHandler(sc->ec_handle, ACPI_ADR_SPACE_EC,
		&EcSpaceHandler, &EcSpaceSetup, sc);
    if (ACPI_FAILURE(Status)) {
	device_printf(dev, "can't install address space handler for %s - %s\n",
		      acpi_name(sc->ec_handle), AcpiFormatException(Status));
	goto error;
    }

    /* Enable runtime GPEs done internally by AcpiEnableGpe() */

    Status = AcpiEnableGpe(sc->ec_gpehandle, sc->ec_gpebit);
    if (ACPI_FAILURE(Status)) {
	device_printf(dev, "AcpiEnableGpe failed: %s\n",
		      AcpiFormatException(Status));
	goto error;
    }

    ACPI_DEBUG_PRINT((ACPI_DB_RESOURCES, "acpi_ec_attach complete\n"));
    return (0);

error:
    AcpiRemoveGpeHandler(sc->ec_gpehandle, sc->ec_gpebit, &EcGpeHandler);
    AcpiRemoveAddressSpaceHandler(sc->ec_handle, ACPI_ADR_SPACE_EC,
	EcSpaceHandler);
    if (sc->ec_csr_res)
	bus_release_resource(sc->ec_dev, SYS_RES_IOPORT, sc->ec_csr_rid,
			     sc->ec_csr_res);
    if (sc->ec_data_res)
	bus_release_resource(sc->ec_dev, SYS_RES_IOPORT, sc->ec_data_rid,
			     sc->ec_data_res);
    return (ENXIO);
}

static int
acpi_ec_suspend(device_t dev)
{
    struct acpi_ec_softc	*sc;

    sc = device_get_softc(dev);
    sc->ec_suspending = TRUE;
    return (0);
}

static int
acpi_ec_resume(device_t dev)
{
    struct acpi_ec_softc	*sc;

    sc = device_get_softc(dev);
    sc->ec_suspending = FALSE;
    return (0);
}

static int
acpi_ec_shutdown(device_t dev)
{
    struct acpi_ec_softc	*sc;

    /* Disable the GPE so we don't get EC events during shutdown. */
    sc = device_get_softc(dev);
    AcpiDisableGpe(sc->ec_gpehandle, sc->ec_gpebit);
    return (0);
}

/* Methods to allow other devices (e.g., smbat) to read/write EC space. */
static int
acpi_ec_read_method(device_t dev, u_int addr, ACPI_INTEGER *val, int width)
{
    struct acpi_ec_softc *sc;
    ACPI_STATUS status;

    sc = device_get_softc(dev);
    status = EcSpaceHandler(ACPI_READ, addr, width * 8, val, sc, NULL);
    if (ACPI_FAILURE(status))
	return (ENXIO);
    return (0);
}

static int
acpi_ec_write_method(device_t dev, u_int addr, ACPI_INTEGER val, int width)
{
    struct acpi_ec_softc *sc;
    ACPI_STATUS status;

    sc = device_get_softc(dev);
    status = EcSpaceHandler(ACPI_WRITE, addr, width * 8, &val, sc, NULL);
    if (ACPI_FAILURE(status))
	return (ENXIO);
    return (0);
}

#ifdef ACPI_LENOVO_S10
static ACPI_STATUS
EcCheckStatus(struct acpi_ec_softc *sc, const char *msg, EC_EVENT event)
{
    ACPI_STATUS status;
    EC_STATUS ec_status;

    status = AE_NO_HARDWARE_RESPONSE;
    ec_status = EC_GET_CSR(sc);
    if (sc->ec_burstactive && !(ec_status & EC_FLAG_BURST_MODE)) {
#if 0
	CTR1(KTR_ACPI, "ec burst disabled in waitevent (%s)", msg);
#endif
	sc->ec_burstactive = FALSE;
    }
    if (EVENT_READY(event, ec_status)) {
#if 0
	CTR2(KTR_ACPI, "ec %s wait ready, status %#x", msg, ec_status);
#endif
	status = AE_OK;
    }
    return (status);
}
#endif

static void
EcGpeQueryHandler(void *Context)
{
    struct acpi_ec_softc	*sc = (struct acpi_ec_softc *)Context;
    UINT8			Data;
    ACPI_STATUS			Status;
#ifdef ACPI_LENOVO_S10
    int				retry;
#endif
    char			qxx[5];

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);
    KASSERT(Context != NULL, ("EcGpeQueryHandler called with NULL"));

    /* Serialize user access with EcSpaceHandler(). */
    Status = EcLock(sc);
    if (ACPI_FAILURE(Status)) {
	device_printf(sc->ec_dev, "GpeQuery lock error: %s\n",
	    AcpiFormatException(Status));
	return;
    }

    /*
     * Send a query command to the EC to find out which _Qxx call it
     * wants to make.  This command clears the SCI bit and also the
     * interrupt source since we are edge-triggered.  To prevent the GPE
     * that may arise from running the query from causing another query
     * to be queued, we clear the pending flag only after running it.
     */
#ifdef ACPI_LENOVO_S10
    for (retry = 0; retry < 2; retry++) {
	Status = EcCommand(sc, EC_COMMAND_QUERY);
	if (ACPI_SUCCESS(Status))
	    break;
	if (EcCheckStatus(sc, "retr_check",
	    EC_EVENT_INPUT_BUFFER_EMPTY) == AE_OK)
	    continue;
	else
	    break;
    }
#else
    Status = EcCommand(sc, EC_COMMAND_QUERY);
#endif
    sc->ec_sci_pend = FALSE;
    if (ACPI_FAILURE(Status)) {
	EcUnlock(sc);
	device_printf(sc->ec_dev, "GPE query failed: %s\n",
	    AcpiFormatException(Status));
	return;
    }
    Data = EC_GET_DATA(sc);

    /*
     * We have to unlock before running the _Qxx method below since that
     * method may attempt to read/write from EC address space, causing
     * recursive acquisition of the lock.
     */
    EcUnlock(sc);

    /* Ignore the value for "no outstanding event". (13.3.5) */
#if 0
    CTR2(KTR_ACPI, "ec query ok,%s running _Q%02X", Data ? "" : " not", Data);
#endif
    if (Data == 0)
	return;

    /* Evaluate _Qxx to respond to the controller. */
    ksnprintf(qxx, sizeof(qxx), "_Q%02X", Data);
    AcpiUtStrupr(qxx);
    Status = AcpiEvaluateObject(sc->ec_handle, qxx, NULL, NULL);
    if (ACPI_FAILURE(Status) && Status != AE_NOT_FOUND) {
	device_printf(sc->ec_dev, "evaluation of query method %s failed: %s\n",
	    qxx, AcpiFormatException(Status));
    }

    /* Reenable runtime GPE if its execution was deferred. */
    if (sc->ec_sci_pend) {
	Status = AcpiFinishGpe(sc->ec_gpehandle, sc->ec_gpebit);
	if (ACPI_FAILURE(Status)) {
	    device_printf(sc->ec_dev, "reenabling runtime GPE failed: %s\n",
		AcpiFormatException(Status));
    	}
    }
}

/*
 * The GPE handler is called when IBE/OBF or SCI events occur.  We are
 * called from an unknown lock context.
 */
static uint32_t
EcGpeHandler(ACPI_HANDLE GpeDevice, UINT32 GpeNumber, void *Context)
{
    struct acpi_ec_softc *sc = Context;
    ACPI_STATUS		       Status;
    EC_STATUS		       EcStatus;

    KASSERT(Context != NULL, ("EcGpeHandler called with NULL"));
#if 0
    CTR0(KTR_ACPI, "ec gpe handler start");
#endif
    /*
     * Notify EcWaitEvent() that the status register is now fresh.  If we
     * didn't do this, it wouldn't be possible to distinguish an old IBE
     * from a new one, for example when doing a write transaction (writing
     * address and then data values.)
     */
    atomic_add_int(&sc->ec_gencount, 1);
#ifdef ACPI_LENOVO_S10
    wakeup(sc);
#else
    wakeup(&sc->ec_gencount);
#endif

    /*
     * If the EC_SCI bit of the status register is set, queue a query handler.
     * It will run the query and _Qxx method later, under the lock.
     */
    EcStatus = EC_GET_CSR(sc);
    if ((EcStatus & EC_EVENT_SCI) && !sc->ec_sci_pend) {
#if 0
	CTR0(KTR_ACPI, "ec gpe queueing query handler");
#endif
	Status = AcpiOsExecute(OSL_GPE_HANDLER, EcGpeQueryHandler, Context);
	if (ACPI_SUCCESS(Status))
	    sc->ec_sci_pend = TRUE;
	else
	    kprintf("EcGpeHandler: queuing GPE query handler failed\n");
    }
    return (0);
}

static ACPI_STATUS
EcSpaceSetup(ACPI_HANDLE Region, UINT32 Function, void *Context,
	     void **RegionContext)
{

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);

    /*
     * If deactivating a region, always set the output to NULL.  Otherwise,
     * just pass the context through.
     */
    if (Function == ACPI_REGION_DEACTIVATE)
	*RegionContext = NULL;
    else
	*RegionContext = Context;

    return_ACPI_STATUS (AE_OK);
}

static ACPI_STATUS
EcSpaceHandler(UINT32 Function, ACPI_PHYSICAL_ADDRESS Address, UINT32 width,
	       ACPI_INTEGER *Value, void *Context, void *RegionContext)
{
    struct acpi_ec_softc	*sc = (struct acpi_ec_softc *)Context;
    ACPI_STATUS			Status;
    UINT8			EcAddr, EcData;
    int				i;

    ACPI_FUNCTION_TRACE_U32((char *)(uintptr_t)__func__, (UINT32)Address);

    if (width % 8 != 0 || Value == NULL || Context == NULL)
	return_ACPI_STATUS (AE_BAD_PARAMETER);
    if (Address + (width / 8) - 1 > 0xFF)
	return_ACPI_STATUS (AE_BAD_ADDRESS);

    if (Function == ACPI_READ)
	*Value = 0;
    EcAddr = Address;
    Status = AE_ERROR;

    /*
     * If booting, check if we need to run the query handler.  If so, we
     * we call it directly here since our thread taskq is not active yet.
     */
    if (cold || rebooting) {
	if ((EC_GET_CSR(sc) & EC_EVENT_SCI)) {
#if 0
	    CTR0(KTR_ACPI, "ec running gpe handler directly");
#endif
	    EcGpeQueryHandler(sc);
	}
    }

    /* Serialize with EcGpeQueryHandler() at transaction granularity. */
    Status = EcLock(sc);
    if (ACPI_FAILURE(Status)) {
	return_ACPI_STATUS (Status);
    }

    /* Perform the transaction(s), based on width. */
    for (i = 0; i < width; i += 8, EcAddr++) {
	switch (Function) {
	case ACPI_READ:
	    Status = EcRead(sc, EcAddr, &EcData);
	    if (ACPI_SUCCESS(Status))
		*Value |= ((ACPI_INTEGER)EcData) << i;
	    break;
	case ACPI_WRITE:
	    EcData = (UINT8)((*Value) >> i);
	    Status = EcWrite(sc, EcAddr, &EcData);
	    break;
	default:
	    device_printf(sc->ec_dev, "invalid EcSpaceHandler function %d\n",
			  Function);
	    Status = AE_BAD_PARAMETER;
	    break;
	}
	if (ACPI_FAILURE(Status))
	    break;
    }

    EcUnlock(sc);
    return_ACPI_STATUS (Status);
}

#ifndef ACPI_LENOVO_S10
static ACPI_STATUS
EcCheckStatus(struct acpi_ec_softc *sc, const char *msg, EC_EVENT event)
{
    ACPI_STATUS status;
    EC_STATUS ec_status;

    status = AE_NO_HARDWARE_RESPONSE;
    ec_status = EC_GET_CSR(sc);
    if (sc->ec_burstactive && !(ec_status & EC_FLAG_BURST_MODE)) {
#if 0
	CTR1(KTR_ACPI, "ec burst disabled in waitevent (%s)", msg);
#endif
	sc->ec_burstactive = FALSE;
    }
    if (EVENT_READY(event, ec_status)) {
#if 0
	CTR2(KTR_ACPI, "ec %s wait ready, status %#x", msg, ec_status);
#endif
	status = AE_OK;
    }
    return (status);
}
#endif

static ACPI_STATUS
EcWaitEvent(struct acpi_ec_softc *sc, EC_EVENT Event, u_int gen_count)
{
#ifdef ACPI_LENOVO_S10
    static int	no_intr = 0;
#endif
    ACPI_STATUS	Status;
#ifdef ACPI_LENOVO_S10
    int		count, i, need_poll, slp_ival;
#else
    int		count, i, slp_ival;
#endif

    ACPI_SERIAL_ASSERT(ec);
    Status = AE_NO_HARDWARE_RESPONSE;
#ifdef ACPI_LENOVO_S10
    need_poll = cold || rebooting || ec_polled_mode || sc->ec_suspending;
#else
    int need_poll = cold || rebooting || ec_polled_mode || sc->ec_suspending;
    /*
     * The main CPU should be much faster than the EC.  So the status should
     * be "not ready" when we start waiting.  But if the main CPU is really
     * slow, it's possible we see the current "ready" response.  Since that
     * can't be distinguished from the previous response in polled mode,
     * this is a potential issue.  We really should have interrupts enabled
     * during boot so there is no ambiguity in polled mode.
     *
     * If this occurs, we add an additional delay before actually entering
     * the status checking loop, hopefully to allow the EC to go to work
     * and produce a non-stale status.
     */
    if (need_poll) {
	static int	once;

	if (EcCheckStatus(sc, "pre-check", Event) == AE_OK) {
	    if (!once) {
		device_printf(sc->ec_dev,
		    "warning: EC done before starting event wait\n");
		once = 1;
	    }
	    AcpiOsStall(10);
	}
    }
#endif

    /* Wait for event by polling or GPE (interrupt). */
    if (need_poll) {
	count = (ec_timeout * 1000) / EC_POLL_DELAY;
	if (count == 0)
	    count = 1;
#ifdef ACPI_LENOVO_S10
	DELAY(10);
#endif
	for (i = 0; i < count; i++) {
	    Status = EcCheckStatus(sc, "poll", Event);
	    if (Status == AE_OK)
		break;
#ifdef ACPI_LENOVO_S10
	    DELAY(EC_POLL_DELAY);
#else
	    AcpiOsStall(EC_POLL_DELAY);
#endif
	}
    } else {
	slp_ival = hz / 1000;
	if (slp_ival != 0) {
	    count = ec_timeout;
	} else {
	    /* hz has less than 1 ms resolution so scale timeout. */
	    slp_ival = 1;
	    count = ec_timeout / (1000 / hz);
	}

	/*
	 * Wait for the GPE to signal the status changed, checking the
	 * status register each time we get one.  It's possible to get a
	 * GPE for an event we're not interested in here (i.e., SCI for
	 * EC query).
	 */
	for (i = 0; i < count; i++) {
#ifdef ACPI_LENOVO_S10
	    if (gen_count == sc->ec_gencount)
		tsleep(sc, 0, "ecgpe", slp_ival);
	    /*
	     * Record new generation count.  It's possible the GPE was
	     * just to notify us that a query is needed and we need to
	     * wait for a second GPE to signal the completion of the
	     * event we are actually waiting for.
	     */
	    Status = EcCheckStatus(sc, "sleep", Event);
	    if (Status == AE_OK) {
		if (gen_count == sc->ec_gencount)
		    no_intr++;
		else
		    no_intr = 0;
		break;
	    }
	    gen_count = sc->ec_gencount;
#else
	    if (gen_count != sc->ec_gencount) {
		/*
		 * Record new generation count.  It's possible the GPE was
		 * just to notify us that a query is needed and we need to
		 * wait for a second GPE to signal the completion of the
		 * event we are actually waiting for.
		 */
		gen_count = sc->ec_gencount;
		Status = EcCheckStatus(sc, "sleep", Event);
		if (Status == AE_OK)
		    break;
	    }
	    tsleep(&sc->ec_gencount, PZERO, "ecgpe", slp_ival);
#endif
	}

#ifdef ACPI_LENOVO_S10
	/*
	 * We finished waiting for the GPE and it never arrived.  Try to
	 * read the register once and trust whatever value we got.  This is
	 * the best we can do at this point.
	 */
	if (Status != AE_OK)
	    Status = EcCheckStatus(sc, "sleep_end", Event);
#else
	/*
	 * We finished waiting for the GPE and it never arrived.  Try to
	 * read the register once and trust whatever value we got.  This is
	 * the best we can do at this point.  Then, force polled mode on
	 * since this system doesn't appear to generate GPEs.
	 */
	if (Status != AE_OK) {
	    Status = EcCheckStatus(sc, "sleep_end", Event);
	    device_printf(sc->ec_dev,
		"wait timed out (%sresponse), forcing polled mode\n",
		Status == AE_OK ? "" : "no ");
	    ec_polled_mode = TRUE;
	}
#endif
    }
#ifdef ACPI_LENOVO_S10
    if (!need_poll && no_intr > 10) {
	device_printf(sc->ec_dev,
	    "not getting interrupts, switched to polled mode\n");
	ec_polled_mode = 1;
    }
#endif
#if 0
    if (Status != AE_OK)
	    CTR0(KTR_ACPI, "error: ec wait timed out");
#endif
    return (Status);
}

static ACPI_STATUS
EcCommand(struct acpi_ec_softc *sc, EC_COMMAND cmd)
{
    ACPI_STATUS	status;
    EC_EVENT	event;
    EC_STATUS	ec_status;
    u_int	gen_count;

    ACPI_SERIAL_ASSERT(ec);

    /* Don't use burst mode if user disabled it. */
    if (!ec_burst_mode && cmd == EC_COMMAND_BURST_ENABLE)
	return (AE_ERROR);

    /* Decide what to wait for based on command type. */
    switch (cmd) {
    case EC_COMMAND_READ:
    case EC_COMMAND_WRITE:
    case EC_COMMAND_BURST_DISABLE:
	event = EC_EVENT_INPUT_BUFFER_EMPTY;
	break;
    case EC_COMMAND_QUERY:
    case EC_COMMAND_BURST_ENABLE:
	event = EC_EVENT_OUTPUT_BUFFER_FULL;
	break;
    default:
	device_printf(sc->ec_dev, "EcCommand: invalid command %#x\n", cmd);
	return (AE_BAD_PARAMETER);
    }

#ifdef ACPI_LENOVO_S10
    /*
     * Ensure empty input buffer before issuing command.
     * Use generation count of zero to force a quick check.
     */
    status = EcWaitEvent(sc, EC_EVENT_INPUT_BUFFER_EMPTY, 0);
    if (ACPI_FAILURE(status))
	return (status);
#endif
    /* Run the command and wait for the chosen event. */
#if 0
    CTR1(KTR_ACPI, "ec running command %#x", cmd);
#endif
    gen_count = sc->ec_gencount;
    EC_SET_CSR(sc, cmd);
    status = EcWaitEvent(sc, event, gen_count);
    if (ACPI_SUCCESS(status)) {
	/* If we succeeded, burst flag should now be present. */
	if (cmd == EC_COMMAND_BURST_ENABLE) {
	    ec_status = EC_GET_CSR(sc);
	    if ((ec_status & EC_FLAG_BURST_MODE) == 0)
		status = AE_ERROR;
	}
    } else
	device_printf(sc->ec_dev, "EcCommand: no response to %#x\n", cmd);
    return (status);
}

static ACPI_STATUS
EcRead(struct acpi_ec_softc *sc, UINT8 Address, UINT8 *Data)
{
    ACPI_STATUS	status;
    UINT8 data;
    u_int gen_count;
#ifdef ACPI_LENOVO_S10
    int retry;
#endif

    ACPI_SERIAL_ASSERT(ec);
#if 0
    CTR1(KTR_ACPI, "ec read from %#x", Address);
#endif
    /* If we can't start burst mode, continue anyway. */
    status = EcCommand(sc, EC_COMMAND_BURST_ENABLE);
    if (status == AE_OK) {
	data = EC_GET_DATA(sc);
	if (data == EC_BURST_ACK) {
#if 0
	    CTR0(KTR_ACPI, "ec burst enabled");
#endif
	    sc->ec_burstactive = TRUE;
	}
    }

#ifdef ACPI_LENOVO_S10
/*
 * Modified to try to set ec_burstactive = FALSE always on exit
 */
    for (retry = 0; retry < 2; retry++) {
	status = EcCommand(sc, EC_COMMAND_READ);
	if (ACPI_FAILURE(status)) {
	    if (sc->ec_burstactive) {
		sc->ec_burstactive = FALSE;
		EcCommand(sc, EC_COMMAND_BURST_DISABLE);
    	    }
	    return (status);
	}
#if 0
	if (ACPI_FAILURE(status))
	    return (status);
#endif

	gen_count = sc->ec_gencount;
	EC_SET_DATA(sc, Address);
	status = EcWaitEvent(sc, EC_EVENT_OUTPUT_BUFFER_FULL, gen_count);
	if (ACPI_FAILURE(status)) {
	    if (EcCheckStatus(sc, "retr_check",
		EC_EVENT_INPUT_BUFFER_EMPTY) == AE_OK)
		continue;
	    else
		break;
	}
	*Data = EC_GET_DATA(sc);
	if (sc->ec_burstactive) {
	    sc->ec_burstactive = FALSE;
	    status = EcCommand(sc, EC_COMMAND_BURST_DISABLE);
	    if (ACPI_FAILURE(status))
		return (status);
#if 0
	    CTR0(KTR_ACPI, "ec disabled burst ok");
#endif
	}
	return (AE_OK);
    }
    device_printf(sc->ec_dev, "EcRead: failed waiting to get data\n");
    if (sc->ec_burstactive) {
	sc->ec_burstactive = FALSE;
	EcCommand(sc, EC_COMMAND_BURST_DISABLE);
    }
    return (status);
#else
    status = EcCommand(sc, EC_COMMAND_READ);
    if (ACPI_FAILURE(status))
	return (status);

    gen_count = sc->ec_gencount;
    EC_SET_DATA(sc, Address);
    status = EcWaitEvent(sc, EC_EVENT_OUTPUT_BUFFER_FULL, gen_count);
    if (ACPI_FAILURE(status)) {
	device_printf(sc->ec_dev, "EcRead: failed waiting to get data\n");
	return (status);
    }
    *Data = EC_GET_DATA(sc);

    if (sc->ec_burstactive) {
	sc->ec_burstactive = FALSE;
	status = EcCommand(sc, EC_COMMAND_BURST_DISABLE);
	if (ACPI_FAILURE(status))
	    return (status);
#if 0
	CTR0(KTR_ACPI, "ec disabled burst ok");
#endif
    }

    return (AE_OK);
#endif
}

static ACPI_STATUS
EcWrite(struct acpi_ec_softc *sc, UINT8 Address, UINT8 *Data)
{
    ACPI_STATUS	status;
    UINT8 data;
    u_int gen_count;

    ACPI_SERIAL_ASSERT(ec);
#if 0
    CTR2(KTR_ACPI, "ec write to %#x, data %#x", Address, *Data);
#endif

    /* If we can't start burst mode, continue anyway. */
    status = EcCommand(sc, EC_COMMAND_BURST_ENABLE);
    if (status == AE_OK) {
	data = EC_GET_DATA(sc);
	if (data == EC_BURST_ACK) {
#if 0
	    CTR0(KTR_ACPI, "ec burst enabled");
#endif
	    sc->ec_burstactive = TRUE;
	}
    }

    status = EcCommand(sc, EC_COMMAND_WRITE);
#ifdef ACPI_LENOVO_S10
    if (ACPI_FAILURE(status)) {
	if (sc->ec_burstactive) {
	    sc->ec_burstactive = FALSE;
		EcCommand(sc, EC_COMMAND_BURST_DISABLE);
	}
	return (status);
    }
#else
    if (ACPI_FAILURE(status))
	return (status);
#endif

    gen_count = sc->ec_gencount;
    EC_SET_DATA(sc, Address);
    status = EcWaitEvent(sc, EC_EVENT_INPUT_BUFFER_EMPTY, gen_count);
#ifdef ACPI_LENOVO_S10
    if (ACPI_FAILURE(status)) {
	device_printf(sc->ec_dev, "EcWrite: failed waiting for sent address\n");
	if (sc->ec_burstactive) {
	    sc->ec_burstactive = FALSE;
		EcCommand(sc, EC_COMMAND_BURST_DISABLE);
	}
	return (status);
    }
#else
    if (ACPI_FAILURE(status)) {
	device_printf(sc->ec_dev, "EcRead: failed waiting for sent address\n");
	return (status);
    }
#endif

    gen_count = sc->ec_gencount;
    EC_SET_DATA(sc, *Data);
    status = EcWaitEvent(sc, EC_EVENT_INPUT_BUFFER_EMPTY, gen_count);
#ifdef ACPI_LENOVO_S10
    if (ACPI_FAILURE(status)) {
	device_printf(sc->ec_dev, "EcWrite: failed waiting for sent data\n");
	if (sc->ec_burstactive) {
	    sc->ec_burstactive = FALSE;
		EcCommand(sc, EC_COMMAND_BURST_DISABLE);
	}
	return (status);
    }
#else
    if (ACPI_FAILURE(status)) {
	device_printf(sc->ec_dev, "EcWrite: failed waiting for sent data\n");
	return (status);
    }
#endif

    if (sc->ec_burstactive) {
	sc->ec_burstactive = FALSE;
	status = EcCommand(sc, EC_COMMAND_BURST_DISABLE);
	if (ACPI_FAILURE(status))
	    return (status);
#if 0
	CTR0(KTR_ACPI, "ec disabled burst ok");
#endif
    }

    return (AE_OK);
}
