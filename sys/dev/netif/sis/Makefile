# $FreeBSD: src/sys/modules/sis/Makefile,v 1.6 2000/01/28 11:26:35 bde Exp $
# $DragonFly: src/sys/dev/netif/sis/Makefile,v 1.5 2006/06/25 11:02:39 corecode Exp $

KMOD	= if_sis
SRCS	= if_sis.c device_if.h bus_if.h pci_if.h
SRCS	+= opt_polling.h
SRCS	+= miibus_if.h

.ifndef BUILDING_WITH_KERNEL
opt_polling.h:
	echo '#define DEVICE_POLLING 1' > ${.OBJDIR}/${.TARGET}
.endif

.include <bsd.kmod.mk>
