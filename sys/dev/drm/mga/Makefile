# $DragonFly: src/sys/dev/drm/mga/Makefile,v 1.3 2008/04/05 18:12:29 hasso Exp $

.PATH:	${.CURDIR}
KMOD= 	mga
SRCS= \
	mga_dma.c \
	mga_drv.c \
	mga_irq.c \
	mga_state.c \
	mga_warp.c

SRCS+=	device_if.h bus_if.h pci_if.h opt_drm.h
CFLAGS+=	${DEBUG_FLAGS} -I. -I.. -I@/dev/drm -I@/dev/drm/mga

.if defined(DRM_DEBUG)
DRM_DEBUG_OPT= "\#define DRM_DEBUG 1"
.endif

.if !defined(DRM_NOLINUX)
DRM_LINUX_OPT= "\#define DRM_LINUX 1"
.endif

opt_drm.h:
	touch ${.TARGET}
	echo $(DRM_DEBUG_OPT) >> ${.TARGET}
	echo $(DRM_LINUX_OPT) >> ${.TARGET}

.include <bsd.kmod.mk>
