# $DragonFly: src/sys/dev/drm/sis/Makefile,v 1.1 2008/04/05 18:12:30 hasso Exp $

.PATH:	${.CURDIR}
KMOD= 	sis
SRCS= \
	sis_drv.c \
	sis_ds.c \
	sis_mm.c

SRCS+=	device_if.h bus_if.h pci_if.h opt_drm.h
CFLAGS+=	${DEBUG_FLAGS} -I. -I.. -I@/dev/drm -I@/dev/drm/sis

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
