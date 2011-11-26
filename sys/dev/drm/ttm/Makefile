# $DragonFly: src/sys/dev/drm/ttm/Makefile,v 1.3 2010/06/09 davshao Exp $

.PATH:	${.CURDIR}
KMOD	= ttm
NO_MAN	= YES
SRCS    = \
	ttm_agp_backend.c \
	ttm_bo.c \
	ttm_bo_util.c \
	ttm_bo_vm.c \
	ttm_execbuf_util.c \
	ttm_global.c \
	ttm_lock.c \
	ttm_memory.c \
	ttm_module.c \
	ttm_object.c \
	ttm_tt.c

SRCS   += device_if.h bus_if.h pci_if.h opt_drm.h
CFLAGS += ${DEBUG_FLAGS} -I. -I.. -I@/dev/drm -I@/dev/drm/ttm

.if ${CC} != "icc"
CFLAGS += --param large-function-growth=1000
.endif

.if defined(DRM_DEBUG)
DRM_DEBUG_OPT= "\#define DRM_DEBUG 1"
.endif

.if !defined(DRM_NOLINUX)
DRM_LINUX_OPT= "\#define DRM_LINUX 1"
.endif

opt_drm.h:
	touch opt_drm.h
	echo $(DRM_DEBUG_OPT) >> opt_drm.h
	echo $(DRM_LINUX_OPT) >> opt_drm.h

.include <bsd.kmod.mk>
