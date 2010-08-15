.PATH:	${.CURDIR}/..
KMOD	= i915_iic
NO_MAN	= YES
SRCS	= intel_i2c_legacy.c intel_drv.h \
	  device_if.h bus_if.h pci_if.h iicbb_if.h opt_drm.h

CFLAGS += ${DEBUG_FLAGS} -I. -I.. -I... -I@/dev/drm -I@/dev/drm/i915

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
