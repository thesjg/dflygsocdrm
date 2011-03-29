# $DragonFly: src/sys/dev/drm/i915/Makefile,v 1.1 2008/04/05 18:12:29 hasso Exp $

.PATH:	${.CURDIR}
KMOD	= i915
NO_MAN	= YES
SRCS    = \
	i915_dma.c \
	i915_drv.c \
	i915_irq.c \
	i915_mem.c \
	i915_suspend.c \
	dvo_ch7017.c \
	dvo_ch7xxx.c \
	dvo_ivch.c \
	dvo_sil164.c \
	dvo_tfp410.c \
	i915_gem.c \
	i915_gem_tiling.c \
	i915_opregion.c \
	intel_bios.c \
	intel_crt.c \
	intel_display.c \
	intel_dp.c \
	intel_dvo.c \
	intel_fb.c \
	intel_hdmi.c \
	intel_i2c.c \
	intel_lvds.c \
	intel_modes.c \
	intel_overlay.c \
	intel_sdvo.c \
	intel_tv.c

SRCS   += device_if.h bus_if.h pci_if.h iicbb_if.h opt_drm.h
CFLAGS += ${DEBUG_FLAGS} -I. -I.. -I@/dev/drm -I@/dev/drm/i915

SUBDIR =
SUBDIR += i915_iic

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
