# $DragonFly: src/sys/dev/drm/drm/Makefile,v 1.1 2008/04/05 18:12:29 hasso Exp $

.PATH:	${.CURDIR}/../porting ${.CURDIR}/..
KMOD	= drm
NO_MAN	= YES
SRCS    = \
	drm_porting_subr_hash.c \
	drm_porting_layer.c \
	ati_pcigart.c \
	drm_agpsupport.c \
	drm_auth.c \
	drm_buffer.c \
	drm_bufs.c \
	drm_cache.c \
	drm_context.c \
	drm_crtc.c \
	drm_crtc_helper.c \
	drm_dma.c \
	drm_dp_i2c_helper.c \
	drm_drawable.c \
	drm_drv.c \
	drm_encoder_slave.c \
	drm_edid.c \
	drm_fb_helper.c \
	drm_fops.c \
	drm_gem.c \
	drm_hashtab.c \
	drm_info.c \
	drm_ioctl.c \
	drm_irq.c \
	drm_lock.c \
	drm_memory.c \
	drm_mm.c \
	drm_modes.c \
	drm_pci.c \
	drm_proc.c \
	drm_scatter.c \
	drm_sman.c \
	drm_stub.c \
	drm_sysctl.c \
	drm_sysfs_porting.c \
	drm_vm.c

SRCS   += device_if.h bus_if.h pci_if.h iicbb_if.h iicbus_if.h opt_drm.h
CFLAGS += ${DEBUG_FLAGS} -I. -I.. -I/@dev/drm

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
