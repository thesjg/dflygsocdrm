/* mga_warp.c -- Matrox G200/G400 WARP engine management -*- linux-c -*-
 * Created: Thu Jan 11 21:29:32 2001 by gareth@valinux.com
 *
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    Gareth Hughes <gareth@valinux.com>
 */

#ifdef __linux__
#include <linux/firmware.h>
#include <linux/ihex.h>
#include <linux/platform_device.h>
#endif

#include "drmP.h"
#include "drm.h"
#include "mga_drm.h"
#include "mga_drv.h"

#ifdef __linux__
#define FIRMWARE_G200 "matrox/g200_warp.fw"
#define FIRMWARE_G400 "matrox/g400_warp.fw"

MODULE_FIRMWARE(FIRMWARE_G200);
MODULE_FIRMWARE(FIRMWARE_G400);
#else
#include "mga_ucode.h"
#endif

#define MGA_WARP_CODE_ALIGN		256	/* in bytes */

#ifdef __linux__
#define WARP_UCODE_SIZE(size)		ALIGN(size, MGA_WARP_CODE_ALIGN)
#else
#define WARP_UCODE_SIZE( which )					\
	((sizeof(which) / MGA_WARP_CODE_ALIGN + 1) * MGA_WARP_CODE_ALIGN)
#endif

#define WARP_UCODE_INSTALL( which, where )				\
do {									\
	DRM_DEBUG( " pcbase = 0x%08lx  vcbase = %p\n", pcbase, vcbase );\
	dev_priv->warp_pipe_phys[where] = pcbase;			\
	memcpy( vcbase, which, sizeof(which) );				\
	pcbase += WARP_UCODE_SIZE( which );				\
	vcbase += WARP_UCODE_SIZE( which );				\
} while (0)

static const unsigned int mga_warp_g400_microcode_size =
	       (WARP_UCODE_SIZE(warp_g400_tgz) +
		WARP_UCODE_SIZE(warp_g400_tgza) +
		WARP_UCODE_SIZE(warp_g400_tgzaf) +
		WARP_UCODE_SIZE(warp_g400_tgzf) +
		WARP_UCODE_SIZE(warp_g400_tgzs) +
		WARP_UCODE_SIZE(warp_g400_tgzsa) +
		WARP_UCODE_SIZE(warp_g400_tgzsaf) +
		WARP_UCODE_SIZE(warp_g400_tgzsf) +
		WARP_UCODE_SIZE(warp_g400_t2gz) +
		WARP_UCODE_SIZE(warp_g400_t2gza) +
		WARP_UCODE_SIZE(warp_g400_t2gzaf) +
		WARP_UCODE_SIZE(warp_g400_t2gzf) +
		WARP_UCODE_SIZE(warp_g400_t2gzs) +
		WARP_UCODE_SIZE(warp_g400_t2gzsa) +
		WARP_UCODE_SIZE(warp_g400_t2gzsaf) +
		WARP_UCODE_SIZE(warp_g400_t2gzsf));

static const unsigned int mga_warp_g200_microcode_size =
	       (WARP_UCODE_SIZE(warp_g200_tgz) +
		WARP_UCODE_SIZE(warp_g200_tgza) +
		WARP_UCODE_SIZE(warp_g200_tgzaf) +
		WARP_UCODE_SIZE(warp_g200_tgzf) +
		WARP_UCODE_SIZE(warp_g200_tgzs) +
		WARP_UCODE_SIZE(warp_g200_tgzsa) +
		WARP_UCODE_SIZE(warp_g200_tgzsaf) +
		WARP_UCODE_SIZE(warp_g200_tgzsf));


unsigned int mga_warp_microcode_size(const drm_mga_private_t * dev_priv)
{
	switch (dev_priv->chipset) {
	case MGA_CARD_TYPE_G400:
	case MGA_CARD_TYPE_G550:
		return PAGE_ALIGN(mga_warp_g400_microcode_size);
	case MGA_CARD_TYPE_G200:
		return PAGE_ALIGN(mga_warp_g200_microcode_size);
	default:
		DRM_ERROR("Unknown chipset value: 0x%x\n", dev_priv->chipset);
		return 0;
	}
}

static int mga_warp_install_g400_microcode(drm_mga_private_t * dev_priv)
{
	unsigned char *vcbase = dev_priv->warp->handle;
	unsigned long pcbase = dev_priv->warp->offset;

	memset(dev_priv->warp_pipe_phys, 0, sizeof(dev_priv->warp_pipe_phys));

	WARP_UCODE_INSTALL(warp_g400_tgz, MGA_WARP_TGZ);
	WARP_UCODE_INSTALL(warp_g400_tgzf, MGA_WARP_TGZF);
	WARP_UCODE_INSTALL(warp_g400_tgza, MGA_WARP_TGZA);
	WARP_UCODE_INSTALL(warp_g400_tgzaf, MGA_WARP_TGZAF);
	WARP_UCODE_INSTALL(warp_g400_tgzs, MGA_WARP_TGZS);
	WARP_UCODE_INSTALL(warp_g400_tgzsf, MGA_WARP_TGZSF);
	WARP_UCODE_INSTALL(warp_g400_tgzsa, MGA_WARP_TGZSA);
	WARP_UCODE_INSTALL(warp_g400_tgzsaf, MGA_WARP_TGZSAF);

	WARP_UCODE_INSTALL(warp_g400_t2gz, MGA_WARP_T2GZ);
	WARP_UCODE_INSTALL(warp_g400_t2gzf, MGA_WARP_T2GZF);
	WARP_UCODE_INSTALL(warp_g400_t2gza, MGA_WARP_T2GZA);
	WARP_UCODE_INSTALL(warp_g400_t2gzaf, MGA_WARP_T2GZAF);
	WARP_UCODE_INSTALL(warp_g400_t2gzs, MGA_WARP_T2GZS);
	WARP_UCODE_INSTALL(warp_g400_t2gzsf, MGA_WARP_T2GZSF);
	WARP_UCODE_INSTALL(warp_g400_t2gzsa, MGA_WARP_T2GZSA);
	WARP_UCODE_INSTALL(warp_g400_t2gzsaf, MGA_WARP_T2GZSAF);

	return 0;
}

static int mga_warp_install_g200_microcode(drm_mga_private_t * dev_priv)
{
	unsigned char *vcbase = dev_priv->warp->handle;
	unsigned long pcbase = dev_priv->warp->offset;

	memset(dev_priv->warp_pipe_phys, 0, sizeof(dev_priv->warp_pipe_phys));

	WARP_UCODE_INSTALL(warp_g200_tgz, MGA_WARP_TGZ);
	WARP_UCODE_INSTALL(warp_g200_tgzf, MGA_WARP_TGZF);
	WARP_UCODE_INSTALL(warp_g200_tgza, MGA_WARP_TGZA);
	WARP_UCODE_INSTALL(warp_g200_tgzaf, MGA_WARP_TGZAF);
	WARP_UCODE_INSTALL(warp_g200_tgzs, MGA_WARP_TGZS);
	WARP_UCODE_INSTALL(warp_g200_tgzsf, MGA_WARP_TGZSF);
	WARP_UCODE_INSTALL(warp_g200_tgzsa, MGA_WARP_TGZSA);
	WARP_UCODE_INSTALL(warp_g200_tgzsaf, MGA_WARP_TGZSAF);

	return 0;
}

int mga_warp_install_microcode(drm_mga_private_t * dev_priv)
{
#ifdef __linux__
	unsigned char *vcbase = dev_priv->warp->handle;
	unsigned long pcbase = dev_priv->warp->offset;
	const char *firmware_name;
	struct platform_device *pdev;
	const struct firmware *fw = NULL;
	const struct ihex_binrec *rec;
	unsigned int size;
	int n_pipes, where;
	int rc = 0;
#else /* !__linux__ */
	const unsigned int size = mga_warp_microcode_size(dev_priv);

	DRM_DEBUG("MGA ucode size = %d bytes\n", size);
	if (size > dev_priv->warp->size) {
		DRM_ERROR("microcode too large! (%u > %lu)\n",
			  size, dev_priv->warp->size);
		return -ENOMEM;
	}
#endif /* !__linux__ */

	switch (dev_priv->chipset) {
	case MGA_CARD_TYPE_G400:
	case MGA_CARD_TYPE_G550:
#ifdef __linux__
		firmware_name = FIRMWARE_G400;
		n_pipes = MGA_MAX_G400_PIPES;
		break;
#else
		return mga_warp_install_g400_microcode(dev_priv);
#endif
	case MGA_CARD_TYPE_G200:
#ifdef __linux__
		firmware_name = FIRMWARE_G200;
		n_pipes = MGA_MAX_G200_PIPES;
		break;
#else
		return mga_warp_install_g200_microcode(dev_priv);
#endif
	default:
		return -EINVAL;
	}

#ifdef __linux__
	pdev = platform_device_register_simple("mga_warp", 0, NULL, 0);
	if (IS_ERR(pdev)) {
		DRM_ERROR("mga: Failed to register microcode\n");
		return PTR_ERR(pdev);
	}
	rc = request_ihex_firmware(&fw, firmware_name, &pdev->dev);
	platform_device_unregister(pdev);
	if (rc) {
		DRM_ERROR("mga: Failed to load microcode \"%s\"\n",
			  firmware_name);
		return rc;
	}

	size = 0;
	where = 0;
	for (rec = (const struct ihex_binrec *)fw->data;
	     rec;
	     rec = ihex_next_binrec(rec)) {
		size += WARP_UCODE_SIZE(be16_to_cpu(rec->len));
		where++;
	}

	if (where != n_pipes) {
		DRM_ERROR("mga: Invalid microcode \"%s\"\n", firmware_name);
		rc = -EINVAL;
		goto out;
	}
	size = PAGE_ALIGN(size);
	DRM_DEBUG("MGA ucode size = %d bytes\n", size);
	if (size > dev_priv->warp->size) {
		DRM_ERROR("microcode too large! (%u > %lu)\n",
			  size, dev_priv->warp->size);
		rc = -ENOMEM;
		goto out;
	}

	memset(dev_priv->warp_pipe_phys, 0, sizeof(dev_priv->warp_pipe_phys));

	where = 0;
	for (rec = (const struct ihex_binrec *)fw->data;
	     rec;
	     rec = ihex_next_binrec(rec)) {
		unsigned int src_size, dst_size;

		DRM_DEBUG(" pcbase = 0x%08lx  vcbase = %p\n", pcbase, vcbase);
		dev_priv->warp_pipe_phys[where] = pcbase;
		src_size = be16_to_cpu(rec->len);
		dst_size = WARP_UCODE_SIZE(src_size);
		memcpy(vcbase, rec->data, src_size);
		pcbase += dst_size;
		vcbase += dst_size;
		where++;
	}

out:
	release_firmware(fw);
	return rc;
#endif /* __linux__ */
}

#define WMISC_EXPECTED		(MGA_WUCODECACHE_ENABLE | MGA_WMASTER_ENABLE)

int mga_warp_init(drm_mga_private_t * dev_priv)
{
	u32 wmisc;

	/* FIXME: Get rid of these damned magic numbers...
	 */
	switch (dev_priv->chipset) {
	case MGA_CARD_TYPE_G400:
	case MGA_CARD_TYPE_G550:
		MGA_WRITE(MGA_WIADDR2, MGA_WMODE_SUSPEND);
		MGA_WRITE(MGA_WGETMSB, 0x00000E00);
		MGA_WRITE(MGA_WVRTXSZ, 0x00001807);
		MGA_WRITE(MGA_WACCEPTSEQ, 0x18000000);
		break;
	case MGA_CARD_TYPE_G200:
		MGA_WRITE(MGA_WIADDR, MGA_WMODE_SUSPEND);
		MGA_WRITE(MGA_WGETMSB, 0x1606);
		MGA_WRITE(MGA_WVRTXSZ, 7);
		break;
	default:
		return -EINVAL;
	}

	MGA_WRITE(MGA_WMISC, (MGA_WUCODECACHE_ENABLE |
			      MGA_WMASTER_ENABLE | MGA_WCACHEFLUSH_ENABLE));
	wmisc = MGA_READ(MGA_WMISC);
	if (wmisc != WMISC_EXPECTED) {
		DRM_ERROR("WARP engine config failed! 0x%x != 0x%x\n",
			  wmisc, WMISC_EXPECTED);
		return -EINVAL;
	}

	return 0;
}
