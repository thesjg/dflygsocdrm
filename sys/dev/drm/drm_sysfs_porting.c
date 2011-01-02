/*
 * Copyright (c) 2010 David Shao <davshao@gmail.com> 
 *
 * DRM sysfs dummy implementation 
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 *
 * Authors:
 *     	David Shao <davshao@gmail.com>
 */
#include "drmP.h"
#include "drm_crtc.h"

struct drm_sysfs_class {
	int placeholder;
};

struct class *drm_sysfs_create(struct module *owner, char *name) {
	return (struct class *)malloc(sizeof(struct class), DRM_MEM_DRIVER, M_WAITOK | M_ZERO);
}

void drm_sysfs_destroy(void) {
	;
}

int drm_sysfs_device_add(struct drm_minor *minor) {
	return 0;
}

void drm_sysfs_hotplug_event(struct drm_device *dev) {
	;
}

void drm_sysfs_device_remove(struct drm_minor *minor) {
	;
}

int drm_sysfs_connector_add(struct drm_connector *connector) {
	return 0;
}

void drm_sysfs_connector_remove(struct drm_connector *connector) {
	;
}
