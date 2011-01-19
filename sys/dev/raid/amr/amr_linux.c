/*-
 * Copyright (c) 2005 Paul Saab
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
 * $FreeBSD: src/sys/dev/amr/amr_linux.c,v 1.5 2009/05/20 17:29:21 imp Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/file.h>
#include <sys/proc.h>

#if defined(__amd64__) /* Assume amd64 wants 32 bit Linux */
#include <machine/../linux32/linux.h>
#include <machine/../linux32/linux32_proto.h>
#else
#include <emulation/linux/i386/linux.h>
#include <emulation/linux/i386/linux_proto.h>
#endif
#include <emulation/linux/linux_ioctl.h>

/* There are multiple ioctl number ranges that need to be handled */
#define AMR_LINUX_IOCTL_MIN  0x6d00
#define AMR_LINUX_IOCTL_MAX  0x6d01

static linux_ioctl_function_t amr_linux_ioctl;
static struct linux_ioctl_handler amr_linux_handler = {amr_linux_ioctl,
						       AMR_LINUX_IOCTL_MIN,
						       AMR_LINUX_IOCTL_MAX};

SYSINIT  (amr_register,   SI_SUB_KLD, SI_ORDER_MIDDLE,
	  linux_ioctl_register_handler, &amr_linux_handler);
SYSUNINIT(amr_unregister, SI_SUB_KLD, SI_ORDER_MIDDLE,
	  linux_ioctl_unregister_handler, &amr_linux_handler);

static int
amr_linux_modevent(module_t mod, int cmd, void *data)
{
	return (0);
}

DEV_MODULE(amr_linux, amr_linux_modevent, NULL);
MODULE_DEPEND(amr, linux, 1, 1, 1);

static int
amr_linux_ioctl(struct thread *p, struct linux_ioctl_args *args)
{
	struct file *fp;
	int error;

	if ((error = fget(p, args->fd, &fp)) != 0)
		return (error);
	error = fo_ioctl(fp, args->cmd, (caddr_t)args->arg, p->td_ucred, p);
	fdrop(fp, p);
	return (error);
}
