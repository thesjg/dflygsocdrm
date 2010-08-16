/*
 * Copyright (c) 2004 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Joerg Sonnenberger <joerg@bec.de>.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * $DragonFly: src/lib/libkcore/kcore_tty.c,v 1.1 2004/12/22 11:01:49 joerg Exp $
 */

#include <sys/kinfo.h>
#include <sys/param.h>

#include <err.h>
#include <errno.h>
#include <kcore.h>
#include <kvm.h>
#include <nlist.h>

#include "kcore_private.h"

int
kcore_get_tty_tk_nin(struct kcore_data *kc, uint64_t *tk_nin)
{
	static struct nlist nl[] = {
		{ "_tk_nin", 0, 0, 0, 0},
		{ NULL, 0, 0, 0, 0}
	};

	return(kcore_get_generic(kc, nl, tk_nin, sizeof(*tk_nin)));
}

int
kcore_get_tty_tk_nout(struct kcore_data *kc, uint64_t *tk_nout)
{
	static struct nlist nl[] = {
		{ "_tk_nout", 0, 0, 0, 0},
		{ NULL, 0, 0, 0, 0}
	};

	return(kcore_get_generic(kc, nl, tk_nout, sizeof(*tk_nout)));
}
