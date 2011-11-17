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
 * $DragonFly: src/lib/libkcore/kcore.h,v 1.3 2005/02/03 17:28:40 joerg Exp $
 */

#ifndef _KCORE_H
#define	_KCORE_H

#include <sys/cdefs.h>

#include <kinfo.h>
#include <stddef.h>

#ifdef KCORE_KINFO_WRAPPER

#define	kinfo_get_cpus(cpus)		\
	kcore_get_cpus(NULL, cpus)
#define	kinfo_get_files(files, len)	\
	kcore_get_files(NULL, files, len)
#define	kinfo_get_maxfiles(maxfiles)	\
	kcore_get_maxfiles(NULL, maxfiles)
#define	kinfo_get_openfiles(openfiles)	\
	kcore_get_openfiles(NULL, openfiles)
#define	kinfo_get_sched_ccpu(ccpu)	\
	kcore_get_sched_ccpu(NULL, ccpu)
#define	kinfo_get_sched_cputime(cputime)	\
	kcore_get_sched_cputime(NULL, cputime)
#define	kinfo_get_sched_hz(hz)		\
	kcore_get_sched_hz(NULL, hz)
#define	kinfo_get_sched_profhz(profhz)	\
	kcore_get_sched_profhz(NULL, profhz)
#define	kinfo_get_sched_stathz(stathz)	\
	kcore_get_sched_stathz(NULL, stathz)
#define	kinfo_get_tty_tk_nin(tk_nin)	\
	kcore_get_tty_tk_nin(NULL, tk_nin)
#define	kinfo_get_tty_tk_nout(tk_nout)	\
	kcore_get_tty_tk_nout(NULL, tk_nout)
#define	kinfo_get_vfs_bufspace(bufspace) \
	kcore_get_vfs_bufspace(NULL, bufspace)

#endif /* KCORE_KINFO_WRAPPER */

struct kcore_data;
struct kinfo_proc;

__BEGIN_DECLS;
struct kcore_data
	*kcore_open(const char *, const char *, char *);
int	 kcore_wrapper_open(const char *, const char *, char *);
int	 kcore_close(struct kcore_data *);

int	 kcore_get_cpus(struct kcore_data *, int *);
int	 kcore_get_files(struct kcore_data *, struct kinfo_file **, size_t *);
int	 kcore_get_maxfiles(struct kcore_data *, int *);
int	 kcore_get_openfiles(struct kcore_data *, int *);
int	 kcore_get_procs(struct kcore_data *kc, struct kinfo_proc **procs,
			size_t *len);
int	 kcore_get_sched_ccpu(struct kcore_data *, int *);
int	 kcore_get_sched_cputime(struct kcore_data *, struct kinfo_cputime *);
int	 kcore_get_sched_hz(struct kcore_data *, int *);
int	 kcore_get_sched_profhz(struct kcore_data *, int *);
int	 kcore_get_sched_stathz(struct kcore_data *, int *);
int	 kcore_get_tty_tk_nin(struct kcore_data *, uint64_t *);
int	 kcore_get_tty_tk_nout(struct kcore_data *, uint64_t *);
int	 kcore_get_vfs_bufspace(struct kcore_data *, long *);
__END_DECLS;

#endif
