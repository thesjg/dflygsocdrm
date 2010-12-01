/*
 * Copryight 1997 Sean Eric Fagan
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Sean Eric Fagan
 * 4. Neither the name of the author may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
 * $FreeBSD: src/usr.bin/truss/extern.h,v 1.1.2.1 2002/02/15 11:43:51 des Exp $
 * $DragonFly: src/usr.bin/truss/extern.h,v 1.4 2005/05/28 00:22:04 swildner Exp $
 */

#include <stdio.h>

char procfs_path[FILENAME_MAX];
int have_procfs;

extern int Procfd;

extern int setup_and_wait(char **);
extern int start_tracing(int, int);
extern void restore_proc(int);
extern const char *ioctlname(register_t val);
#ifdef __i386__
extern void i386_syscall_entry(struct trussinfo *, int);
extern int i386_syscall_exit(struct trussinfo *, int);
extern void i386_linux_syscall_entry(struct trussinfo *, int);
extern int i386_linux_syscall_exit(struct trussinfo *, int);
#endif
#ifdef __x86_64__
extern void x86_64_syscall_entry(struct trussinfo *, int);
extern int x86_64_syscall_exit(struct trussinfo *, int);
#endif
