/*
 * Copyright (C) 2005 David Xu <davidxu@freebsd.org>.
 * Copyright (c) 2003 Daniel Eischen <deischen@freebsd.org>.
 * Copyright (C) 2000 Jason Evans <jasone@freebsd.org>.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice(s), this list of conditions and the following disclaimer as
 *    the first lines of this file unmodified other than the possible
 *    addition of one or more copyright notices.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice(s), this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $DragonFly: src/lib/libthread_xu/thread/thr_syscalls.c,v 1.8 2008/01/10 22:30:27 nth Exp $
 */

/*
 * Copyright (c) 1995-1998 John Birrell <jb@cimlogic.com.au>
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by John Birrell.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JOHN BIRRELL AND CONTRIBUTORS ``AS IS'' AND
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
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <machine/tls.h>

#include <aio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>

#include "thr_private.h"

extern int	__creat(const char *, mode_t);
extern int	__pause(void);
extern int	__sys_pselect(int, fd_set *, fd_set *, fd_set *,
			const struct timespec *, const sigset_t *);
extern unsigned	__sleep(unsigned int);
extern int	__system(const char *);
extern int	__tcdrain(int);
extern int	__usleep(unsigned);
extern pid_t	__wait(int *);
extern pid_t	__waitpid(pid_t, int *, int);
extern int	__sys_aio_suspend(const struct aiocb * const[], int,
			const struct timespec *);
extern int	__sys_accept(int, struct sockaddr *, socklen_t *);
extern int	__sys_connect(int, const struct sockaddr *, socklen_t);
extern int	__sys_fsync(int);
extern int	__sys_msync(void *, size_t, int);
extern int	__sys_poll(struct pollfd *, unsigned, int);
extern ssize_t	__sys_recv(int, void *, size_t, int);
extern ssize_t	__sys_recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *);
extern ssize_t	__sys_recvmsg(int, struct msghdr *, int);
extern int	__sys_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
extern int	__sys_sendfile(int, int, off_t, size_t, struct sf_hdtr *,
			off_t *, int);
extern ssize_t	__sys_sendmsg(int, const struct msghdr *, int);
extern ssize_t	__sys_sendto(int, const void *,size_t, int, const struct sockaddr *, socklen_t);
extern ssize_t	__sys_readv(int, const struct iovec *, int);
extern pid_t	__sys_wait4(pid_t, int *, int, struct rusage *);
extern ssize_t	__sys_writev(int, const struct iovec *, int);

int	___creat(const char *, mode_t);
int	___usleep(unsigned);
int	__accept(int, struct sockaddr *, socklen_t *);
int	__close(int);
int	__connect(int, const struct sockaddr *, socklen_t);
int	__fcntl(int, int,...);
int	__fsync(int);
int	__msync(void *, size_t, int);
int	__nanosleep(const struct timespec *, struct timespec *);
int	__open(const char *, int,...);
int	__openat(int fd, const char *, int,...);
int	__poll(struct pollfd *, unsigned int, int);
ssize_t	__read(int, void *buf, size_t);
ssize_t	__readv(int, const struct iovec *, int);
ssize_t	__recvfrom(int, void *, size_t, int f, struct sockaddr *, socklen_t *);
ssize_t	__recvmsg(int, struct msghdr *, int);
int	__select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
ssize_t	__sendmsg(int, const struct msghdr *, int);
ssize_t	__sendto(int, const void *, size_t, int,
		const struct sockaddr *, socklen_t);
pid_t	__wait4(pid_t, int *, int, struct rusage *);
ssize_t	__write(int, const void *, size_t);
ssize_t	__writev(int, const struct iovec *, int);
int	_aio_suspend(const struct aiocb * const iocbs[], int,
		const struct timespec *);
int	_pause(void);
int	__pselect(int, fd_set *, fd_set *, fd_set *,
		const struct timespec *, const sigset_t *);
int	_raise(int);
unsigned	_sleep(unsigned);
int	_system(const char *);
int	_tcdrain(int);
int	_vfork(void);
pid_t	_wait(int *);
pid_t	_waitpid(pid_t wpid, int *status, int options);

int
__accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	struct pthread *curthread;
	int oldcancel;
	int ret;

	curthread = tls_get_curthread();
	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_accept(s, addr, addrlen);
	_thr_cancel_leave(curthread, oldcancel);

 	return (ret);
}

__strong_reference(__accept, accept);

int
_aio_suspend(const struct aiocb * const iocbs[], int niocb, const struct
    timespec *timeout)
{
	struct pthread *curthread = tls_get_curthread();
	int oldcancel;
	int ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_aio_suspend(iocbs, niocb, timeout);
	_thr_cancel_leave(curthread, oldcancel);

	return (ret);
}

__strong_reference(_aio_suspend, aio_suspend);

int
__close(int fd)
{
	struct pthread	*curthread = tls_get_curthread();
	int	oldcancel;
	int	ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_close(fd);
	_thr_cancel_leave(curthread, oldcancel);
	
	return (ret);
}

__strong_reference(__close, close);

int
__connect(int fd, const struct sockaddr *name, socklen_t namelen)
{
	struct pthread *curthread = tls_get_curthread();
	int oldcancel;
	int ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_connect(fd, name, namelen);
	_thr_cancel_leave(curthread, oldcancel);

 	return (ret);
}

__strong_reference(__connect, connect);

int
___creat(const char *path, mode_t mode)
{
	struct pthread *curthread = tls_get_curthread();
	int oldcancel;
	int ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __creat(path, mode);
	_thr_cancel_leave(curthread, oldcancel);
	
	return ret;
}

__strong_reference(___creat, creat);

int
__fcntl(int fd, int cmd,...)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	int	ret;
	va_list	ap;
	
	oldcancel = _thr_cancel_enter(curthread);

	va_start(ap, cmd);
	switch (cmd) {
	case F_DUPFD:
		ret = __sys_fcntl(fd, cmd, va_arg(ap, int));
		break;
	case F_SETFD:
	case F_SETFL:
		ret = __sys_fcntl(fd, cmd, va_arg(ap, int));
		break;
	case F_GETFD:
	case F_GETFL:
		ret = __sys_fcntl(fd, cmd);
		break;
	default:
		ret = __sys_fcntl(fd, cmd, va_arg(ap, void *));
	}
	va_end(ap);

	_thr_cancel_leave(curthread, oldcancel);

	return (ret);
}

__strong_reference(__fcntl, fcntl);

int
__fsync(int fd)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	int	ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_fsync(fd);
	_thr_cancel_leave(curthread, oldcancel);

	return (ret);
}

__strong_reference(__fsync, fsync);

int
__msync(void *addr, size_t len, int flags)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	int	ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_msync(addr, len, flags);
	_thr_cancel_leave(curthread, oldcancel);

	return ret;
}

__strong_reference(__msync, msync);

int
__nanosleep(const struct timespec *time_to_sleep,
    struct timespec *time_remaining)
{
	struct pthread *curthread = tls_get_curthread();
	int		oldcancel;
	int		ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_nanosleep(time_to_sleep, time_remaining);
	_thr_cancel_leave(curthread, oldcancel);

	return (ret);
}

__strong_reference(__nanosleep, nanosleep);

int
__open(const char *path, int flags,...)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	int	ret;
	int	mode = 0;
	va_list	ap;

	oldcancel = _thr_cancel_enter(curthread);
	
	/* Check if the file is being created: */
	if (flags & O_CREAT) {
		/* Get the creation mode: */
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	
	ret = __sys_open(path, flags, mode);

	_thr_cancel_leave(curthread, oldcancel);

	return ret;
}

__strong_reference(__open, open);

int
__openat(int fd, const char *path, int flags,...)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	int	ret;
	int	mode = 0;
	va_list	ap;

	oldcancel = _thr_cancel_enter(curthread);
	
	/* Check if the file is being created: */
	if (flags & O_CREAT) {
		/* Get the creation mode: */
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	
	ret = __sys_openat(fd, path, flags, mode);

	_thr_cancel_leave(curthread, oldcancel);

	return ret;
}

__strong_reference(__openat, openat);

int
_pause(void)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	int	ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __pause();
	_thr_cancel_leave(curthread, oldcancel);
	
	return ret;
}

__strong_reference(_pause, pause);

int
__poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
	struct pthread *curthread = tls_get_curthread();
	int oldcancel;
	int ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_poll(fds, nfds, timeout);
	_thr_cancel_leave(curthread, oldcancel);

	return ret;
}

__strong_reference(__poll, poll);

int 
__pselect(int count, fd_set *rfds, fd_set *wfds, fd_set *efds,
	const struct timespec *timo, const sigset_t *mask)
{
	struct pthread *curthread = tls_get_curthread();
	int oldcancel;
	int ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_pselect(count, rfds, wfds, efds, timo, mask);
	_thr_cancel_leave(curthread, oldcancel);

	return (ret);
}
__strong_reference(__pselect, pselect);


int
_raise(int sig)
{
	int ret;

	if (!_thr_isthreaded())
		ret = kill(getpid(), sig);
	else
		ret = _thr_send_sig(tls_get_curthread(), sig);
	return (ret);
}

__strong_reference(_raise, raise);

ssize_t
__read(int fd, void *buf, size_t nbytes)
{
	struct pthread *curthread = tls_get_curthread();
	int oldcancel;
	ssize_t	ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_read(fd, buf, nbytes);
	_thr_cancel_leave(curthread, oldcancel);

	return ret;
}

__strong_reference(__read, read);

ssize_t
__readv(int fd, const struct iovec *iov, int iovcnt)
{
	struct pthread *curthread = tls_get_curthread();
	int oldcancel;
	ssize_t ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_readv(fd, iov, iovcnt);
	_thr_cancel_leave(curthread, oldcancel);

	return ret;
}

__strong_reference(__readv, readv);

ssize_t
__recvfrom(int s, void *b, size_t l, int f, struct sockaddr *from,
    socklen_t *fl)
{
	struct pthread *curthread = tls_get_curthread();
	int oldcancel;
	ssize_t ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_recvfrom(s, b, l, f, from, fl);
	_thr_cancel_leave(curthread, oldcancel);
	return (ret);
}

__strong_reference(__recvfrom, recvfrom);

ssize_t
__recvmsg(int s, struct msghdr *m, int f)
{
	struct pthread *curthread = tls_get_curthread();
	ssize_t ret;
	int oldcancel;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_recvmsg(s, m, f);
	_thr_cancel_leave(curthread, oldcancel);
	return (ret);
}

__strong_reference(__recvmsg, recvmsg);

int 
__select(int numfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	struct timeval *timeout)
{
	struct pthread *curthread = tls_get_curthread();
	int oldcancel;
	int ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_select(numfds, readfds, writefds, exceptfds, timeout);
	_thr_cancel_leave(curthread, oldcancel);
	return ret;
}

__strong_reference(__select, select);

ssize_t
__sendmsg(int s, const struct msghdr *m, int f)
{
	struct pthread *curthread = tls_get_curthread();
	ssize_t ret;
	int oldcancel;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_sendmsg(s, m, f);
	_thr_cancel_leave(curthread, oldcancel);
	return (ret);
}

__strong_reference(__sendmsg, sendmsg);

ssize_t
__sendto(int s, const void *m, size_t l, int f, const struct sockaddr *t,
    socklen_t tl)
{
	struct pthread *curthread = tls_get_curthread();
	ssize_t ret;
	int oldcancel;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_sendto(s, m, l, f, t, tl);
	_thr_cancel_leave(curthread, oldcancel);
	return (ret);
}

__strong_reference(__sendto, sendto);

unsigned int
_sleep(unsigned int seconds)
{
	struct pthread *curthread = tls_get_curthread();
	int		oldcancel;
	unsigned int	ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sleep(seconds);
	_thr_cancel_leave(curthread, oldcancel);
	
	return (ret);
}

int
_system(const char *string)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	int	ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __system(string);
	_thr_cancel_leave(curthread, oldcancel);
	
	return ret;
}

__strong_reference(_system, system);

int
_tcdrain(int fd)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	int	ret;
	
	oldcancel = _thr_cancel_enter(curthread);
	ret = __tcdrain(fd);
	_thr_cancel_leave(curthread, oldcancel);

	return (ret);
}

__strong_reference(_tcdrain, tcdrain);

int
___usleep(unsigned int useconds)
{
	struct pthread *curthread = tls_get_curthread();
	int		oldcancel;
	int		ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __usleep(useconds);
	_thr_cancel_leave(curthread, oldcancel);
	
	return (ret);
}

__strong_reference(___usleep, usleep);

int
_vfork(void)
{
	return (fork());
}

__strong_reference(_vfork, vfork);

pid_t
_wait(int *istat)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	pid_t	ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __wait(istat);
	_thr_cancel_leave(curthread, oldcancel);

	return ret;
}

__strong_reference(_wait, wait);

pid_t
__wait4(pid_t pid, int *istat, int options, struct rusage *rusage)
{
	struct pthread *curthread = tls_get_curthread();
	int oldcancel;
	pid_t ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_wait4(pid, istat, options, rusage);
	_thr_cancel_leave(curthread, oldcancel);

	return ret;
}

__strong_reference(__wait4, wait4);

pid_t
_waitpid(pid_t wpid, int *status, int options)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	pid_t	ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __waitpid(wpid, status, options);
	_thr_cancel_leave(curthread, oldcancel);
	
	return ret;
}

__strong_reference(_waitpid, waitpid);

ssize_t
__write(int fd, const void *buf, size_t nbytes)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	ssize_t	ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_write(fd, buf, nbytes);
	_thr_cancel_leave(curthread, oldcancel);

	return ret;
}

__strong_reference(__write, write);

ssize_t
__writev(int fd, const struct iovec *iov, int iovcnt)
{
	struct pthread *curthread = tls_get_curthread();
	int	oldcancel;
	ssize_t ret;

	oldcancel = _thr_cancel_enter(curthread);
	ret = __sys_writev(fd, iov, iovcnt);
	_thr_cancel_leave(curthread, oldcancel);

	return ret;
}

__strong_reference(__writev, writev);

