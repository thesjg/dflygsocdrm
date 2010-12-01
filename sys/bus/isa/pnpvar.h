/*-
 * Copyright (c) 1999 Doug Rabson
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
 * $FreeBSD: src/sys/isa/pnpvar.h,v 1.6 2001/09/05 03:54:28 yokota Exp $
 * $DragonFly: src/sys/bus/isa/pnpvar.h,v 1.3 2003/11/08 02:55:16 dillon Exp $
 */

#ifndef _ISA_PNPVAR_H_
#define _ISA_PNPVAR_H_

#ifdef _KERNEL

#if 0
void    pnp_write(int d, u_char r); /* used by Luigi's sound driver */
u_char  pnp_read(int d); /* currently unused, but who knows... */
#endif

#define PNP_HEXTONUM(c)	((c) >= 'a'		\
			 ? (c) - 'a' + 10	\
			 : ((c) >= 'A'		\
			    ? (c) - 'A' + 10	\
			    : (c) - '0'))

#define PNP_EISAID(s)				\
	((((s[0] - '@') & 0x1f) << 2)		\
	 | (((s[1] - '@') & 0x18) >> 3)		\
	 | (((s[1] - '@') & 0x07) << 13)	\
	 | (((s[2] - '@') & 0x1f) << 8)		\
	 | (PNP_HEXTONUM(s[4]) << 16)		\
	 | (PNP_HEXTONUM(s[3]) << 20)		\
	 | (PNP_HEXTONUM(s[6]) << 24)		\
	 | (PNP_HEXTONUM(s[5]) << 28))

struct isa_config;

typedef int pnp_scan_cb(device_t dev, u_char tag, u_char *res, int len,
			struct isa_config *config, int ldn);

char *pnp_eisaformat(u_int32_t id);
void pnp_printf(u_int32_t id, char *fmt, ...) __printflike(2, 3);
void pnp_parse_resources(device_t dev, u_char *resources, int len, int ldn);
u_char *pnp_parse_dependant(device_t dev, u_char *resources, int len,
			    struct isa_config *config, int ldn);
u_char *pnp_scan_resources(device_t dev, u_char *resources, int len,
			   struct isa_config *config, int ldn, pnp_scan_cb *cb);

void pnp_check_quirks(u_int32_t vendor_id, u_int32_t logical_id, int ldn, struct isa_config *config);

#endif /* _KERNEL */

#endif /* !_ISA_PNPVAR_H_ */
