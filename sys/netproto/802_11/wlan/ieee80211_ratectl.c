/*-
 * Copyright (c) 2010 Rui Paulo <rpaulo@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: head/sys/net80211/ieee80211_ratectl.c 206358 2010-04-07 15:29:13Z rpaulo $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_media.h>

#include <netproto/802_11/ieee80211_var.h>
#include <netproto/802_11/ieee80211_ratectl.h>

static const struct ieee80211_ratectl *ratectls[IEEE80211_RATECTL_MAX];

MALLOC_DEFINE(M_80211_RATECTL, "80211ratectl", "802.11 rate control");

void
ieee80211_ratectl_register(int type, const struct ieee80211_ratectl *ratectl)
{
	if (type >= IEEE80211_RATECTL_MAX)
		return;
	ratectls[type] = ratectl;
}

void
ieee80211_ratectl_unregister(int type)
{
	if (type >= IEEE80211_RATECTL_MAX)
		return;
	ratectls[type] = NULL;
}

void
ieee80211_ratectl_set(struct ieee80211vap *vap, int type)
{
	if (type >= IEEE80211_RATECTL_MAX)
		return;
	vap->iv_rate = ratectls[type];
}
