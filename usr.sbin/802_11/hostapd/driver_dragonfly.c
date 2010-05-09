/*
 * Host AP - driver interaction with BSD net80211 layer
 * Copyright (c) 2004, Sam Leffler <sam@errno.com>
 * Copyright (c) 2004, 2Wire, Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 *
 * $FreeBSD: head/usr.sbin/wpa/hostapd/driver_freebsd.c 193524 2009-06-05 17:19:55Z sam $
 * $DragonFly$
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#include <netproto/802_11/ieee80211_ioctl.h>

#undef RSN_VERSION
#undef WPA_VERSION
#undef WPA_OUI_TYPE
#undef WME_OUI_TYPE

#include "hostapd/hostapd.h"
#include "hostapd/driver.h"
#include "hostapd/ieee802_1x.h"
#include "hostapd/ieee802_11_auth.h"
#include "eloop.h"
#include "hostapd/sta_info.h"
#include "l2_packet/l2_packet.h"

#include "hostapd/eapol_sm.h"
#include "hostapd/wpa.h"
#include "radius/radius.h"
#include "hostapd/ieee802_11.h"
#include "common.h"
#include "hostapd/hostap_common.h"

struct bsd_driver_data {
	struct hostapd_data *hapd;		/* back pointer */

	char	iface[IFNAMSIZ + 1];
	unsigned int ifindex;			/* interface index */
	struct l2_packet_data *sock_xmit;	/* raw packet xmit socket */
	int	ioctl_sock;			/* socket for ioctl() use */
	int	wext_sock;			/* socket for wireless events */
};

static const struct wpa_driver_ops bsd_driver_ops;

static int bsd_sta_deauth(void *priv, const u8 *addr, int reason_code);

static int
set80211var(struct bsd_driver_data *drv, int op, const void *arg, int arg_len)
{
	struct ieee80211req ireq;

	memset(&ireq, 0, sizeof(ireq));
	strncpy(ireq.i_name, drv->iface, IFNAMSIZ);
	ireq.i_type = op;
	ireq.i_len = arg_len;
	ireq.i_data = (void *) arg;

	if (ioctl(drv->ioctl_sock, SIOCS80211, &ireq) < 0) {
		perror("ioctl[SIOCS80211]");
		return -1;
	}
	return 0;
}

static int
get80211var(struct bsd_driver_data *drv, int op, void *arg, int arg_len)
{
	struct ieee80211req ireq;

	memset(&ireq, 0, sizeof(ireq));
	strncpy(ireq.i_name, drv->iface, IFNAMSIZ);
	ireq.i_type = op;
	ireq.i_len = arg_len;
	ireq.i_data = arg;

	if (ioctl(drv->ioctl_sock, SIOCG80211, &ireq) < 0) {
		perror("ioctl[SIOCG80211]");
		return -1;
	}
	return ireq.i_len;
}

static int
set80211param(struct bsd_driver_data *drv, int op, int arg)
{
	struct ieee80211req ireq;

	memset(&ireq, 0, sizeof(ireq));
	strncpy(ireq.i_name, drv->iface, IFNAMSIZ);
	ireq.i_type = op;
	ireq.i_val = arg;

	if (ioctl(drv->ioctl_sock, SIOCS80211, &ireq) < 0) {
		perror("ioctl[SIOCS80211]");
		return -1;
	}
	return 0;
}

static const char *
ether_sprintf(const u8 *addr)
{
	static char buf[sizeof(MACSTR)];

	if (addr != NULL)
		snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	else
		snprintf(buf, sizeof(buf), MACSTR, 0,0,0,0,0,0);
	return buf;
}

static int
bsd_set_iface_flags(void *priv, int flags)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct ifreq ifr;

	wpa_printf(MSG_DEBUG, "%s: flags=0x%x\n", __func__, flags);

	if (drv->ioctl_sock < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", drv->iface);

	if (ioctl(drv->ioctl_sock, SIOCGIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCGIFFLAGS]");
		return -1;
	}

	if (flags < 0) {
		flags = -flags;
		if ((ifr.ifr_flags & flags) == 0)
			return 0;
		ifr.ifr_flags &= ~flags;
	} else {
		if ((ifr.ifr_flags & flags) == flags)
			return 0;
		ifr.ifr_flags |= flags;
	}

	if (ioctl(drv->ioctl_sock, SIOCSIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCSIFFLAGS]");
		return -1;
	}
	return 0;
}

static int
bsd_commit(void *priv)
{
	return bsd_set_iface_flags(priv, IFF_UP);
}

static int
bsd_set_ieee8021x(const char *ifname, void *priv, int enabled)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct hostapd_bss_config *conf = hapd->conf;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d\n", __func__, enabled);

	if (!enabled) {
		/* XXX restore state */
		return set80211param(priv, IEEE80211_IOC_AUTHMODE,
			IEEE80211_AUTH_AUTO);
	}
	if (!conf->wpa && !conf->ieee802_1x) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_DRIVER,
			HOSTAPD_LEVEL_WARNING, "No 802.1X or WPA enabled!");
		return -1;
	}
	if (conf->wpa && set80211param(drv, IEEE80211_IOC_WPA, conf->wpa)) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_DRIVER,
			HOSTAPD_LEVEL_WARNING, "Error configuring WPA state!");
		return -1;
	}
	if (set80211param(priv, IEEE80211_IOC_AUTHMODE,
		(conf->wpa ?  IEEE80211_AUTH_WPA : IEEE80211_AUTH_8021X))) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_DRIVER,
			HOSTAPD_LEVEL_WARNING, "Error enabling WPA/802.1X!");
		return -1;
	}
	return 0;
}

static int
bsd_set_privacy(const char *ifname, void *priv, int enabled)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d\n", __func__, enabled);

	return set80211param(priv, IEEE80211_IOC_PRIVACY, enabled);
}

static int
bsd_set_sta_authorized(void *priv, const u8 *addr, int authorized)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s: addr=%s authorized=%d\n",
		__func__, ether_sprintf(addr), authorized);

	if (authorized)
		mlme.im_op = IEEE80211_MLME_AUTHORIZE;
	else
		mlme.im_op = IEEE80211_MLME_UNAUTHORIZE;
	mlme.im_reason = 0;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211var(priv, IEEE80211_IOC_MLME, &mlme, sizeof(mlme));
}

static int
bsd_sta_set_flags(void *priv, const u8 *addr, int total_flags,
	int flags_or, int flags_and)
{
	/* For now, only support setting Authorized flag */
	if (flags_or & WLAN_STA_AUTHORIZED)
		return bsd_set_sta_authorized(priv, addr, 1);
	if (!(flags_and & WLAN_STA_AUTHORIZED))
		return bsd_set_sta_authorized(priv, addr, 0);
	return 0;
}

static int
bsd_del_key(void *priv, const unsigned char *addr, int key_idx)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211req_del_key wk;

	wpa_printf(MSG_DEBUG, "%s: addr=%s key_idx=%d\n",
		__func__, ether_sprintf(addr), key_idx);

	memset(&wk, 0, sizeof(wk));
	if (addr != NULL) {
		memcpy(wk.idk_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.idk_keyix = (u_int8_t) IEEE80211_KEYIX_NONE;	/* XXX */
	} else {
		wk.idk_keyix = key_idx;
	}

	return set80211var(priv, IEEE80211_IOC_DELKEY, &wk, sizeof(wk));
}

static int
bsd_set_key(const char *ifname, void *priv, const char *alg,
	    const u8 *addr, int key_idx,
	    const u8 *key, size_t key_len, int txkey)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211req_key wk;
	u_int8_t cipher;

	if (strcmp(alg, "none") == 0)
		return bsd_del_key(priv, addr, key_idx);

	wpa_printf(MSG_DEBUG, "%s: alg=%s addr=%s key_idx=%d\n",
		__func__, alg, ether_sprintf(addr), key_idx);

	if (strcmp(alg, "WEP") == 0)
		cipher = IEEE80211_CIPHER_WEP;
	else if (strcmp(alg, "TKIP") == 0)
		cipher = IEEE80211_CIPHER_TKIP;
	else if (strcmp(alg, "CCMP") == 0)
		cipher = IEEE80211_CIPHER_AES_CCM;
	else {
		printf("%s: unknown/unsupported algorithm %s\n",
			__func__, alg);
		return -1;
	}

	if (key_len > sizeof(wk.ik_keydata)) {
		printf("%s: key length %d too big\n", __func__, key_len);
		return -3;
	}

	memset(&wk, 0, sizeof(wk));
	wk.ik_type = cipher;
	if (addr == NULL) {
		memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
		wk.ik_keyix = key_idx;
		wk.ik_flags = IEEE80211_KEY_XMIT
			    | IEEE80211_KEY_GROUP
			    | IEEE80211_KEY_DEFAULT;
	} else {
		memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
		wk.ik_keyix = IEEE80211_KEYIX_NONE;
		wk.ik_flags = IEEE80211_KEY_RECV | IEEE80211_KEY_XMIT;
	}
	wk.ik_keylen = key_len;
	memcpy(wk.ik_keydata, key, key_len);

	return set80211var(priv, IEEE80211_IOC_WPAKEY, &wk, sizeof(wk));
}


static int
bsd_get_seqnum(const char *ifname, void *priv, const u8 *addr, int idx,
	       u8 *seq)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211req_key wk;

	wpa_printf(MSG_DEBUG, "%s: addr=%s idx=%d\n",
	    __func__, ether_sprintf(addr), idx);

	memset(&wk, 0, sizeof(wk));
	if (addr == NULL)
		memset(wk.ik_macaddr, 0xff, IEEE80211_ADDR_LEN);
	else
		memcpy(wk.ik_macaddr, addr, IEEE80211_ADDR_LEN);
	wk.ik_keyix = idx;

	if (get80211var(drv, IEEE80211_IOC_WPAKEY, &wk, sizeof(wk)) < 0) {
		printf("Failed to get encryption.\n");
		return -1;
	} else {
		/* NB: upper layer expects tsc in network order */
		wk.ik_keytsc = htole64(wk.ik_keytsc);
		memcpy(seq, &wk.ik_keytsc, sizeof(wk.ik_keytsc));
		return 0;
	}
}


static int 
bsd_flush(void *priv)
{
	u8 allsta[IEEE80211_ADDR_LEN];

	memset(allsta, 0xff, IEEE80211_ADDR_LEN);
	return bsd_sta_deauth(priv, allsta, IEEE80211_REASON_AUTH_LEAVE);
}


static int
bsd_read_sta_driver_data(void *priv, struct hostap_sta_driver_data *data,
			 const u8 *addr)
{
	struct bsd_driver_data *drv = priv;
	struct ieee80211req_sta_stats stats;

	memcpy(stats.is_u.macaddr, addr, IEEE80211_ADDR_LEN);
	if (get80211var(drv, IEEE80211_IOC_STA_STATS, &stats, sizeof(stats)) > 0) {
		/* XXX? do packets counts include non-data frames? */
		data->rx_packets = stats.is_stats.ns_rx_data;
		data->rx_bytes = stats.is_stats.ns_rx_bytes;
		data->tx_packets = stats.is_stats.ns_tx_data;
		data->tx_bytes = stats.is_stats.ns_tx_bytes;
	}
	return 0;
}

static int
bsd_sta_clear_stats(void *priv, const u8 *addr)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211req_sta_stats stats;
	
	wpa_printf(MSG_DEBUG, "%s: addr=%s\n", __func__, ether_sprintf(addr));

	/* zero station statistics */
	memset(&stats, 0, sizeof(stats));
	memcpy(stats.is_u.macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211var(drv, IEEE80211_IOC_STA_STATS, &stats, sizeof(stats));
}

static int
bsd_set_opt_ie(const char *ifname, void *priv, const u8 *ie, size_t ie_len)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211req ireq;

	memset(&ireq, 0, sizeof(ireq));
	strncpy(ireq.i_name, drv->iface, IFNAMSIZ);
	ireq.i_type = IEEE80211_IOC_APPIE;
	ireq.i_val = IEEE80211_APPIE_WPA;
	ireq.i_data = (void *) ie;
	ireq.i_len = ie_len;

	wpa_printf(MSG_DEBUG, "%s: set WPA+RSN ie (len %d)\n",
	    __func__, ie_len);
	if (ioctl(drv->ioctl_sock, SIOCS80211, &ireq) < 0) {
		printf("Unable to set WPA+RSN ie\n");
		return -1;
	}
	return 0;
}

static int
bsd_sta_deauth(void *priv, const u8 *addr, int reason_code)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d\n",
		__func__, ether_sprintf(addr), reason_code);

	mlme.im_op = IEEE80211_MLME_DEAUTH;
	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211var(priv, IEEE80211_IOC_MLME, &mlme, sizeof(mlme));
}

static int
bsd_sta_disassoc(void *priv, const u8 *addr, int reason_code)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211req_mlme mlme;

	wpa_printf(MSG_DEBUG, "%s: addr=%s reason_code=%d\n",
		__func__, ether_sprintf(addr), reason_code);

	mlme.im_reason = reason_code;
	memcpy(mlme.im_macaddr, addr, IEEE80211_ADDR_LEN);
	return set80211var(priv, IEEE80211_IOC_MLME, &mlme, sizeof(mlme));
}

static int
bsd_del_sta(struct bsd_driver_data *drv, u8 addr[IEEE80211_ADDR_LEN])
{
	struct hostapd_data *hapd = drv->hapd;
	struct hostapd_bss_config *conf = hapd->conf;
	struct sta_info *sta;

	hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
		HOSTAPD_LEVEL_INFO, "deassociated");

	sta = ap_get_sta(hapd, addr);
	if (sta != NULL) {
		sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
		if (conf->wpa)
			wpa_auth_sm_event(sta->wpa_sm, WPA_DISASSOC);
		sta->acct_terminate_cause = RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST;
		ieee802_1x_notify_port_enabled(sta->eapol_sm, 0);
		ap_free_sta(hapd, sta);
	}
	return 0;
}

static int
bsd_new_sta(struct bsd_driver_data *drv, u8 addr[IEEE80211_ADDR_LEN])
{
	struct hostapd_data *hapd = drv->hapd;
	struct hostapd_bss_config *conf = hapd->conf;
	struct sta_info *sta;
	struct ieee80211req_wpaie ie;
	int new_assoc, ielen, res;

	hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
		HOSTAPD_LEVEL_INFO, "associated");

	sta = ap_sta_add(hapd, addr);
	if (sta == NULL)
		return -1;
	/*
	 * Fetch and validate any negotiated WPA/RSN parameters.
	 */
	if (conf->wpa) {
		memset(&ie, 0, sizeof(ie));
		memcpy(ie.wpa_macaddr, addr, IEEE80211_ADDR_LEN);
		if (get80211var(drv, IEEE80211_IOC_WPAIE, &ie, sizeof(ie)) < 0) {
			printf("Failed to get WPA/RSN information element.\n");
			return -1;		/* XXX not right */
		}
		if (ie.wpa_ie[1] == 0) {
			printf("No WPA/RSN information element for station!\n");
			return -1;		/* XXX not right */
		}
		if (sta->wpa_sm == NULL)
			sta->wpa_sm = wpa_auth_sta_init(hapd->wpa_auth,
							sta->addr);
		if (sta->wpa_sm == NULL) {
			printf("Failed to initialize WPA state machine\n");
			return -1;
		}
		ielen = 2 + ie.wpa_ie[1];
		res = wpa_validate_wpa_ie(hapd->wpa_auth, sta->wpa_sm,
					  ie.wpa_ie, ielen, NULL, 0);
		if (res != WPA_IE_OK) {
			printf("WPA/RSN information element rejected? "
				"(res %u)\n", res);
			return -1;
		}
	}

	/*
	 * Now that the internal station state is setup
	 * kick the authenticator into action.
	 */
	new_assoc = (sta->flags & WLAN_STA_ASSOC) == 0;
	sta->flags |= WLAN_STA_AUTH | WLAN_STA_ASSOC;
	wpa_auth_sm_event(sta->wpa_sm, WPA_ASSOC);
	hostapd_new_assoc_sta(hapd, sta, !new_assoc);
	ieee802_1x_notify_port_enabled(sta->eapol_sm, 1);

	return 0;
}

#include <net/route.h>
#include <netproto/802_11/ieee80211_dragonfly.h>

static void
bsd_wireless_event_receive(int sock, void *ctx, void *sock_ctx)
{
	struct bsd_driver_data *drv = ctx;
	struct hostapd_data *hapd = drv->hapd;
	char buf[2048];
	struct if_announcemsghdr *ifan;
	struct rt_msghdr *rtm;
	struct ieee80211_michael_event *mic;
	struct ieee80211_join_event *join;
	struct ieee80211_leave_event *leave;
#ifdef CONFIG_DRIVER_RADIUS_ACL
	struct ieee80211_auth_event *auth;
#endif
	int n;

	n = read(sock, buf, sizeof(buf));
	if (n < 0) {
		if (errno != EINTR && errno != EAGAIN)
			perror("read(PF_ROUTE)");
		return;
	}

	rtm = (struct rt_msghdr *) buf;
	if (rtm->rtm_version != RTM_VERSION) {
		wpa_printf(MSG_DEBUG, "Routing message version %d not "
			"understood\n", rtm->rtm_version);
		return;
	}
	ifan = (struct if_announcemsghdr *) rtm;
	if (ifan->ifan_index != drv->ifindex) {
		wpa_printf(MSG_DEBUG, "Discard routing message to if#%d "
			"(not for us %d)\n",
			ifan->ifan_index, drv->ifindex);
		return;
	}
	switch (rtm->rtm_type) {
	case RTM_IEEE80211:
		switch (ifan->ifan_what) {
		case RTM_IEEE80211_ASSOC:
		case RTM_IEEE80211_REASSOC:
		case RTM_IEEE80211_DISASSOC:
		case RTM_IEEE80211_SCAN:
			break;
		case RTM_IEEE80211_LEAVE:
			leave = (struct ieee80211_leave_event *) &ifan[1];
			bsd_del_sta(drv, leave->iev_addr);
			break;
		case RTM_IEEE80211_JOIN:
#ifdef RTM_IEEE80211_REJOIN
		case RTM_IEEE80211_REJOIN:
#endif
			join = (struct ieee80211_join_event *) &ifan[1];
			bsd_new_sta(drv, join->iev_addr);
			break;
		case RTM_IEEE80211_REPLAY:
			/* ignore */
			break;
		case RTM_IEEE80211_MICHAEL:
			mic = (struct ieee80211_michael_event *) &ifan[1];
			wpa_printf(MSG_DEBUG,
				"Michael MIC failure wireless event: "
				"keyix=%u src_addr=" MACSTR, mic->iev_keyix,
				MAC2STR(mic->iev_src));
			ieee80211_michael_mic_failure(hapd, mic->iev_src, 1);
			break;
#ifdef CONFIG_DRIVER_RADIUS_ACL
		case RTM_IEEE80211_AUTH:
			auth = (struct ieee80211_auth_event *) &ifan[1];
			wpa_printf(MSG_DEBUG, "802.11 AUTH, STA = " MACSTR,
			    MAC2STR(auth->iev_addr));
			n = hostapd_allowed_address(hapd, auth->iev_addr,
				NULL, 0, NULL, NULL, NULL);
			switch (n) {
			case HOSTAPD_ACL_ACCEPT:
			case HOSTAPD_ACL_REJECT:
				hostapd_set_radius_acl_auth(hapd,
				    auth->iev_addr, n, 0);
				wpa_printf(MSG_DEBUG,
				    "802.11 AUTH, STA = " MACSTR " hostapd says: %s",
				    MAC2STR(auth->iev_addr),
				    (n == HOSTAPD_ACL_ACCEPT ?
					"ACCEPT" : "REJECT" ));
				break;
			case HOSTAPD_ACL_PENDING:
				wpa_printf(MSG_DEBUG,
				    "802.11 AUTH, STA = " MACSTR " pending",
				    MAC2STR(auth->iev_addr));
				break;
			}
			break;
#endif /* CONFIG_DRIVER_RADIUS_ACL */
		}
		break;
	}
}

static int
bsd_wireless_event_init(void *priv)
{
	struct bsd_driver_data *drv = priv;
	int s;

	drv->wext_sock = -1;

	s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0) {
		perror("socket(PF_ROUTE,SOCK_RAW)");
		return -1;
	}
	eloop_register_read_sock(s, bsd_wireless_event_receive, drv, NULL);
	drv->wext_sock = s;

	return 0;
}

static void
bsd_wireless_event_deinit(void *priv)
{
	struct bsd_driver_data *drv = priv;

	if (drv != NULL) {
		if (drv->wext_sock < 0)
			return;
		eloop_unregister_read_sock(drv->wext_sock);
		close(drv->wext_sock);
	}
}


static int
bsd_send_eapol(void *priv, const u8 *addr, const u8 *data, size_t data_len,
	       int encrypt, const u8 *own_addr)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	unsigned char buf[3000];
	unsigned char *bp = buf;
	struct l2_ethhdr *eth;
	size_t len;
	int status;

	/*
	 * Prepend the Etherent header.  If the caller left us
	 * space at the front we could just insert it but since
	 * we don't know we copy to a local buffer.  Given the frequency
	 * and size of frames this probably doesn't matter.
	 */
	len = data_len + sizeof(struct l2_ethhdr);
	if (len > sizeof(buf)) {
		bp = malloc(len);
		if (bp == NULL) {
			printf("EAPOL frame discarded, cannot malloc temp "
				"buffer of size %u!\n", len);
			return -1;
		}
	}
	eth = (struct l2_ethhdr *) bp;
	memcpy(eth->h_dest, addr, ETH_ALEN);
	memcpy(eth->h_source, own_addr, ETH_ALEN);
	eth->h_proto = htons(ETH_P_EAPOL);
	memcpy(eth+1, data, data_len);

	wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", bp, len);

	status = l2_packet_send(drv->sock_xmit, addr, ETH_P_EAPOL, bp, len);

	if (bp != buf)
		free(bp);
	return status;
}

static void
handle_read(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
	struct bsd_driver_data *drv = ctx;
	struct hostapd_data *hapd = drv->hapd;
	struct sta_info *sta;

	sta = ap_get_sta(hapd, src_addr);
	if (!sta || !(sta->flags & WLAN_STA_ASSOC)) {
		printf("Data frame from not associated STA %s\n",
		       ether_sprintf(src_addr));
		/* XXX cannot happen */
		return;
	}
	ieee802_1x_receive(hapd, src_addr, buf + sizeof(struct l2_ethhdr),
			   len - sizeof(struct l2_ethhdr));
}

static int
bsd_get_ssid(const char *ifname, void *priv, u8 *buf, int len)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	int ssid_len = get80211var(priv, IEEE80211_IOC_SSID, buf, len);

	wpa_printf(MSG_DEBUG, "%s: ssid=\"%.*s\"\n", __func__, ssid_len, buf);

	return ssid_len;
}

static int
bsd_set_ssid(const char *ifname, void *priv, const u8 *buf, int len)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;

	wpa_printf(MSG_DEBUG, "%s: ssid=\"%.*s\"\n", __func__, len, buf);

	return set80211var(priv, IEEE80211_IOC_SSID, buf, len);
}

static int
bsd_set_countermeasures(void *priv, int enabled)
{
	struct bsd_driver_data *drv = priv;

	wpa_printf(MSG_DEBUG, "%s: enabled=%d", __FUNCTION__, enabled);
	return set80211param(drv, IEEE80211_IOC_COUNTERMEASURES, enabled);
}

#ifdef CONFIG_DRIVER_RADIUS_ACL
static int 
bsd_set_radius_acl_auth(void *priv, const u8 *mac, int accepted, 
	u32 session_timeout)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	struct ieee80211req_mlme mlme;

	switch (accepted) {
	case HOSTAPD_ACL_ACCEPT_TIMEOUT:
		wpa_printf(MSG_DEBUG, "[%s] STA " MACSTR 
			" has been accepted by RADIUS ACL with timeout "
			"of %d.\n", hapd->conf->iface, MAC2STR(mac), 
			session_timeout);
		mlme.im_reason = IEEE80211_STATUS_SUCCESS;
		break;
	case HOSTAPD_ACL_ACCEPT:
		wpa_printf(MSG_DEBUG, "[%s] STA " MACSTR 
			" has been accepted by RADIUS ACL.\n", 
			hapd->conf->iface, MAC2STR(mac));
		mlme.im_reason = IEEE80211_STATUS_SUCCESS;
		break;
	case HOSTAPD_ACL_REJECT:
		wpa_printf(MSG_DEBUG, "[%s] STA " MACSTR 
			" has been rejected by RADIUS ACL.\n", 
			hapd->conf->iface, MAC2STR(mac));
		mlme.im_reason = IEEE80211_STATUS_UNSPECIFIED;
		break;
	default:
		wpa_printf(MSG_ERROR, "[%s] STA " MACSTR 
			" has unknown status (%d) by RADIUS ACL.  "
			"Nothing to do...\n", hapd->conf->iface, 
			MAC2STR(mac), accepted);
		return 0;
	}
	memset(&mlme, 0, sizeof(mlme));
	mlme.im_op = IEEE80211_MLME_AUTH;
	memcpy(mlme.im_macaddr, mac, IEEE80211_ADDR_LEN);
	return set80211var(drv, IEEE80211_IOC_MLME, &mlme, sizeof(mlme));
}

static int
bsd_set_radius_acl_expire(void *priv, const u8 *mac)
{
	struct bsd_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;

	/*
	 * The expiry of the MAC address from RADIUS ACL cache doesn't mean 
	 * that we should kick off the client.  Our current approach doesn't 
	 * require adding/removing entries from an allow/deny list; so this
	 * function is likely unecessary
	 */
	wpa_printf(MSG_DEBUG, "[%s] STA " MACSTR " radius acl cache "
		"expired; nothing to do...", hapd->conf->iface, 
		MAC2STR(mac));
	return 0;
}
#endif /* CONFIG_DRIVER_RADIUS_ACL */

static void *
bsd_init(struct hostapd_data *hapd)
{
	struct bsd_driver_data *drv;

	drv = malloc(sizeof(struct bsd_driver_data));
	if (drv == NULL) {
		printf("Could not allocate memory for bsd driver data\n");
		goto bad;
	}

	memset(drv, 0, sizeof(*drv));
	drv->hapd = hapd;
	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		goto bad;
	}
	memcpy(drv->iface, hapd->conf->iface, sizeof(drv->iface));
	/*
	 * NB: We require the interface name be mappable to an index.
	 *     This implies we do not support having wpa_supplicant
	 *     wait for an interface to appear.  This seems ok; that
	 *     doesn't belong here; it's really the job of devd.
	 *     XXXSCW: devd is FreeBSD-specific.
	 */
	drv->ifindex = if_nametoindex(drv->iface);
	if (drv->ifindex == 0) {
		printf("%s: interface %s does not exist", __func__, drv->iface);
		goto bad;
	}

	drv->sock_xmit = l2_packet_init(drv->iface, NULL, ETH_P_EAPOL,
					handle_read, drv, 1);
	if (drv->sock_xmit == NULL)
		goto bad;
	if (l2_packet_get_own_addr(drv->sock_xmit, hapd->own_addr))
		goto bad;

	bsd_set_iface_flags(drv, -IFF_UP);	/* mark down during setup */

	return drv;
bad:
	if (drv != NULL) {
		if (drv->sock_xmit != NULL)
			l2_packet_deinit(drv->sock_xmit);
		if (drv->ioctl_sock >= 0)
			close(drv->ioctl_sock);
		free(drv);
	}
	return NULL;
}


static void
bsd_deinit(void *priv)
{
	struct bsd_driver_data *drv = priv;

	(void) bsd_set_iface_flags(drv, -IFF_UP);
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
	if (drv->sock_xmit != NULL)
		l2_packet_deinit(drv->sock_xmit);
	free(drv);
}

const struct wpa_driver_ops wpa_driver_bsd_ops = {
	.name			= "bsd",
	.init			= bsd_init,
	.deinit			= bsd_deinit,
	.set_ieee8021x		= bsd_set_ieee8021x,
	.set_privacy		= bsd_set_privacy,
	.set_encryption		= bsd_set_key,
	.get_seqnum		= bsd_get_seqnum,
	.flush			= bsd_flush,
	.set_generic_elem	= bsd_set_opt_ie,
	.wireless_event_init	= bsd_wireless_event_init,
	.wireless_event_deinit	= bsd_wireless_event_deinit,
	.sta_set_flags		= bsd_sta_set_flags,
	.read_sta_data		= bsd_read_sta_driver_data,
	.send_eapol		= bsd_send_eapol,
	.sta_disassoc		= bsd_sta_disassoc,
	.sta_deauth		= bsd_sta_deauth,
	.set_ssid		= bsd_set_ssid,
	.get_ssid		= bsd_get_ssid,
	.set_countermeasures	= bsd_set_countermeasures,
	.sta_clear_stats        = bsd_sta_clear_stats,
	.commit			= bsd_commit,
#ifdef CONFIG_DRIVER_RADIUS_ACL
	.set_radius_acl_auth	= bsd_set_radius_acl_auth,
	.set_radius_acl_expire	= bsd_set_radius_acl_expire,
#endif
};
