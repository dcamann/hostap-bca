/*
 * hostapd / BC Accounting
 * Copyright (c) 2017, David Amann
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "eapol_auth/eapol_auth_sm.h"
#include "eapol_auth/eapol_auth_sm_i.h"
#include "hostapd.h"
#include "ieee802_1x.h"
#include "ap_config.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include "bc_accounting.h"

#include "eap_server/eap_i.h"
#include "eap_common/eap_bca_common.h"
#include "eap_server/eap_bca_common.h"



int bc_accounting_sta_update_stats(struct hostapd_data *hapd, struct sta_info *sta, struct hostap_sta_driver_data *data);


int get_eap_bca_data(struct sta_info *sta, struct eap_bca_data **bca_data)
{
	struct eapol_state_machine *eapol_sm = sta->eapol_sm;
	if (eapol_sm == NULL ||
		eapol_sm->eap == NULL)
		return -1;
	
	const struct eap_method *eap_m = eapol_sm->eap->m;
	if (eap_m == NULL ||
		eap_m->vendor != EAP_VENDOR_BCA ||
		eap_m->method != EAP_VENDOR_TYPE_BCA)
		return -1;
	
	*bca_data = eapol_sm->eap->eap_method_priv;
	
	return 0;
}


void bc_accounting_interim_update(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;
	struct hostap_sta_driver_data data;
	struct eap_bca_data *bca_data;
	
	if (hapd == NULL || sta == NULL)
		return;
	
	if (get_eap_bca_data(sta, &bca_data) ||
		bca_data == NULL) {
		return;
	}
	
	if (!bca_data->acct_session_started)
		return;
	
	bc_accounting_sta_update_stats(hapd, sta, &data);
	
	eloop_register_timeout(BC_ACCOUNTING_UPDATE_STATE_INTERVAL_SEC, BC_ACCOUNTING_UPDATE_STATE_INTERVAL_USEC,
			bc_accounting_interim_update, hapd, sta);
}


int bc_accounting_sta_update_stats(struct hostapd_data *hapd, struct sta_info *sta, struct hostap_sta_driver_data *data)
{
	struct eap_bca_data *bca_data;
	
	if (get_eap_bca_data(sta, &bca_data) ||
		bca_data == NULL) {
		return -1;
	}
	
	if (!bca_data->acct_session_started)
		return -1;
	
	if (hostapd_drv_read_sta_data(hapd, data, sta->addr))
		return -1;
	
	if (!data->bytes_64bit) {
		/* Extend 32-bit counters from the driver to 64-bit counters */
		if (sta->last_rx_bytes_lo > data->rx_bytes)
			sta->last_rx_bytes_hi++;
		sta->last_rx_bytes_lo = data->rx_bytes;

		if (sta->last_tx_bytes_lo > data->tx_bytes)
			sta->last_tx_bytes_hi++;
		sta->last_tx_bytes_lo = data->tx_bytes;
	}
	
	bca_data->rx_packets = data->rx_packets;
	bca_data->tx_packets = data->tx_packets;
	
	if (data->bytes_64bit)
		bca_data->rx_bytes = data->rx_bytes;
	else
		bca_data->rx_bytes = ((u64) sta->last_rx_bytes_hi << 32) | sta->last_rx_bytes_lo;
	
	if (data->bytes_64bit)
		bca_data->tx_bytes = data->tx_bytes;
	else
		bca_data->tx_bytes = ((u64) sta->last_tx_bytes_hi << 32) | sta->last_tx_bytes_lo;
	
	return 0;
}


void bc_accounting_sta_start(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct hostap_sta_driver_data data;
	struct eap_bca_data *bca_data;
	
	if (get_eap_bca_data(sta, &bca_data)) {
		return;
	}
	
	if (bca_data == NULL)
		return;
	
	if (bca_data->acct_session_started)
		return;
	
	hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_RADIUS,
		       HOSTAPD_LEVEL_INFO,
		       "starting bc accounting session");
	
	eloop_register_timeout(BC_ACCOUNTING_UPDATE_STATE_INTERVAL_SEC, BC_ACCOUNTING_UPDATE_STATE_INTERVAL_USEC,
			bc_accounting_interim_update, hapd, sta);
	
	bca_data->acct_session_started = 1;
	
	if (hostapd_drv_read_sta_data(hapd, &data, sta->addr))
		return;
	
	if (!data.bytes_64bit) {
		/* Extend 32-bit counters from the driver to 64-bit counters */
		if (sta->last_rx_bytes_lo > data.rx_bytes)
			sta->last_rx_bytes_hi++;
		sta->last_rx_bytes_lo = data.rx_bytes;

		if (sta->last_tx_bytes_lo > data.tx_bytes)
			sta->last_tx_bytes_hi++;
		sta->last_tx_bytes_lo = data.tx_bytes;
	}
	
	bca_data->rx_start_packets = bca_data->rx_packets = data.rx_packets;
	bca_data->tx_start_packets = bca_data->tx_packets = data.tx_packets;
	
	if (data.bytes_64bit)
		bca_data->rx_start_bytes = data.rx_bytes;
	else
		bca_data->rx_start_bytes = ((u64) sta->last_rx_bytes_hi << 32) | sta->last_rx_bytes_lo;
	
	if (data.bytes_64bit)
		bca_data->tx_start_bytes = data.tx_bytes;
	else
		bca_data->tx_start_bytes = ((u64) sta->last_tx_bytes_hi << 32) | sta->last_tx_bytes_lo;
	
	bca_data->rx_bytes = bca_data->rx_start_bytes;
	bca_data->tx_bytes = bca_data->tx_start_bytes;
}


void bc_accounting_sta_stop(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct eap_bca_data *bca_data;
	
	if (get_eap_bca_data(sta, &bca_data)) {
		return;
	}
	
	if (bca_data == NULL)
		return;
	
	if (bca_data->acct_session_started) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_RADIUS,
				   HOSTAPD_LEVEL_INFO,
				   "stopped bc accounting session");
		eloop_cancel_timeout(bc_accounting_interim_update, hapd, sta);
		bca_data->acct_session_started = 0;
	}
}
