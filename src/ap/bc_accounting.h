/*
 * hostapd / BC Accounting
 * Copyright (c) 2017, David Amann
 */

#ifndef BC_ACCOUNTING_H
#define BC_ACCOUNTING_H


#define BC_ACCOUNTING_UPDATE_STATE_INTERVAL_SEC			1
#define BC_ACCOUNTING_UPDATE_STATE_INTERVAL_USEC		0


void bc_accounting_sta_start(struct hostapd_data *hapd, struct sta_info *sta);
void bc_accounting_sta_stop(struct hostapd_data *hapd, struct sta_info *sta);

#endif /* BC_ACCOUNTING_H */
