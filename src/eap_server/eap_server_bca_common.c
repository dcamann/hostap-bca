/*
 * hostapd / EAP-BCA
 * Copyright (c) 2017, David Amann
 */

#include "includes.h"

#include "common.h"
#include "eap_i.h"
#include "ap/hostapd.h"
#include "ap/ap_config.h"

#include "eap_common/eap_bca_common.h"
#include "eap_bca_common.h"



int bca_global_init(struct hostapd_data *hapd) {
	struct hostapd_bss_config *conf;
	
	conf = hapd->conf;
	
	if (bca_global_data)
		return 0;
	
	bca_global_data = os_malloc(sizeof(*bca_global_data));
	
	if (bca_global_data == NULL)
		return -1;
	
	os_memcpy(bca_global_data->authPrivateKey, conf->eap_bca_auth_private_key, BCA_ECDSA_KEY_LENGTH);
	// os_memcpy(bca_global_data->authKeySign, conf->eap_bca_auth_key_sign, 2 * BCA_ECDSA_KEY_LENGTH);
	// os_memcpy(bca_global_data->caPublicKey, conf->eap_bca_ca_public_key, 2 * BCA_ECDSA_KEY_LENGTH);
	os_memcpy(bca_global_data->authAddress, conf->eap_bca_eth_auth_address, BCA_ETH_ADDR_LENGTH);
	
	if (conf->eap_bca_eth_auth_passphrase != NULL) {
		bca_global_data->authPassphrase = os_strdup(conf->eap_bca_eth_auth_passphrase);
	} else {
		bca_global_data->authPassphrase = os_malloc(1);
		bca_global_data->authPassphrase[0] = 0;
	}
	
	bca_global_data->ethIPCFilePath = os_strdup(conf->eap_bca_eth_ipc_file_path);
	if (bca_global_data->ethIPCFilePath == NULL) {
		os_free(bca_global_data);
		return -1;
	}
	
	if (bca_ecdsa_create_public_key(bca_global_data->authPrivateKey, bca_global_data->authPublicKey)) {
		bca_global_deinit();
		return -1;
	}
	
	if (bca_hash_dsa_key(bca_global_data->authPublicKey, bca_global_data->authKeyHash)) {
		bca_global_deinit();
		return -1;
	}
	
	// if (bca_hash_dsa_key(bca_global_data->caPublicKey, bca_global_data->caKeyHash)) {
	// 	bca_global_deinit();
	// 	return -1;
	// }
	
	return 0;
}

void bca_global_deinit(void)
{
	if (bca_global_data == NULL)
		return;
	
	os_free(bca_global_data->authPassphrase);
	os_free(bca_global_data->ethIPCFilePath);
	
	os_free(bca_global_data);
	bca_global_data = NULL;
}





struct wpabuf * eap_server_bca_build_msg(struct eap_bca_data *data, u8 id)
{
	struct wpabuf *req;
	u8 sign_msg[BCA_AUTH_AUTHENTICATION_SIGN_MSG_LENGTH];

	wpa_printf(MSG_DEBUG, "EAP-BCA: Generating Request");

	req = eap_msg_alloc(EAP_VENDOR_BCA, EAP_VENDOR_TYPE_BCA,
			sizeof(struct bca_msg_hdr) + sizeof(struct bca_init_msg),
			EAP_CODE_REQUEST, id);
	if (req == NULL)
		return NULL;
	
	if (bca_global_data->authPublicKey == NULL)
		return NULL;
	
	if (data->ecdhAuthPrivateKey == NULL ||
		data->ecdhAuthPublicKey == NULL ||
		data->ecdhAuthKeyHash == NULL ||
		data->caPublicKey == NULL ||
		data->authKeySign == NULL)
		return NULL;
	
	if (bca_ecdh_create_private_key(data->ecdhAuthPrivateKey) ||
		bca_ecdh_create_public_key(data->ecdhAuthPrivateKey, data->ecdhAuthPublicKey) ||
		bca_hash_dh_key(data->ecdhAuthPublicKey, data->ecdhAuthKeyHash))
		return NULL;
	
	os_memcpy(sign_msg, BCA_AUTH_AUTHENTICATION_SIGN_MSG_PREFIX, strlen(BCA_AUTH_AUTHENTICATION_SIGN_MSG_PREFIX));
	WPA_PUT_BE64(sign_msg + strlen(BCA_AUTH_AUTHENTICATION_SIGN_MSG_PREFIX), data->timestamp);
	os_memcpy(sign_msg + strlen(BCA_AUTH_AUTHENTICATION_SIGN_MSG_PREFIX) + sizeof(data->timestamp),
			data->ecdhAuthPublicKey, (2 * BCA_ECDH_KEY_LENGTH));
	if (bca_ecdsa_sign(sign_msg, BCA_AUTH_AUTHENTICATION_SIGN_MSG_LENGTH,
				bca_global_data->authPrivateKey,
				data->authAuthenticationSign))
		return NULL;
	
	wpabuf_put_u8(req, BCA_MSG_TYPE_INIT);
	WPA_PUT_BE64((u8 *) wpabuf_put(req, sizeof(data->timestamp)), data->timestamp);
	wpabuf_put_data(req, data->caPublicKey, 2 * BCA_ECDSA_KEY_LENGTH);
	wpabuf_put_data(req, bca_global_data->authPublicKey, 2 * BCA_ECDSA_KEY_LENGTH);
	wpabuf_put_data(req, data->authKeySign, 2 * BCA_ECDSA_KEY_LENGTH);
	wpabuf_put_data(req, data->ecdhAuthPublicKey, 2 * BCA_ECDH_KEY_LENGTH);
	wpabuf_put_data(req, data->authAuthenticationSign, 2 * BCA_ECDSA_KEY_LENGTH);
	
	wpa_printf(MSG_DEBUG, "EAP-BCA: Sending out %lu bytes", (unsigned long) wpabuf_len(req));
	wpa_hexdump(MSG_DEBUG, "EAP-BCA: Msg", wpabuf_head(req), wpabuf_len(req));
	
	return req;
}
