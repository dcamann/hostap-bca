/*
 * hostapd / EAP-BCA
 * Copyright (c) 2017, David Amann
 */

#include "includes.h"

#include "common.h"
#include "eap_i.h"
#include "eap_common/eap_bca_common.h"
#include "eap_bca_common.h"







static const char * eap_bca_state_txt(int state)
{
	switch (state) {
	case START:
		return "START";
	case CONTINUE:
		return "CONTINUE";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "Unknown?!";
	}
}


static void eap_bca_state(struct eap_bca_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-BCA: %s -> %s", eap_bca_state_txt(data->state), eap_bca_state_txt(state));
	data->state = state;
}


static void * eap_bca_init(struct eap_sm *sm)
{
	struct eap_bca_data *data;
	
	if (sm->user == NULL || sm->user->password == NULL || sm->user->password_len == 0) {
		wpa_printf(MSG_ERROR, "EAP-BCA: bcNetwordId (user) and smart contract address (password)"
				" in the hostapd.eap_user file is not configured");
		return NULL;
	}
	
	if (sm->user->password_hash == 1) {
		wpa_printf(MSG_ERROR, "EAP-BCA: The smart contract address (user password)"
				" in the hostapd.eap_user file must be a hex value");
		return NULL;
	}
	
	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = START;
	
	if (sm->user->password_len < (BCA_ETH_ADDR_LENGTH + BCA_CONTRACT_PSK_LENGTH)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: User password length is %d not %d",
				sm->user->password_len,
				BCA_ETH_ADDR_LENGTH + BCA_CONTRACT_PSK_LENGTH);
		os_free(data);
		return NULL;
	}
	
	data->bcContractAddress = os_memdup(sm->user->password, BCA_ETH_ADDR_LENGTH);
	data->bcContractPSK     = os_memdup(sm->user->password + BCA_ETH_ADDR_LENGTH, BCA_CONTRACT_PSK_LENGTH);
	data->caPublicKey       = os_malloc(2 * BCA_ECDSA_KEY_LENGTH);
	data->authKeySign       = os_malloc(2 * BCA_ECDSA_KEY_LENGTH);
	if (data->bcContractAddress == NULL ||
		data->bcContractPSK == NULL ||
		data->caPublicKey == NULL ||
		data->authKeySign == NULL) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Memory allocation fail");
		os_free(data->bcContractAddress);
		os_free(data->bcContractPSK);
		os_free(data->caPublicKey);
		os_free(data->authKeySign);
		os_free(data);
		return NULL;
	}
	
	if (sm->user->password_len == (BCA_ETH_ADDR_LENGTH + BCA_CONTRACT_PSK_LENGTH)) {
		// get ca_public_key & auth_key_sign from the block chain contract
		// and add it to the user password value
		u8 *oldpwd = sm->user->password;
		u8 is_auth_sign_found;
		
		sm->user->password_len = BCA_ETH_ADDR_LENGTH + BCA_CONTRACT_PSK_LENGTH + (2*(2 * BCA_ECDSA_KEY_LENGTH));
		sm->user->password = os_malloc(sm->user->password_len);
		
		os_memcpy(sm->user->password, oldpwd, BCA_ETH_ADDR_LENGTH + BCA_CONTRACT_PSK_LENGTH);
		
		
		// get ca_public_key from the smart contract via geth
		if (bca_eth_aaa_contract_call_get_ca_public_key(bca_global_data->ethIPCFilePath,
					data->bcContractAddress,
					bca_global_data->authAddress,
					data->caPublicKey)) {
			wpa_printf(MSG_ERROR, "EAP-BCA: Error in bca_eth_aaa_contract_call_get_ca_public_key");
			os_free(data->caPublicKey);
			os_free(data->authKeySign);
			os_free(data);
			return NULL;
		}
		wpa_hexdump(MSG_DEBUG, "EAP-BCA: caPublicKey from contract loaded", data->caPublicKey, 2 * BCA_ECDSA_KEY_LENGTH);
		
		// get auth_key_sign from the smart contract via geth
		if (bca_eth_aaa_contract_call_get_auth_key_sign(bca_global_data->ethIPCFilePath,
					data->bcContractAddress,
					bca_global_data->authAddress,
					bca_global_data->authKeyHash,
					&is_auth_sign_found,
					data->authKeySign)) {
			wpa_printf(MSG_ERROR, "EAP-BCA: Error in bca_eth_aaa_contract_call_get_auth_key_sign");
			os_free(data->caPublicKey);
			os_free(data->authKeySign);
			os_free(data);
			return NULL;
		}
		if (!is_auth_sign_found) {
			wpa_printf(MSG_ERROR, "EAP-BCA: Error in authKeySign not in contract found");
			os_free(data->caPublicKey);
			os_free(data->authKeySign);
			os_free(data);
			return NULL;
		}
		wpa_hexdump(MSG_DEBUG, "EAP-BCA: authKeySign from contract loaded", data->authKeySign, 2 * BCA_ECDSA_KEY_LENGTH);
		
		bin_clear_free(oldpwd, BCA_ETH_ADDR_LENGTH + BCA_CONTRACT_PSK_LENGTH);
	} else if (sm->user->password_len == (BCA_ETH_ADDR_LENGTH + BCA_CONTRACT_PSK_LENGTH + (2*(2 * BCA_ECDSA_KEY_LENGTH)))) {
		os_memcpy(data->caPublicKey,
				sm->user->password + BCA_ETH_ADDR_LENGTH + BCA_CONTRACT_PSK_LENGTH,
				2 * BCA_ECDSA_KEY_LENGTH);
		os_memcpy(data->authKeySign,
				sm->user->password + BCA_ETH_ADDR_LENGTH + BCA_CONTRACT_PSK_LENGTH + (2 * BCA_ECDSA_KEY_LENGTH),
				2 * BCA_ECDSA_KEY_LENGTH);
	} else {
		wpa_printf(MSG_ERROR, "EAP-BCA: User password has unexpected length is %d",
				sm->user->password_len);
		os_free(data->caPublicKey);
		os_free(data->authKeySign);
		os_free(data);
		return NULL;
	}
	
	
	
	// TODO: allocating all filds in data
	
	data->timestamp = bca_time_now();
	
	data->ecdhAuthPrivateKey = os_malloc(BCA_ECDSA_KEY_LENGTH);
	data->ecdhAuthPublicKey  = os_malloc(2 * BCA_ECDSA_KEY_LENGTH);
	data->ecdhAuthKeyHash    = os_malloc(BCA_KEY_HASH_LENGTH);
	
	data->ecdhPeerPublicKey  = os_malloc(2 * BCA_ECDSA_KEY_LENGTH);
	data->ecdhPeerKeyHash    = os_malloc(BCA_KEY_HASH_LENGTH);
	
	data->authAuthenticationSign = os_malloc(2 * BCA_ECDSA_KEY_LENGTH);
	
	data->peerPublicKey      = os_malloc(2 * BCA_ECDSA_KEY_LENGTH);
	data->peerKeyHash        = os_malloc(BCA_KEY_HASH_LENGTH);
	
	data->masterSecret       = os_malloc(BCA_MASTER_SECRET_LENGTH);
	
	data->combinedCipherParameters = os_malloc(sizeof(*data->combinedCipherParameters));
	
	
	data->rx_packets = 0;
	data->tx_packets = 0;
	data->rx_bytes = 0;
	data->tx_bytes = 0;
	
	data->rx_start_packets = 0;
	data->tx_start_packets = 0;
	data->rx_start_bytes = 0;
	data->tx_start_bytes = 0;
	
	data->acct_session_started = 0;
	
	// update bc accounting
	data->isBCAccounting = 0;
	
	u8 accounting_test_access_token[32];
	os_memset(accounting_test_access_token, 0, 32);
	u64 accounting_test_count;
	
	// test the contract accounting support
	if (bca_eth_aaa_contract_call_get_accounting_entry_count(bca_global_data->ethIPCFilePath,
				data->bcContractAddress,
				bca_global_data->authAddress,
				accounting_test_access_token,
				&accounting_test_count) == 0) {
		data->isBCAccounting = 1;
		
		wpa_printf(MSG_DEBUG, "BC Accounting: enable");
	} else {
		wpa_printf(MSG_DEBUG, "BC Accounting: disenable");
	}
	
	return data;
}


static void eap_bca_reset(struct eap_sm *sm, void *priv)
{
	struct eap_bca_data *data = priv;
	if (data == NULL)
		return;
	
	u32 rx_packets, tx_packets;
	u64 rx_bytes, tx_bytes;
	
	rx_packets = data->rx_packets - data->rx_start_packets;
	tx_packets = data->tx_packets - data->tx_start_packets;
	rx_bytes = data->rx_bytes - data->rx_start_bytes;
	tx_bytes = data->tx_bytes - data->tx_start_bytes;

	wpa_printf(MSG_DEBUG, "EAP-BCA: %s - (auth_*) rx_packets = %u, tx_packets = %u, rx_bytes = %llu, tx_bytes = %llu",
			__func__,
			rx_packets,
			tx_packets,
			rx_bytes,
			tx_bytes);
	
	
	if (data->state == SUCCESS && data->isBCAccounting) {
		u8 access_token[BCA_ACCESS_TOKEN_LENGTH];
		u8 accounting_msg[BCA_ACCOUNTING_MSG_LENGTH];
		size_t accounting_msg_len = 0;
		struct os_time now;
		
		os_get_time(&now);
		
		WPA_PUT_BE32(accounting_msg, now.sec);
		accounting_msg_len += 4;
		os_memcpy(accounting_msg + accounting_msg_len, bca_global_data->authKeyHash, 4);
		accounting_msg_len += 4;
		
		// optional cipher part
		accounting_msg[accounting_msg_len] = 1;
		accounting_msg_len += 1;
		os_memcpy(accounting_msg + accounting_msg_len, sm->peer_addr, 6);
		accounting_msg_len += 6;
		
		WPA_PUT_BE64(accounting_msg + accounting_msg_len, rx_bytes + tx_bytes);
		accounting_msg_len += 8;
		WPA_PUT_BE32(accounting_msg + accounting_msg_len, tx_packets); // == peer_rx_packets
		accounting_msg_len += 4;
		WPA_PUT_BE32(accounting_msg + accounting_msg_len, rx_packets); // == peer_tx_packets
		accounting_msg_len += 4;
		
		wpa_printf(MSG_DEBUG, "BC Accounting: sending accounting update message");
		wpa_hexdump(MSG_DEBUG, "BC Accounting: Msg", accounting_msg, accounting_msg_len);
		
		if (bca_eth_aaa_contract_gen_access_token(data->peerKeyHash, data->bcContractPSK, access_token) ||
			bca_eth_aaa_contract_update_accounting(bca_global_data->ethIPCFilePath,
					data->bcContractAddress,
					bca_global_data->authAddress,
					bca_global_data->authPassphrase,
					access_token,
					accounting_msg,
					accounting_msg_len)) {
			wpa_printf(MSG_ERROR, "BC Accounting: %s - accounting update fail", __func__);
		}
	}
	
	
	// deallocating all filds in data
	os_free(data->ecdhAuthPrivateKey);
	os_free(data->ecdhAuthPublicKey);
	os_free(data->ecdhAuthKeyHash);
	os_free(data->ecdhPeerPublicKey);
	os_free(data->ecdhPeerKeyHash);
	
	os_free(data->authAuthenticationSign);
	
	os_free(data->peerPublicKey);
	os_free(data->peerKeyHash);
	
	os_free(data->masterSecret);
	os_free(data->combinedCipherParameters);
	
	os_free(data->bcContractAddress);
	os_free(data->bcContractPSK);
	
	os_free(data->authKeySign);
	os_free(data->caPublicKey);
	
	os_free(data);
}


static struct wpabuf * eap_bca_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_bca_data *data = priv;
	struct wpabuf *res;
	
	if (data->state != START) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - unexpected state %d", __func__, data->state);
		return NULL;
	}

	res = eap_server_bca_build_msg(data, id);
	
	eap_bca_state(data, CONTINUE);
	
	return res;
}


static Boolean eap_bca_check(struct eap_sm *sm, void *priv, struct wpabuf *respData)
{
	// struct eap_bca_data *data = priv;
	const u8 *pos;
	size_t len;
	struct bca_msg_hdr *msg_header;
	
	pos = eap_hdr_validate(EAP_VENDOR_BCA, EAP_VENDOR_TYPE_BCA, respData, &len);
	
	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, "EAP-BCA: Invalid frame");
		return TRUE;
	}
	
	
	if (len != (sizeof(struct bca_msg_hdr) + sizeof(struct bca_auth_msg))) {
		wpa_printf(MSG_INFO, "EAP-BCA: %s - unexpected message length %d", __func__, len);
		return TRUE;
	}
	
	msg_header = (struct bca_msg_hdr *) pos;
	
	if (msg_header->type != BCA_MSG_TYPE_AUTH) {
		wpa_printf(MSG_INFO, "EAP-BCA: %s - unexpected message type %d", __func__, msg_header->type);
		return TRUE;
	}
	
	return FALSE;
}


static void eap_bca_process(struct eap_sm *sm, void *priv, struct wpabuf *respData)
{
	struct eap_bca_data *data = priv;
	// const struct wpabuf *buf;
	const u8 *pos;
	size_t len;
	struct bca_msg_hdr *msg_header;
	struct bca_auth_msg *auth_msg;
	struct bca_auth_cipher_msg_part *auth_deciphered_msg;
	struct bca_cipher_parameters *cipher_parameters;
	u8 *comb_shared_key;
	u8 *key_block;
	u8 sign_msg[BCA_PEER_AUTHENTICATION_SIGN_MSG_LENGTH];
	u8 has_access;
	u8 access_token[BCA_ACCESS_TOKEN_LENGTH];
	
	pos = eap_hdr_validate(EAP_VENDOR_BCA, EAP_VENDOR_TYPE_BCA, respData, &len);
	has_access = 0;
	
	wpa_printf(MSG_DEBUG, "EAP-BCA: process msg ...");
	//wpa_hexdump(MSG_DEBUG, "EAP-BCA: Response Msg", wpabuf_head(respData), wpabuf_len(respData));
	
	
	if (pos == NULL) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - (pos) null pointer error", __func__);
		eap_bca_state(data, FAILURE);
		return;
	}
	
	if (len != (sizeof(struct bca_msg_hdr) + sizeof(struct bca_auth_msg))) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - invalid package size", __func__);
		eap_bca_state(data, FAILURE);
		return;
	}
	
	msg_header = (struct bca_msg_hdr *) pos;
	
	if (msg_header->type != BCA_MSG_TYPE_AUTH) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - unexpected BCA message type", __func__);
		eap_bca_state(data, FAILURE);
		return;
	}
	
	auth_msg = (struct bca_auth_msg *)(pos + sizeof(struct bca_msg_hdr));
	
	if (bca_hash_dh_key(auth_msg->ecdhPeerPublicKey, data->ecdhPeerKeyHash)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - hashing ECDH peer public key fail", __func__);
		eap_bca_state(data, FAILURE);
		return;
	}
	
	data->ecdhPeerPublicKey = os_memdup(auth_msg->ecdhPeerPublicKey, 2 * BCA_ECDH_KEY_LENGTH);
	comb_shared_key = os_malloc(BCA_ECDH_KEY_LENGTH + BCA_ECDSA_KEY_LENGTH);
	
	if (bca_ecdh_generate_key(data->ecdhAuthPrivateKey, data->ecdhPeerPublicKey, comb_shared_key)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - ECDH key generation fail", __func__);
		eap_bca_state(data, FAILURE);
		os_free(comb_shared_key);
		return;
	}
	
	if (bca_ecdh_generate_key_by_dsa_keys(bca_global_data->authPrivateKey, auth_msg->ecEncPublicKey, comb_shared_key + BCA_ECDH_KEY_LENGTH)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - ECDH (ecEnc) key generation fail", __func__);
		eap_bca_state(data, FAILURE);
		os_free(comb_shared_key);
		return;
	}
	
	
	if (bca_generate_master_secret(comb_shared_key, BCA_ECDH_KEY_LENGTH + BCA_ECDSA_KEY_LENGTH,
			data->timestamp,
			data->ecdhAuthKeyHash,
			data->ecdhPeerKeyHash,
			data->masterSecret)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - master secret generation fail", __func__);
		eap_bca_state(data, FAILURE);
		os_free(comb_shared_key);
		return;
	}
	
	
	wpa_hexdump(MSG_MSGDUMP, "EAP-BCA: comb_shared_key", comb_shared_key, BCA_ECDH_KEY_LENGTH + BCA_ECDSA_KEY_LENGTH);
	
	
	key_block = os_malloc(BCA_KEY_BLOCK_LENGTH);
	cipher_parameters = os_malloc(sizeof(*cipher_parameters));
	auth_deciphered_msg = os_malloc(sizeof(*auth_deciphered_msg));
	
	if (key_block == NULL || cipher_parameters == NULL || auth_deciphered_msg == NULL) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - memory allocation error", __func__);
		eap_bca_state(data, FAILURE);
		os_free(comb_shared_key);
		return;
	}
	
	if (bca_generate_key_block(data->masterSecret, data->timestamp, data->ecdhAuthKeyHash, data->ecdhPeerKeyHash, key_block)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - key_block generate fail", __func__);
		eap_bca_state(data, FAILURE);
		os_free(auth_deciphered_msg);
		os_free(key_block);
		os_free(comb_shared_key);
		return;
	}
	
	os_memcpy(cipher_parameters->key,  key_block,  BCA_CIPHER_KEY_LENGTH);
	os_memcpy(cipher_parameters->salt, key_block + BCA_CIPHER_KEY_LENGTH, BCA_CIPHER_SALT_LENGTH);
	
	
	if (bca_cipher_decryption(auth_msg->ciphered, sizeof(auth_msg->ciphered),
			cipher_parameters,
			(u8 *) auth_deciphered_msg))
	{
		eap_bca_state(data, FAILURE);
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - decryption error", __func__);
		os_free(auth_deciphered_msg);
		os_free(cipher_parameters);
		os_free(key_block);
		os_free(comb_shared_key);
		return;
	}
	
	os_memcpy(data->peerPublicKey, auth_deciphered_msg->peerPublicKey, 2 * BCA_ECDSA_KEY_LENGTH);
	
	if (bca_hash_dsa_key(data->peerPublicKey, data->peerKeyHash)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - peer public key hashing fail", __func__);
		eap_bca_state(data, FAILURE);
		os_free(auth_deciphered_msg);
		os_free(cipher_parameters);
		os_free(key_block);
		os_free(comb_shared_key);
		return;
	}
	
	
	os_memcpy(sign_msg, BCA_PEER_AUTHENTICATION_SIGN_MSG_PREFIX, strlen(BCA_PEER_AUTHENTICATION_SIGN_MSG_PREFIX));
	WPA_PUT_BE64(sign_msg + strlen(BCA_PEER_AUTHENTICATION_SIGN_MSG_PREFIX), data->timestamp);
	os_memcpy(sign_msg + strlen(BCA_PEER_AUTHENTICATION_SIGN_MSG_PREFIX) + sizeof(data->timestamp),
			comb_shared_key, BCA_ECDH_KEY_LENGTH);
	if (!bca_ecdsa_validate(sign_msg, BCA_PEER_AUTHENTICATION_SIGN_MSG_LENGTH, auth_deciphered_msg->peerAuthenticationSign, data->peerPublicKey)) {
		eap_bca_state(data, FAILURE);
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - peer authentication signature validation fail", __func__);
		os_free(auth_deciphered_msg);
		os_free(cipher_parameters);
		os_free(key_block);
		os_free(comb_shared_key);
		return;
	}
	
	wpa_hexdump(MSG_MSGDUMP, "EAP-BCA: peerKeyHash", data->peerKeyHash, BCA_KEY_HASH_LENGTH);
	
	
	// check data->peerKeyHash access with blockchain contract
	if (bca_eth_aaa_contract_gen_access_token(data->peerKeyHash, data->bcContractPSK, access_token) ||
		bca_eth_aaa_contract_call_has_access(bca_global_data->ethIPCFilePath,
				data->bcContractAddress, bca_global_data->authAddress, access_token, &has_access)) {
		eap_bca_state(data, FAILURE);
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - peer access check with contract fails", __func__);
		os_free(auth_deciphered_msg);
		os_free(cipher_parameters);
		os_free(key_block);
		os_free(comb_shared_key);
		return;
	}
	
	wpa_hexdump(MSG_MSGDUMP, "EAP-BCA: access_token", access_token, BCA_ACCESS_TOKEN_LENGTH);
	
	if (has_access) {
		wpa_printf(MSG_INFO, "EAP-BCA: ACCESS GRANTED");
		eap_bca_state(data, SUCCESS);
	} else {
		wpa_printf(MSG_INFO, "EAP-BCA: ACCESS DENIED");
		eap_bca_state(data, FAILURE);
	}
	
	os_free(auth_deciphered_msg);
	os_free(cipher_parameters);
	os_free(key_block);
	os_free(comb_shared_key);
}


static Boolean eap_bca_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_bca_data *data = priv;
	return data->state == SUCCESS || data->state == FAILURE;
}


static u8 * eap_bca_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_bca_data *data = priv;
	u8 *eapKeyData, *msk;
	
	if (data->state != SUCCESS)
		return NULL;
	
	eapKeyData = os_malloc(EAP_MSK_LEN + EAP_EMSK_LEN);
	
	if (eapKeyData == NULL ||
		bca_generate_msk_key_block(data->masterSecret, data->timestamp, data->ecdhAuthKeyHash, data->ecdhPeerKeyHash, eapKeyData)
	) {
		msk = NULL;
	} else {
		msk = os_malloc(EAP_MSK_LEN);
		if (msk != NULL)
			os_memcpy(msk, eapKeyData, EAP_MSK_LEN);
		bin_clear_free(eapKeyData, EAP_MSK_LEN + EAP_EMSK_LEN);
	}
	
	if (msk != NULL) {
		*len = EAP_MSK_LEN;
		wpa_hexdump(MSG_DEBUG, "EAP-BCA: Derived key", msk, EAP_MSK_LEN);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-BCA: Failed to derive key");
	}
	
	return msk;
}


static u8 * eap_bca_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_bca_data *data = priv;
	u8 *eapKeyData, *emsk;
	
	if (data->state != SUCCESS)
		return NULL;
	
	eapKeyData = os_malloc(EAP_MSK_LEN + EAP_EMSK_LEN);
	
	if (eapKeyData == NULL ||
		bca_generate_msk_key_block(data->masterSecret, data->timestamp, data->ecdhAuthKeyHash, data->ecdhPeerKeyHash, eapKeyData))
	{
		emsk = NULL;
	} else {
		emsk = os_malloc(EAP_EMSK_LEN);
		if (emsk != NULL)
			os_memcpy(emsk, eapKeyData + EAP_MSK_LEN, EAP_EMSK_LEN);
		bin_clear_free(eapKeyData, EAP_MSK_LEN + EAP_EMSK_LEN);
	}
	
	if (emsk != NULL) {
		*len = EAP_EMSK_LEN;
		wpa_hexdump(MSG_DEBUG, "EAP-BCA: Derived EMSK", emsk, EAP_EMSK_LEN);
	} else {
		wpa_printf(MSG_DEBUG, "EAP-BCA: Failed to derive EMSK");
	}
	
	return emsk;
}


static Boolean eap_bca_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_bca_data *data = priv;
	return data->state == SUCCESS;
}


static u8 * eap_bca_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_bca_data *data = priv;
	
	if (data == NULL || data->state != SUCCESS)
		return NULL;
	
	return bca_derive_session_id(data->timestamp, data->ecdhAuthKeyHash, data->ecdhPeerKeyHash, len);
}


int eap_server_bca_register(void)
{
	struct eap_method *eap;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION, EAP_VENDOR_BCA, EAP_VENDOR_TYPE_BCA, "BCA");
	if (eap == NULL)
		return -1;

	eap->init = eap_bca_init;
	eap->reset = eap_bca_reset;
	eap->buildReq = eap_bca_buildReq;
	eap->check = eap_bca_check;
	eap->process = eap_bca_process;
	eap->isDone = eap_bca_isDone;
	eap->getKey = eap_bca_getKey;
	eap->isSuccess = eap_bca_isSuccess;
	eap->get_emsk = eap_bca_get_emsk;
	eap->getSessionId = eap_bca_get_session_id;

	return eap_server_method_register(eap);
}
