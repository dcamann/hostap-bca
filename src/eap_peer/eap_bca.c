/*
 * hostapd / EAP-BCA
 * Copyright (c) 2017, David Amann
 */

#include "includes.h"

#include "common.h"
#include "crypto/tls.h"
#include "eap_i.h"
#include "eap_common/eap_bca_common.h"
#include "eap_bca_common.h"
#include "eap_config.h"


static void eap_bca_deinit(struct eap_sm *sm, void *priv);


struct eap_bca_data {
	u8 peerPrivateKey[BCA_ECDSA_KEY_LENGTH];
	u8 peerPublicKey[2 * BCA_ECDSA_KEY_LENGTH];
	u8 peerKeyHash[BCA_KEY_HASH_LENGTH];
	
	u8 caKeyHash[BCA_KEY_HASH_LENGTH];
	
	u8 authPublicKey[2 * BCA_ECDSA_KEY_LENGTH];
	
	u64 timestamp;
	
	u8 ecdhPeerPrivateKey[BCA_ECDH_KEY_LENGTH];
	u8 ecdhPeerPublicKey[2 * BCA_ECDH_KEY_LENGTH];
	u8 ecdhPeerKeyHash[BCA_KEY_HASH_LENGTH];
	
	u8 ecdhAuthPublicKey[2 * BCA_ECDH_KEY_LENGTH];
	
	u8 *key_data;
	u8 *session_id;
	size_t id_len;
};


static void * eap_bca_init(struct eap_sm *sm)
{
	struct eap_bca_data *data;
	struct eap_peer_config *config = eap_get_config(sm);
	
	if (config == NULL ||
		config->password == NULL ||
		config->password_len != (BCA_ECDSA_KEY_LENGTH + BCA_KEY_HASH_LENGTH)) {
		wpa_printf(MSG_INFO, "EAP-BCA: User password (Private key + CA key hash) not configured");
		return NULL;
	}
	
	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	
	os_memcpy(data->peerPrivateKey, config->password, BCA_ECDSA_KEY_LENGTH);
	os_memcpy(data->caKeyHash, config->password + BCA_ECDSA_KEY_LENGTH, BCA_KEY_HASH_LENGTH);
	
	if (bca_ecdsa_create_public_key(data->peerPrivateKey, data->peerPublicKey) ||
		bca_hash_dsa_key(data->peerPublicKey, data->peerKeyHash)) {
		eap_bca_deinit(sm, data);
		return NULL;
	}
	
	return data;
}


static void eap_bca_free_key(struct eap_bca_data *data)
{
	if (data->key_data) {
		bin_clear_free(data->key_data, EAP_MSK_LEN + EAP_EMSK_LEN);
		data->key_data = NULL;
	}
}


static void eap_bca_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_bca_data *data = priv;
	if (data == NULL)
		return;
	
	os_memset(data->peerPrivateKey, 0, BCA_ECDSA_KEY_LENGTH);
	
	eap_bca_free_key(data);
	os_free(data->session_id);
	os_free(data);
}


static struct wpabuf * eap_bca_process(struct eap_sm *sm, void *priv, struct eap_method_ret *ret, const struct wpabuf *reqData)
{
	struct eap_bca_data *data = priv;
	
	struct wpabuf *resp;
	const u8 *pos;
	size_t len;
	struct bca_msg_hdr *msg_header;
	struct bca_init_msg *init_msg;
	u8 init_msg_caKeyHash[BCA_KEY_HASH_LENGTH];
	u8 auth_sign_msg[BCA_AUTH_AUTHENTICATION_SIGN_MSG_LENGTH];
	u8 peer_sign_msg[BCA_PEER_AUTHENTICATION_SIGN_MSG_LENGTH];
	struct bca_auth_cipher_msg_part auth_deciphered_msg;
	struct bca_cipher_parameters *cipher_parameters;
	struct bca_auth_msg auth_msg;
	
	u8 ecdh_auth_key_hash[BCA_KEY_HASH_LENGTH];
	u8 comb_shared_key[BCA_ECDH_KEY_LENGTH + BCA_ECDSA_KEY_LENGTH];
	u8 ec_enc_private_key[BCA_ECDSA_KEY_LENGTH];
	u8 ec_enc_public_key[2 * BCA_ECDSA_KEY_LENGTH];
	
	u8 master_secret[BCA_MASTER_SECRET_LENGTH];
	u8 key_block[BCA_KEY_BLOCK_LENGTH];
	
	const u64 nowtimestamp = bca_time_now();
	
	wpa_printf(MSG_DEBUG, "EAP-BCA: start process ...");
	
	// check ...
	wpa_printf(MSG_DEBUG, "EAP-BCA: check request ...");
	
	pos = eap_hdr_validate(EAP_VENDOR_BCA, EAP_VENDOR_TYPE_BCA, reqData, &len);
	if (pos == NULL || len == 0) {
		wpa_printf(MSG_INFO, "EAP-BCA: Invalid frame (pos=%p len=%lu)", pos, (unsigned long) len);
		ret->ignore = TRUE;
		return NULL;
	}
	
	if (len != (sizeof(struct bca_msg_hdr) + sizeof(struct bca_init_msg))) {
		wpa_printf(MSG_INFO, "EAP-BCA: %s - unexpected message length %d", __func__, len);
		ret->ignore = TRUE;
		return NULL;
	}
	
	msg_header = (struct bca_msg_hdr *) pos;
	pos += sizeof(struct bca_msg_hdr);
	
	if (msg_header->type != BCA_MSG_TYPE_INIT) {
		wpa_printf(MSG_INFO, "EAP-BCA: %s - unexpected message type %d", __func__, msg_header->type);
		ret->ignore = TRUE;
		return NULL;
	}
	
	ret->ignore = FALSE;
	init_msg = (struct bca_init_msg *) pos;
	
	
	
	// process ...
	wpa_printf(MSG_DEBUG, "EAP-BCA: process request ...");
	
	data->timestamp = WPA_GET_BE64((u8 *) &init_msg->timestamp);
	
	// validate timestamp
	if ((data->timestamp + BCA_TIMESTAMP_MAX_DELTA) < nowtimestamp ||
		(data->timestamp - BCA_TIMESTAMP_MAX_DELTA) > nowtimestamp) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: Timestamp invalid - Authenticator and Peer clock not synchronized");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	// validate caPublicKey
	if (bca_hash_dsa_key(init_msg->caPublicKey, init_msg_caKeyHash) ||
		os_memcmp(data->caKeyHash, init_msg_caKeyHash, BCA_KEY_HASH_LENGTH) != 0) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: CA public key validation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	// validate Authenticator public key
	if (!bca_ecdsa_validate(init_msg->authPublicKey, 2 * BCA_ECDSA_KEY_LENGTH,
				init_msg->authKeySign,
				init_msg->caPublicKey)) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: Authenticator public key signature validation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	// validate Authenticator authentication signature
	os_memcpy(auth_sign_msg, BCA_AUTH_AUTHENTICATION_SIGN_MSG_PREFIX, strlen(BCA_AUTH_AUTHENTICATION_SIGN_MSG_PREFIX));
	WPA_PUT_BE64(auth_sign_msg + strlen(BCA_AUTH_AUTHENTICATION_SIGN_MSG_PREFIX), data->timestamp);
	os_memcpy(auth_sign_msg + strlen(BCA_AUTH_AUTHENTICATION_SIGN_MSG_PREFIX) + sizeof(data->timestamp),
			init_msg->ecdhAuthPublicKey, (2 * BCA_ECDH_KEY_LENGTH));
	if (!bca_ecdsa_validate(auth_sign_msg, BCA_AUTH_AUTHENTICATION_SIGN_MSG_LENGTH,
				init_msg->authAuthenticationSign,
				init_msg->authPublicKey)) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: Authenticator authentication signature validation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	
	// buildResp ...
	wpa_printf(MSG_DEBUG, "EAP-BCA: build response ...");
	
	if (bca_ecdh_create_private_key(data->ecdhPeerPrivateKey) ||
		bca_ecdh_create_public_key(data->ecdhPeerPrivateKey, data->ecdhPeerPublicKey) ||
		bca_hash_dh_key(data->ecdhPeerPublicKey, data->ecdhPeerKeyHash)) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: ECDH key pair creation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	if (bca_ecdsa_create_private_key(ec_enc_private_key) ||
		bca_ecdsa_create_public_key(ec_enc_private_key, ec_enc_public_key)) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: EC(DSA) key pair creation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	if (bca_hash_dh_key(init_msg->ecdhAuthPublicKey, ecdh_auth_key_hash)) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: ecdhAuthPublicKey hash generation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	if (bca_ecdh_generate_key(data->ecdhPeerPrivateKey, init_msg->ecdhAuthPublicKey, comb_shared_key) ||
		bca_ecdh_generate_key_by_dsa_keys(ec_enc_private_key, init_msg->authPublicKey,
				comb_shared_key + BCA_ECDH_KEY_LENGTH)) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: ECDH key generation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	
	wpa_hexdump(MSG_MSGDUMP, "EAP-BCA: comb_shared_key", comb_shared_key, BCA_ECDH_KEY_LENGTH + BCA_ECDSA_KEY_LENGTH);
	
	
	if (bca_generate_master_secret(comb_shared_key, BCA_ECDH_KEY_LENGTH + BCA_ECDSA_KEY_LENGTH,
				data->timestamp,
				ecdh_auth_key_hash,
				data->ecdhPeerKeyHash,
				master_secret)) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: master secret generation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	wpa_hexdump(MSG_MSGDUMP, "EAP-BCA: master_secret", master_secret, BCA_MASTER_SECRET_LENGTH);
	
	if (bca_generate_key_block(master_secret, data->timestamp, ecdh_auth_key_hash, data->ecdhPeerKeyHash, key_block)) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: key block generation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	wpa_hexdump(MSG_MSGDUMP, "EAP-BCA: key_block", key_block, BCA_KEY_BLOCK_LENGTH);
	
	
	cipher_parameters = os_malloc(sizeof(*cipher_parameters));
	if (cipher_parameters == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: cipher_parameters memory allocation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	os_memcpy(cipher_parameters->key,  key_block,  BCA_CIPHER_KEY_LENGTH);
	os_memcpy(cipher_parameters->salt, key_block + BCA_CIPHER_KEY_LENGTH, BCA_CIPHER_SALT_LENGTH);
	
	wpa_hexdump(MSG_MSGDUMP, "EAP-BCA: cipher_parameters->key", cipher_parameters->key, BCA_CIPHER_KEY_LENGTH);
	wpa_hexdump(MSG_MSGDUMP, "EAP-BCA: cipher_parameters->salt", cipher_parameters->salt, BCA_CIPHER_SALT_LENGTH);
	
	// create auth_deciphered_msg
	wpa_printf(MSG_DEBUG, "EAP-BCA: create auth_deciphered_msg ...");
	
	os_memcpy(auth_deciphered_msg.peerPublicKey, data->peerPublicKey, 2 * BCA_ECDSA_KEY_LENGTH);
	
	// generate peer authentication signature
	os_memcpy(peer_sign_msg, BCA_PEER_AUTHENTICATION_SIGN_MSG_PREFIX, strlen(BCA_PEER_AUTHENTICATION_SIGN_MSG_PREFIX));
	WPA_PUT_BE64(peer_sign_msg + strlen(BCA_PEER_AUTHENTICATION_SIGN_MSG_PREFIX), data->timestamp);
	os_memcpy(peer_sign_msg + strlen(BCA_PEER_AUTHENTICATION_SIGN_MSG_PREFIX) + sizeof(data->timestamp),
			comb_shared_key, (2 * BCA_ECDH_KEY_LENGTH));
	if (bca_ecdsa_sign(peer_sign_msg, BCA_PEER_AUTHENTICATION_SIGN_MSG_LENGTH,
				data->peerPrivateKey,
				auth_deciphered_msg.peerAuthenticationSign)) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: peer authentication signature generation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		os_free(cipher_parameters);
		return NULL;
	}
	
	
	// create auth_msg
	wpa_printf(MSG_DEBUG, "EAP-BCA: create auth_msg ...");
	
	os_memcpy(auth_msg.ecdhPeerPublicKey, data->ecdhPeerPublicKey, 2 * BCA_ECDH_KEY_LENGTH);
	os_memcpy(auth_msg.ecEncPublicKey, ec_enc_public_key, 2 * BCA_ECDSA_KEY_LENGTH);
	
	if (bca_cipher_encryption((u8 *) &auth_deciphered_msg, sizeof(auth_deciphered_msg),
				cipher_parameters, auth_msg.ciphered)) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: cipher encryption fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		os_free(cipher_parameters);
		return NULL;
	}
	
	os_free(cipher_parameters);
	
	
	wpa_printf(MSG_DEBUG, "EAP-BCA: build msg ...");
	
	// create response message with auth_msg as vendor data
	resp = eap_msg_alloc(EAP_VENDOR_BCA, EAP_VENDOR_TYPE_BCA,
			sizeof(struct bca_msg_hdr) + sizeof(struct bca_auth_msg),
			EAP_CODE_RESPONSE,
			eap_get_id(reqData));
	if (resp == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-BCA: message memory allocation fail");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	
	wpabuf_put_u8(resp, BCA_MSG_TYPE_AUTH);
	wpabuf_put_data(resp, (u8 *) &auth_msg, sizeof(auth_msg));
	
	wpa_hexdump(MSG_MSGDUMP, "EAP-BCA: Response", wpabuf_head(resp), wpabuf_len(resp));
	
	
	ret->methodState = METHOD_DONE;
	ret->decision = DECISION_UNCOND_SUCC;
	
	
	// Derived key (MSK & EMSK)
	eap_bca_free_key(data);
	data->key_data = os_malloc(EAP_MSK_LEN + EAP_EMSK_LEN);
	
	if (data->key_data == NULL ||
		bca_generate_msk_key_block(master_secret, data->timestamp, ecdh_auth_key_hash, data->ecdhPeerKeyHash, data->key_data)) {
		data->key_data = NULL;
	}
	
	if (data->key_data) {
		wpa_hexdump_key(MSG_DEBUG, "EAP-BCA: Derived key", data->key_data, EAP_MSK_LEN);
		wpa_hexdump_key(MSG_DEBUG, "EAP-BCA: Derived EMSK", data->key_data + EAP_MSK_LEN, EAP_EMSK_LEN);
	} else {
		wpa_printf(MSG_INFO, "EAP-BCA: Failed to derive key");
	}
	
	// Derived Session-Id
	os_free(data->session_id);
	data->session_id = bca_derive_session_id(data->timestamp, ecdh_auth_key_hash, data->ecdhPeerKeyHash, &data->id_len);
	
	if (data->session_id) {
		wpa_hexdump(MSG_DEBUG, "EAP-BCA: Derived Session-Id", data->session_id, data->id_len);
	} else {
		wpa_printf(MSG_ERROR, "EAP-BCA: Failed to derive Session-Id");
	}
	
	return resp;
}


static Boolean eap_bca_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_bca_data *data = priv;
	return data->key_data != NULL;
}


static u8 * eap_bca_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_bca_data *data = priv;
	u8 *key;

	if (data->key_data == NULL)
		return NULL;

	key = os_memdup(data->key_data, EAP_MSK_LEN);
	if (key == NULL)
		return NULL;

	*len = EAP_MSK_LEN;

	return key;
}


static u8 * eap_bca_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_bca_data *data = priv;
	u8 *key;

	if (data->key_data == NULL)
		return NULL;

	key = os_memdup(data->key_data + EAP_MSK_LEN, EAP_EMSK_LEN);
	if (key == NULL)
		return NULL;

	*len = EAP_EMSK_LEN;

	return key;
}


static u8 * eap_bca_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_bca_data *data = priv;
	u8 *id;

	if (data->session_id == NULL)
		return NULL;

	id = os_memdup(data->session_id, data->id_len);
	if (id == NULL)
		return NULL;

	*len = data->id_len;

	return id;
}



int eap_peer_bca_register(void)
{
	struct eap_method *eap;
	
	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION, EAP_VENDOR_BCA, EAP_VENDOR_TYPE_BCA, "BCA");
	if (eap == NULL)
		return -1;
	
	eap->init = eap_bca_init;
	eap->deinit = eap_bca_deinit;
	eap->process = eap_bca_process;
	eap->isKeyAvailable = eap_bca_isKeyAvailable;
	eap->getKey = eap_bca_getKey;
	eap->getSessionId = eap_bca_get_session_id;
	eap->get_emsk = eap_bca_get_emsk;
	
	return eap_peer_method_register(eap);
}
