/*
 * EAP-BCA common routines
 * Copyright (c) 2017, David Amann
 */

#ifndef EAP_BCA_COMMON_H
#define EAP_BCA_COMMON_H

#include "common/defs.h"

#define BCA_ECDH_KEY_BIT_LENGTH		256
#define BCA_ECDH_KEY_LENGTH			(BCA_ECDH_KEY_BIT_LENGTH / 8)
#define BCA_ECDSA_KEY_BIT_LENGTH	256
#define BCA_ECDSA_KEY_LENGTH		(BCA_ECDSA_KEY_BIT_LENGTH / 8)
#define BCA_RANDOM_LENGTH			32
#define BCA_KEY_HASH_LENGTH			32
#define BCA_CIPHER_NONCE_EX_LENGTH	8
#define BCA_CIPHER_KEY_BIT_LENGTH	128
#define BCA_CIPHER_KEY_LENGTH		(BCA_CIPHER_KEY_BIT_LENGTH / 8)
#define BCA_CIPHER_SALT_LENGTH		4
#define BCA_CIPHER_GCM_IV_LENGTH	(BCA_CIPHER_SALT_LENGTH + BCA_CIPHER_NONCE_EX_LENGTH)
#define BCA_CIPHER_BLOCK_LENGTH		16
#define BCA_KEY_BLOCK_LENGTH		(BCA_CIPHER_KEY_LENGTH + BCA_CIPHER_SALT_LENGTH)
#define BCA_MASTER_SECRET_LENGTH	48

#define BCA_TIMESTAMP_MAX_DELTA		(5 * 60 * 1000)


#define BCA_ETH_ADDR_LENGTH			20
#define BCA_CONTRACT_PSK_LENGTH		16

#define BCA_ACCESS_TOKEN_LENGTH		32
#define BCA_ACCOUNTING_MSG_LENGTH	32


#define BCA_AUTH_AUTHENTICATION_SIGN_MSG_PREFIX	"EAP-BCA-Authenticator-Auth"
#define BCA_PEER_AUTHENTICATION_SIGN_MSG_PREFIX	"EAP-BCA-Peer-Auth"

#define BCA_AUTH_AUTHENTICATION_SIGN_MSG_LENGTH	(strlen(BCA_AUTH_AUTHENTICATION_SIGN_MSG_PREFIX) + 8 + (2 * BCA_ECDH_KEY_LENGTH))
#define BCA_PEER_AUTHENTICATION_SIGN_MSG_LENGTH	(strlen(BCA_PEER_AUTHENTICATION_SIGN_MSG_PREFIX) + 8 + BCA_ECDH_KEY_LENGTH)


// 0x06a4f1fd = bytes4(sha3("accessToken(bytes32,bytes)"))
#define BCA_ETH_AAA_CONTRACT_METHODE_ACCESS_TOKEN		((u32) 0x06a4f1fd)

//0xdb83423d = bytes4(sha3("hasAccess(bytes32)"))
#define BCA_ETH_AAA_CONTRACT_METHODE_HAS_ACCESS			((u32) 0xdb83423d)

// 0x5888cee5 = bytes4(sha3("getAuthKeySign(bytes32)"))
#define BCA_ETH_AAA_CONTRACT_METHODE_GET_AUTH_KEY_SIGN	((u32) 0x5888cee5)

// 0x819df481 = bytes4(sha3("getCAPublicKey()"))
#define BCA_ETH_AAA_CONTRACT_METHODE_GET_CA_PUBLIC_KEY	((u32) 0x819df481)

// 0x2b200b9f = bytes4(sha3("updateAccounting(bytes32,bytes)"))
#define BCA_ETH_AAA_CONTRACT_METHODE_UPDATE_ACCOUNTING	((u32) 0x2b200b9f)

// 0x4aa9557d = bytes4(sha3("getAccountingEntryCount(bytes32)"))
#define BCA_ETH_AAA_CONTRACT_METHODE_GET_ACCOUNTING_ENTRY_COUNT	((u32) 0x4aa9557d)


enum {
	BCA_MSG_TYPE_INIT = 0,
	BCA_MSG_TYPE_AUTH = 1
} bca_msg_typ;


struct bca_cipher_parameters {
	u8 key[BCA_CIPHER_KEY_LENGTH];
	u8 salt[BCA_CIPHER_SALT_LENGTH];
};


struct bca_msg_hdr {
	u8 type;
};


struct bca_init_msg {
	u64 timestamp;
	u8  caPublicKey[2 * BCA_ECDSA_KEY_LENGTH];
	u8  authPublicKey[2 * BCA_ECDSA_KEY_LENGTH];
	u8  authKeySign[2 * BCA_ECDSA_KEY_LENGTH];
	u8  ecdhAuthPublicKey[2 * BCA_ECDH_KEY_LENGTH];
	u8  authAuthenticationSign[2 * BCA_ECDSA_KEY_LENGTH];
};


struct bca_auth_cipher_msg_part {
	u8  peerPublicKey[2 * BCA_ECDSA_KEY_LENGTH];
	u8  peerAuthenticationSign[2 * BCA_ECDSA_KEY_LENGTH];
};

struct bca_auth_msg {
	u8  ecdhPeerPublicKey[2 * BCA_ECDH_KEY_LENGTH];
	u8  ecEncPublicKey[2 * BCA_ECDSA_KEY_LENGTH];
	u8  ciphered[BCA_CIPHER_NONCE_EX_LENGTH + sizeof(struct bca_auth_cipher_msg_part) + BCA_CIPHER_BLOCK_LENGTH];
};





static inline void wpabuf_put_be64(struct wpabuf *buf, u64 data)
{
	u8 *pos = (u8 *) wpabuf_put(buf, 8);
	WPA_PUT_BE64(pos, data);
}



u64 bca_time_now();

int bca_ecdh_create_private_key(u8 *privKey);
int bca_ecdsa_create_private_key(u8 *privKey);
int bca_ecdh_create_public_key(const u8 *privKey, u8 *pubKey);
int bca_ecdsa_create_public_key(const u8 *privKey, u8 *pubKey);
int bca_hash_dsa_key(const u8 *pubKey, u8 *keyHash);
int bca_hash_dh_key(const u8 *pubKey, u8 *keyHash);

int bca_ecdh_generate_key(const u8 *privKey, const u8 *pubKey, u8 *key);
int bca_ecdh_generate_key_by_dsa_keys(const u8 *privKey, const u8 *pubKey, u8 *key);

int bca_ecdsa_sign(const u8 *msg, size_t msg_len, const u8 *privKey, u8 *sign);
Boolean bca_ecdsa_validate(const u8 *msg, size_t msg_len, const u8 *sign, const u8 *pubKey);

void bca_prf(const u8 *secret, size_t secret_len, const char *label, const u8 *seed, size_t seed_len, u8 *out, size_t length);
int bca_generate_master_secret(const u8 *sharedKey, size_t sharedKeyLen, const u64 timestamp, const u8 *authKeyHash, const u8 *peerKeyHash, u8 *masterSecret);
int bca_generate_key_block(const u8 *masterSecret, const u64 timestamp, const u8 *authKeyHash, const u8 *peerKeyHash, u8 *keyBlock);
int bca_generate_msk_key_block(const u8 *masterSecret, const u64 timestamp, const u8 *authKeyHash, const u8 *peerKeyHash, u8 *mskBlock);

int bca_cipher_encryption(const u8 *msg, const size_t msg_len, const struct bca_cipher_parameters *cipher_parameters, u8 *crypt);
int bca_cipher_decryption(const u8 *crypt, const size_t crypt_len, const struct bca_cipher_parameters *cipher_parameters, u8 *msg);

u8 * bca_derive_session_id(const u64 timestamp, const u8 *authKeyHash, const u8 *peerKeyHash, size_t *len);

int bca_eth_call(const char *ipc_file_path, const u8 *contract_addr, const u8 *from_addr, const u8 *param_data, size_t param_data_len, u8 **result, size_t *result_len);
int bca_eth_aaa_contract_call_has_access(const char *ipc_file_path, const u8 *contract_addr, const u8 *from_addr, const u8 *access_token, u8 *has_access);
int bca_eth_aaa_contract_call_get_ca_public_key(const char *ipc_file_path, const u8 *contract_addr, const u8 *from_addr, u8 *ca_public_key);
int bca_eth_aaa_contract_call_get_auth_key_sign(const char *ipc_file_path,
		const u8 *contract_addr, const u8 *from_addr,
		const u8 *auth_key_hash, u8 *is_found, u8 *auth_key_sign);

int bca_eth_aaa_contract_gen_access_token(const u8 *peer_key_hash, const u8 *psk, u8 *access_token);

int bca_eth_sendTransaction(const char *ipc_file_path, const u8 *contract_addr, const u8 *from_addr, const u8 *param_data, size_t param_data_len, u8 **result, size_t *result_len);
int bca_eth_unlockAccount(const char *ipc_file_path, const u8 *account_addr, const char *passphrase);

int bca_eth_aaa_contract_update_accounting(const char *ipc_file_path, const u8 *contract_addr, const u8 *auth_addr, const char *auth_passphrase, const u8 *access_token, const u8 *accounting_msg, size_t accounting_msg_len);

int bca_eth_aaa_contract_call_get_accounting_entry_count(
		const char *ipc_file_path, const u8 *contract_addr, const u8 *from_addr,
		const u8 *access_token, u64 *count);


#endif /* EAP_BCA_COMMON_H */
