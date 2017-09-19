/*
 * hostapd / EAP-BCA
 * Copyright (c) 2017, David Amann
 */

#ifndef EAP_SERVER_BCA_COMMON_H
#define EAP_SERVER_BCA_COMMON_H

#include "utils/wpabuf.h"
#include "eap_common/eap_bca_common.h"


struct hostapd_data;

struct eap_bca_global_data {
	u8 authPrivateKey[BCA_ECDSA_KEY_LENGTH];
	u8 authPublicKey[2 * BCA_ECDSA_KEY_LENGTH];
	u8 authKeyHash[BCA_KEY_HASH_LENGTH];
	
	// u8 authKeySign[2 * BCA_ECDSA_KEY_LENGTH];
	// 
	// u8 caPublicKey[2 * BCA_ECDSA_KEY_LENGTH];
	// u8 caKeyHash[BCA_KEY_HASH_LENGTH];
	
	u8 authAddress[BCA_ETH_ADDR_LENGTH];
	char *authPassphrase;
	
	char *ethIPCFilePath;
} *bca_global_data;


struct eap_bca_data {
	//struct eap_ssl_data ssl;
	enum { START, CONTINUE, SUCCESS, FAILURE } state;
	
	
	u64 timestamp;
	
	u8 *ecdhAuthPrivateKey;
	u8 *ecdhAuthPublicKey;
	u8 *ecdhAuthKeyHash;
	// u8 *ecdhPeerPrivateKey;
	u8 *ecdhPeerPublicKey;
	u8 *ecdhPeerKeyHash;
	
	u8 *authAuthenticationSign;
	// u8 *peerAuthenticationSign;
	
	u8 *peerPublicKey;
	u8 *peerKeyHash;
	
	u8 *sharedKey;
	u8 *masterSecret;
	
	struct bca_cipher_parameters *combinedCipherParameters;
	
	u8 *bcContractAddress;
	u8 *bcContractPSK;
	
	u8 *authKeySign;
	
	u8 *caPublicKey;
	// u8 *caKeyHash;
	
	
	int isBCAccounting;
	int acct_session_started;
	
	u32 rx_packets;
	u32 tx_packets;
	u64 rx_bytes;
	u64 tx_bytes;
	
	u32 rx_start_packets;
	u32 tx_start_packets;
	u64 rx_start_bytes;
	u64 tx_start_bytes;
};


int bca_global_init(struct hostapd_data *hapd);
void bca_global_deinit(void);

struct wpabuf * eap_server_bca_build_msg(struct eap_bca_data *data, u8 id);


#endif /* EAP_SERVER_BCA_COMMON_H */
