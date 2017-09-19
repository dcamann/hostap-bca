/*
 * Test program for BCA functions
 */

#include "includes.h"
#include <sys/un.h>

#include "common.h"
#include "utils/cJSON.h"

#include "crypto/crypto.h"

#include "eap_common/eap_bca_common.h"


void bin2hexstr(const u8 *bin, const size_t bin_len, unsigned char *str)
{
	unsigned int i;
	static const unsigned char hexchars[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	
	for (i = 0; i < bin_len; ++i) {
		str[i * 2]       = hexchars[(bin[i] >> 4) & 0xf];
		str[(i * 2) + 1] = hexchars[ bin[i] & 0xf];
	}
	
	str[i * 2] = 0;
}

void printHex(const u8 *bin, const size_t bin_len, const char *preStr)
{
	unsigned char *hexstr;
	
	hexstr = os_malloc(2*bin_len + 1);
	
	bin2hexstr(bin, bin_len, hexstr);
	
	if (preStr != NULL)
		printf("%s", preStr);
	
	printf("%s\n", hexstr);
}





static int test_time()
{
	// unsigned char hexstrbuf[25];
	u64 timestamp;
	
	timestamp = bca_time_now();
	
	printf("Test bca_time_now: %15lld\n", timestamp);
	
	return 1;
}


static int test_ecdh_create_private_key()
{
	u8 privKey[64];
	unsigned char hexstrbuf[80];
	
	if (bca_ecdh_create_private_key(privKey))
		return 0;
	
	bin2hexstr(privKey, BCA_ECDH_KEY_LENGTH, hexstrbuf);
	printf("Test bca_ecdh_create_private_key: %s\n", hexstrbuf);
	
	return 1;
}


static int test_ecdh_create_public_key()
{
	u8 privKey[BCA_ECDH_KEY_LENGTH];
	u8 pubKey[2 * BCA_ECDH_KEY_LENGTH];
	unsigned char privKeyhex[80];
	unsigned char pubKeyhex[160];
	
	if (bca_ecdh_create_private_key(privKey))
		return 0;
	
	if (bca_ecdh_create_public_key(privKey, pubKey))
		return 0;
	
	bin2hexstr(privKey, BCA_ECDH_KEY_LENGTH, privKeyhex);
	bin2hexstr(pubKey, 2 * BCA_ECDH_KEY_LENGTH, pubKeyhex);
	printf("Test bca_ecdh_create_public_key:\nPrivate Key: %s\nPublic Key:  %s\n",
			privKeyhex,
			pubKeyhex);
	
	return 1;
}


static int test_hash_dsa_key()
{
	u8 privKey[BCA_ECDH_KEY_LENGTH];
	u8 pubKey[2 * BCA_ECDH_KEY_LENGTH];
	u8 keyHash[BCA_KEY_HASH_LENGTH];
	unsigned char privKeyhex[(2 * BCA_ECDH_KEY_LENGTH) + 1];
	unsigned char pubKeyhex[(2 * 2 * BCA_ECDH_KEY_LENGTH) + 1];
	unsigned char keyHashHex[(2 * BCA_KEY_HASH_LENGTH) + 1];
	
	if (bca_ecdh_create_private_key(privKey))
		return 0;
	
	if (bca_ecdh_create_public_key(privKey, pubKey))
		return 0;
	
	if (bca_hash_dsa_key(pubKey, keyHash))
		return 0;
	
	bin2hexstr(privKey, BCA_ECDH_KEY_LENGTH, privKeyhex);
	bin2hexstr(pubKey, 2 * BCA_ECDH_KEY_LENGTH, pubKeyhex);
	bin2hexstr(keyHash, BCA_KEY_HASH_LENGTH, keyHashHex);
	printf("Test bca_ecdh_create_public_key:\nPrivate Key: %s\nPublic Key:  %s\nKey Hash:    %s\n",
			privKeyhex,
			pubKeyhex,
			keyHashHex);
	
	return 1;
}


static int test_ecdh_generate_key()
{
	u8 authPrivateKey[BCA_ECDH_KEY_LENGTH];
	u8 authPublicKey[2 * BCA_ECDH_KEY_LENGTH];
	u8 authSharedKey[BCA_ECDH_KEY_LENGTH];

	u8 peerPrivateKey[BCA_ECDH_KEY_LENGTH];
	u8 peerPublicKey[2 * BCA_ECDH_KEY_LENGTH];
	u8 peerSharedKey[BCA_ECDH_KEY_LENGTH];
	
	unsigned char authSharedKeyhex[(2 * BCA_ECDH_KEY_LENGTH) + 1];
	unsigned char peerSharedKeyhex[(2 * BCA_ECDH_KEY_LENGTH) + 1];
	
	printf("start test_ecdh_generate_key\n");

	if (bca_ecdh_create_private_key(authPrivateKey) ||
		bca_ecdh_create_public_key(authPrivateKey, authPublicKey))
		return 0;
	
	if (bca_ecdh_create_private_key(peerPrivateKey) ||
		bca_ecdh_create_public_key(peerPrivateKey, peerPublicKey))
		return 0;
	
	printHex(authPrivateKey, BCA_ECDH_KEY_LENGTH, "authPrivateKey: ");
	printHex(authPublicKey, 2 * BCA_ECDH_KEY_LENGTH, "authPublicKey: ");
	printHex(peerPrivateKey, BCA_ECDH_KEY_LENGTH, "peerPrivateKey: ");
	printHex(peerPublicKey, 2 * BCA_ECDH_KEY_LENGTH, "peerPublicKey: ");
	
	if (bca_ecdh_generate_key(authPrivateKey, peerPublicKey, authSharedKey))
		return 0;
	
	if (bca_ecdh_generate_key(peerPrivateKey, authPublicKey, peerSharedKey))
		return 0;
	
	bin2hexstr(authSharedKey, BCA_ECDH_KEY_LENGTH, authSharedKeyhex);
	bin2hexstr(peerSharedKey, BCA_ECDH_KEY_LENGTH, peerSharedKeyhex);
	printf("end test_ecdh_generate_key:\nAuth. Shared Key: %s\nPeer Shared Key:  %s\n",
			authSharedKeyhex,
			peerSharedKeyhex);
	
	return 1;
}


static int test_ecdsa_sign_validate()
{
	u8 privKey[BCA_ECDH_KEY_LENGTH];
	u8 pubKey[2 * BCA_ECDH_KEY_LENGTH];
	u8 sign[(2 * BCA_ECDH_KEY_LENGTH) + 10];
	unsigned char privKeyhex[(2 * BCA_ECDH_KEY_LENGTH) + 1];
	unsigned char pubKeyhex[(2 * 2 * BCA_ECDH_KEY_LENGTH) + 1];
	unsigned char signHex[(2 * 2 * BCA_ECDH_KEY_LENGTH) + 20 + 1];
	
	const char test_msg[] = "This is a message!";
	
	if (bca_ecdh_create_private_key(privKey))
		return 0;
	
	if (bca_ecdh_create_public_key(privKey, pubKey))
		return 0;
	
	if (bca_ecdsa_sign(test_msg, strlen(test_msg), privKey, sign))
		return 0;
	
	if (!bca_ecdsa_validate(test_msg, strlen(test_msg), sign, pubKey)) {
		return 0;
	}
	
	bin2hexstr(privKey, BCA_ECDH_KEY_LENGTH, privKeyhex);
	bin2hexstr(pubKey, 2 * BCA_ECDH_KEY_LENGTH, pubKeyhex);
	bin2hexstr(sign, 2 * BCA_ECDH_KEY_LENGTH, signHex);
	printf("test_ecdsa_sign_validate:\nPrivate Key: %s\nPublic Key:  %s\nSign:        %s\n",
			privKeyhex,
			pubKeyhex,
			signHex);
	
	return 1;
}



static int test_bca_prf()
{
	u8 sharedKey[BCA_ECDH_KEY_LENGTH];
	u8 masterSecret[BCA_MASTER_SECRET_LENGTH];
	u8 randA[BCA_RANDOM_LENGTH];
	u8 randP[BCA_RANDOM_LENGTH];
	u8 prf_seed[2*BCA_RANDOM_LENGTH];
	
	unsigned char sharedKeyHex[(2 * BCA_ECDH_KEY_LENGTH) + 1];
	unsigned char masterSecretHex[(2 * BCA_MASTER_SECRET_LENGTH) + 1];
	unsigned char randAHex[(2 * BCA_RANDOM_LENGTH) + 1];
	unsigned char randPHex[(2 * BCA_RANDOM_LENGTH) + 1];
	
	
	if (random_get_bytes(randA, BCA_RANDOM_LENGTH) || random_get_bytes(randP, BCA_RANDOM_LENGTH))
		return 0;
	
	os_memcpy(prf_seed, randP, BCA_RANDOM_LENGTH);
	os_memcpy(prf_seed + BCA_RANDOM_LENGTH, randA, BCA_RANDOM_LENGTH);
	// masterSecret := prf(sharedKey, "master secret", randP ◦ randA, MasterSecretLength)
	bca_prf(sharedKey, BCA_MASTER_SECRET_LENGTH, "master secret", prf_seed, 2*BCA_RANDOM_LENGTH, masterSecret, BCA_MASTER_SECRET_LENGTH);
	
	
	bin2hexstr(sharedKey, BCA_ECDH_KEY_LENGTH, sharedKeyHex);
	bin2hexstr(randA, BCA_ECDH_KEY_LENGTH, randAHex);
	bin2hexstr(randP, BCA_ECDH_KEY_LENGTH, randPHex);
	bin2hexstr(masterSecret, BCA_MASTER_SECRET_LENGTH, masterSecretHex);
	printf("test_bca_prf:\nShared Key:  %s\nrandA:       %s\nrandP:       %s\nMaster Key:  %s\n",
			sharedKeyHex,
			randAHex,
			randPHex,
			masterSecretHex);
	
	return 1;
}


static int test_bca_cipher()
{
	struct bca_cipher_parameters *cipher_parameters;
	const char test_msg[] = "This is a message!";
	u8 *ciphertext;
	u8 *decryptedText;
	
	unsigned char msgHex[(2 * (strlen(test_msg) + 1)) + 1];
	unsigned char ciphertextHex[(2 * (BCA_CIPHER_NONCE_EX_LENGTH + strlen(test_msg) + 1 + BCA_CIPHER_BLOCK_LENGTH)) + 1];
	unsigned char decryptedTextHex[(2 * (strlen(test_msg) + 1)) + 1];
	
	
	ciphertext = os_malloc(BCA_CIPHER_NONCE_EX_LENGTH + strlen(test_msg) + 1 + BCA_CIPHER_BLOCK_LENGTH);
	decryptedText = os_malloc(strlen(test_msg) + 1);
	cipher_parameters = os_malloc(sizeof(*cipher_parameters));
	
	printf("test_bca_cipher:\n");
	
	bin2hexstr((u8 *) test_msg, strlen(test_msg) + 1, msgHex);
	printf("test_msg:    %s\n", msgHex);
	
	if (random_get_bytes(cipher_parameters->key, BCA_CIPHER_KEY_LENGTH) ||
		random_get_bytes(cipher_parameters->salt, BCA_CIPHER_SALT_LENGTH)) {
		printf("Error: test_bca_cipher - random_get_bytes\n");
		return 0;
	}
	
	if (bca_cipher_encryption((u8 *) test_msg, strlen(test_msg) + 1, cipher_parameters, ciphertext)) {
		printf("Error: test_bca_cipher - bca_cipher_encryption\n");
		return 0;
	}
	
	bin2hexstr(ciphertext, BCA_CIPHER_NONCE_EX_LENGTH + strlen(test_msg) + 1 + BCA_CIPHER_BLOCK_LENGTH, ciphertextHex);
	printf("ciphertext:  %s\n", ciphertextHex);
	
	if (bca_cipher_decryption(ciphertext, BCA_CIPHER_NONCE_EX_LENGTH + strlen(test_msg) + 1 + BCA_CIPHER_BLOCK_LENGTH, cipher_parameters, decryptedText)) {
		printf("Error: test_bca_cipher - bca_cipher_decryption\n");
		return 0;
	}
	
	bin2hexstr(decryptedText, strlen(test_msg) + 1, decryptedTextHex);
	printf("decrypted:   %s\n", decryptedTextHex);
	
	os_free(cipher_parameters);
	os_free(ciphertext);
	os_free(decryptedText);
	
	return 1;
}


static int test_bca_key_sign()
{
	u8 caPrivateKey[BCA_ECDSA_KEY_LENGTH];
	u8 caPublicKey[2 * BCA_ECDSA_KEY_LENGTH];
	u8 caKeyHash[BCA_KEY_HASH_LENGTH];
	
	u8 authPrivateKey[BCA_ECDSA_KEY_LENGTH];
	u8 authPublicKey[2 * BCA_ECDSA_KEY_LENGTH];
	u8 authKeyHash[BCA_KEY_HASH_LENGTH];
	
	u8 authKeySign[2 * BCA_ECDSA_KEY_LENGTH];
	
	printf("\ntest_bca_key_sign:\n");
	
	if (hexstr2bin("9597bd83bf7243b6a588172e8e9daec19dfba2d24f757daa6f75dc1d7503e9a8", caPrivateKey, 32))
		return 0;
	
	printHex(caPrivateKey, BCA_ECDSA_KEY_LENGTH, "caPrivateKey: ");
	
	if (hexstr2bin("0291e444ecb0cba525a13b490c25ab5b05d08e00590538e744628fe085e180d1", authPrivateKey, 32))
		return 0;
	
	printHex(authPrivateKey, BCA_ECDSA_KEY_LENGTH, "authPrivateKey: ");
	
	if (bca_ecdh_create_public_key(caPrivateKey, caPublicKey))
		return 0;
	
	printHex(caPublicKey, 2 * BCA_ECDSA_KEY_LENGTH, "caPublicKey: ");
	
	if (bca_ecdh_create_public_key(authPrivateKey, authPublicKey))
		return 0;
	
	printHex(authPublicKey, 2 * BCA_ECDSA_KEY_LENGTH, "authPublicKey: ");
	
	
	if (bca_hash_dsa_key(caPublicKey, caKeyHash))
		return 0;
	
	printHex(caKeyHash, BCA_KEY_HASH_LENGTH, "caKeyHash: ");
	
	if (bca_hash_dsa_key(authPublicKey, authKeyHash))
		return 0;
	
	printHex(authKeyHash, BCA_KEY_HASH_LENGTH, "authKeyHash: ");
	
	
	
	if (hexstr2bin("c9d756d28de58a8d3ebd873aee3c47c20dfbc0d9e1070538bb8b172d7ea2dc1a3ba72da0a78287ab50f893512dddfe8ef32efb696a48103d0b26eace8f4d7757", authKeySign, 64))
		return 0;
	
	printHex(authKeySign, 2 * BCA_ECDSA_KEY_LENGTH, "authKeySign: ");
	
	
	if (bca_ecdsa_validate(authPublicKey, 2 * BCA_ECDSA_KEY_LENGTH, authKeySign, caPublicKey)) {
		printf("bca_ecdsa_validate(authPublicKey, BCA_KEY_HASH_LENGTH, authKeySign, caPublicKey) == true\n");
	} else {
		printf("bca_ecdsa_validate(authPublicKey, BCA_KEY_HASH_LENGTH, authKeySign, caPublicKey) == false\n");
	}
	
	
	printf("gen. new authenticator key sign:\n");
	if (bca_ecdsa_sign(authPublicKey, 2 * BCA_ECDSA_KEY_LENGTH, caPrivateKey, authKeySign))
		return 0;
	
	printHex(authKeySign, 2 * BCA_ECDSA_KEY_LENGTH, "authKeySign: ");
	
	return 1;
}


static int test_geth_ipc_conn()
{
	const char *ipc_file_path = "/home/pi/.ethereum/testnet/geth.ipc";
	const char *req_msg = "{\"jsonrpc\":\"2.0\",\"method\":\"rpc_modules\",\"params\":[],\"id\":1}";
	
	int geth_ipc_socket;
	u8 *buffer;
	struct sockaddr_un address;
	int size;
	
	printf("test_geth_ipc_conn:\n");
	
	buffer = os_malloc(1024);
	
	geth_ipc_socket = socket(PF_LOCAL, SOCK_STREAM, 0);
	if(geth_ipc_socket <= 0) {
		printf("Error: Socket konnte nicht angelegt werden\n");
		return 0;
	}
	
	address.sun_family = AF_LOCAL;
	strcpy(address.sun_path, ipc_file_path);
	
	if (connect(geth_ipc_socket, (struct sockaddr *) &address, sizeof(address))) {
		printf("Error: Can't open socket\n");
		return 0;
	}
	
	printf("Verbindung mit geth hergestellt\n");
	
	send(geth_ipc_socket, req_msg, strlen(req_msg), 0);
	
	printf("Send: %s\n", req_msg);
	
	size = 0;
	u64 timeout = bca_time_now() + 2000;
	do {
		size += recv(geth_ipc_socket, buffer + size, 1024 - 1 - size, 0);
		if (size > 0 && buffer[size - 1] == 0x0a)
			break;
		os_sleep(0, 1000); // sleep 1ms
	} while (size <= 0 && timeout <= bca_time_now());
	
	buffer[size] = '\0';
	
	printf("Receiving %d Bytes\n", size);
	printf("Received: %s\n", buffer);
	printHex(buffer, size, "Received (hex): ");
	
	close(geth_ipc_socket);
	
	return 1;
}




static int test_geth_ipc_contract_call()
{
	const char *ipc_file_path = "/home/pi/.ethereum/testnet/geth.ipc";
	char *req_msg;
	
	struct wpabuf * parameter_buffer;
	
	
	req_msg = os_malloc(1024);
	
	parameter_buffer = wpabuf_alloc(512);
	wpabuf_put_be32(parameter_buffer, BCA_ETH_AAA_CONTRACT_METHODE_ACCESS_TOKEN);
	
	printHex((u8 *) wpabuf_head(parameter_buffer), wpabuf_len(parameter_buffer), "parameter_buffer (Hex): ");
	
	
	os_strlcpy(req_msg, "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"from\":\"0x1d7831d9d19d66d1104a0d532b13a623fba30f59\",\"to\":\"0x55110407995624598c6a935c57e31aa0a04d4494\",\"value\":\"0x0\",\"data\":\"0xdb83423df93171eb342d3ffba3008f3ec32b882352dd04a65651ba53292683733bc2c239\"}, \"latest\"],\"id\":1}\n", 1024);
	// parameter_buffer to hex
	//os_strlcpy(req_msg + strlen(req_msg), "],\"id\":1}", 1024 - strlen(req_msg));
	
	printf("req_msg: %s\n", req_msg);
	printHex((u8 *) req_msg, strlen(req_msg), "req_msg (Hex): ");
	
	
	int geth_ipc_socket;
	char *buffer;
	struct sockaddr_un address;
	int size;
	
	printf("test_geth_ipc_contract_call:\n");
	
	buffer = os_malloc(1024);
	
	geth_ipc_socket = socket(PF_LOCAL, SOCK_STREAM, 0);
	if(geth_ipc_socket <= 0) {
		printf("Error: Socket konnte nicht angelegt werden\n");
		return 0;
	}
	
	address.sun_family = AF_LOCAL;
	strcpy(address.sun_path, ipc_file_path);
	
	if (connect(geth_ipc_socket, (struct sockaddr *) &address, sizeof(address))) {
		printf("Error: Can't open socket\n");
		return 0;
	}
	
	printf("Verbindung mit geth hergestellt\n");
	
	send(geth_ipc_socket, req_msg, strlen(req_msg), 0);
	
	printf("Send: %s\n", req_msg);
	
	size = 0;
	u64 timeout = bca_time_now() + 2000;
	do {
		size += recv(geth_ipc_socket, buffer + size, 1024 - 1 - size, 0);
		if (size > 0 && buffer[size - 1] == 0x0a)
			break;
		os_sleep(0, 1000); // sleep 1ms
	} while (size <= 0 && timeout <= bca_time_now());
	
	buffer[size] = '\0';
	
	printf("Received: %s\n", buffer);
	printHex(buffer, size, "Received (hex): ");
	
	close(geth_ipc_socket);
	
	// {"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"missing value for required argument 1"}}
	// {"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000000000000000000000000000000000000000000000"}
	
	cJSON * root = cJSON_Parse(buffer);
	cJSON * err = cJSON_GetObjectItem(root, "error");
	if (err) {
		cJSON * err_msg = cJSON_GetObjectItem(root, "message");
		if (err_msg) {
			printf("Error: %s\n", cJSON_Print(err_msg));
		} else {
			printf("Error (no message)\n");
		}
		return 0;
	}
	
	
	cJSON * result_obj = cJSON_GetObjectItem(root, "result");
	char * result_str = result_obj->valuestring;
	size_t result_len;
	u8 *result;
	
	if (strlen(result_str) <= 2) {
		result_len = 0;
		result = NULL;
		
		printf("result = 0\n");
		return 1;
	} else if (strlen(result_str) & 1) {
		printf("Error: Incorrect hex string length (%d)\n", strlen(result_str));
		return 0;
	} else {
		result_len = (strlen(result_str) - 2) / 2;
		result = os_malloc(result_len);
	} 
	
	if (hexstr2bin(result_str + 2, result, result_len)) {
		printf("Error: hexstr2bin\n");
		return 0;
	}
	printf("result length: %d\n", result_len);
	printHex(result, result_len, "Message (hex): ");
	
	os_free(result);
	os_free(buffer);
	return 1;
}


static int test_bca_eth_gen_access_token()
{
	const char *psk_hex = "25f98e1db744c0630a7a6799a6ec82f1";
	const char *peer_key_hash_hex = "c83b5436f4383840fca20b0d89c8f5b9882df938630513937d0c3f850c66e393";
	const char *access_token_hex = "f93171eb342d3ffba3008f3ec32b882352dd04a65651ba53292683733bc2c239";
	
	u8 psk[BCA_CONTRACT_PSK_LENGTH];
	u8 peer_key_hash[BCA_KEY_HASH_LENGTH];
	u8 access_token[BCA_ACCESS_TOKEN_LENGTH];
	u8 gen_access_token[BCA_ACCESS_TOKEN_LENGTH];
	
	printf("\ntest_bca_eth_gen_access_token: ");
	
	if (hexstr2bin(psk_hex, psk, BCA_CONTRACT_PSK_LENGTH) ||
		hexstr2bin(peer_key_hash_hex, peer_key_hash, BCA_KEY_HASH_LENGTH) ||
		hexstr2bin(access_token_hex, access_token, BCA_ACCESS_TOKEN_LENGTH)) {
		printf("\nError in hexstr2bin\n");
		return 0;
	}
	
	if (bca_eth_aaa_contract_gen_access_token(peer_key_hash, psk, gen_access_token)) {
		printf("\nError in bca_eth_aaa_contract_call_has_access\n");
		return 0;
	}
	
	if (os_memcmp(access_token, gen_access_token, BCA_ACCESS_TOKEN_LENGTH) == 0)
		printf("Test success\n");
	else {
		printf("Test FAIL\n");
		return 0;
	}
	
	return 1;
}


static int test_bca_eth_call_has_access()
{
	const char *ipc_file_path = "/home/pi/.ethereum/testnet/geth.ipc";
	const char *contract_addr_hex = "55110407995624598c6a935c57e31aa0a04d4494";
	const char *from_addr_hex = "1d7831d9d19d66d1104a0d532b13a623fba30f59";
	const char *access_token_hex = "f93171eb342d3ffba3008f3ec32b882352dd04a65651ba53292683733bc2c239";
	
	u8 contract_addr[20];
	u8 from_addr[20];
	u8 access_token[BCA_ACCESS_TOKEN_LENGTH];
	u8 has_access;
	
	printf("\ntest_bca_eth_call_has_access:\n");
	
	if (hexstr2bin(contract_addr_hex, contract_addr, 20) ||
		hexstr2bin(from_addr_hex, from_addr, 20) ||
		hexstr2bin(access_token_hex, access_token, BCA_ACCESS_TOKEN_LENGTH)) {
		printf("Error in hexstr2bin\n");
		return 0;
	}
	
	if (bca_eth_aaa_contract_call_has_access(ipc_file_path, contract_addr, from_addr, access_token, &has_access)) {
		printf("Error in bca_eth_aaa_contract_call_has_access\n");
		return 0;
	}
	
	printf("has_access: %d\n", has_access);
	return 1;
}


static int test_bca_eth_call_get_ca_public_key()
{
	const char *ipc_file_path = "/home/pi/.ethereum/testnet/geth.ipc";
	const char *contract_addr_hex = "55110407995624598c6a935c57e31aa0a04d4494";
	const char *from_addr_hex = "1d7831d9d19d66d1104a0d532b13a623fba30f59";
	
	u8 contract_addr[20];
	u8 from_addr[20];
	u8 ca_public_key[2 * BCA_ECDSA_KEY_LENGTH];
	
	printf("\ntest_bca_eth_call_get_ca_public_key:\n");
	
	if (hexstr2bin(contract_addr_hex, contract_addr, 20) ||
		hexstr2bin(from_addr_hex, from_addr, 20)) {
		printf("Error in hexstr2bin\n");
		return 0;
	}
	
	if (bca_eth_aaa_contract_call_get_ca_public_key(ipc_file_path, contract_addr, from_addr, ca_public_key)) {
		printf("Error in bca_eth_aaa_contract_call_get_ca_public_key\n");
		return 0;
	}
	
	printHex(ca_public_key, 2 * BCA_ECDSA_KEY_LENGTH, "caPublicKey (hex): ");
	
	return 1;
}


static int test_bca_eth_call_get_auth_key_sign()
{
	const char *ipc_file_path = "/home/pi/.ethereum/testnet/geth.ipc";
	const char *contract_addr_hex = "55110407995624598c6a935c57e31aa0a04d4494";
	const char *from_addr_hex = "1d7831d9d19d66d1104a0d532b13a623fba30f59";
	const char *auth_key_hash_hex = "2e453c495585fd32688d003900bc59d95e07550aa229424ff5ee4c70923a902d";
	const size_t param_data_len = 4 + 32;
	
	u8 contract_addr[20];
	u8 from_addr[20];
	u8 auth_key_hash[BCA_KEY_HASH_LENGTH];
	u8 is_found;
	u8 auth_key_sign[2 * BCA_ECDSA_KEY_LENGTH];
	
	printf("\ntest_bca_eth_call_get_ca_public_key:\n");
	
	if (hexstr2bin(contract_addr_hex, contract_addr, 20) ||
		hexstr2bin(from_addr_hex, from_addr, 20) ||
		hexstr2bin(auth_key_hash_hex, auth_key_hash, BCA_KEY_HASH_LENGTH)) {
		printf("Error in hexstr2bin\n");
		return 0;
	}
	
	if (bca_eth_aaa_contract_call_get_auth_key_sign(ipc_file_path, contract_addr, from_addr, auth_key_hash, &is_found, auth_key_sign)) {
		printf("Error in bca_eth_aaa_contract_call_get_auth_key_sign\n");
		return 0;
	}
	
	if (is_found) {
		printf("authKeySign found\n");
		printHex(auth_key_sign, 2 * BCA_ECDSA_KEY_LENGTH, "authKeySign (hex): ");
	} else {
		printf("authKeySign not found\n");
	}
	
	
	// not fount result test part ...
	printf("\nNot found test part:\n");
	
	auth_key_hash[1] ^= 0x11;
	
	if (bca_eth_aaa_contract_call_get_auth_key_sign(ipc_file_path, contract_addr, from_addr, auth_key_hash, &is_found, auth_key_sign)) {
		printf("Error in bca_eth_aaa_contract_call_get_auth_key_sign\n");
		return 0;
	}
	
	if (is_found) {
		printf("authKeySign found\n");
		printHex(auth_key_sign, 2 * BCA_ECDSA_KEY_LENGTH, "authKeySign (hex): ");
	} else {
		printf("authKeySign not found\n");
	}
	
	return 1;
}



int main(int argc, char *argv[])
{
	int ret = 0;
	
	if (test_time()) {
		ret++;
	} else {
		printf("ERROR: test_time()\n");
	}
	
	if (test_ecdh_create_private_key()) {
		ret++;
	} else {
		printf("ERROR: test_ecdh_create_private_key()\n");
	}
	
	if (test_ecdh_create_public_key()) {
		ret++;
	} else {
		printf("ERROR: test_ecdh_create_public_key()\n");
	}
	
	if (test_hash_dsa_key()) {
		ret++;
	} else {
		printf("ERROR: test_hash_dsa_key()\n");
	}
	
	if (test_ecdh_generate_key()) {
		ret++;
	} else {
		printf("ERROR: test_ecdh_generate_key()\n");
	}
	
	if (test_ecdsa_sign_validate()) {
		ret++;
	} else {
		printf("ERROR: test_ecdsa_sign_validate()\n");
	}
	
	if (test_bca_prf()) {
		ret++;
	} else {
		printf("ERROR: test_bca_prf()\n");
	}
	
	if (test_bca_cipher()) {
		ret++;
	} else {
		printf("ERROR: test_bca_cipher()\n");
	}
	
	
	if (test_bca_key_sign()) {
		ret++;
	} else {
		printf("ERROR: test_bca_key_sign()\n");
	}
	
	
	if (test_geth_ipc_conn()) {
		ret++;
	} else {
		printf("ERROR: test_geth_ipc_conn()\n");
	}
	
	if (test_geth_ipc_contract_call()) {
		ret++;
	} else {
		printf("ERROR: test_geth_ipc_contract_call()\n");
	}
	
	if (test_bca_eth_gen_access_token()) {
		ret++;
	} else {
		printf("ERROR: test_bca_eth_gen_access_token()\n");
	}
	
	if (test_bca_eth_call_has_access()) {
		ret++;
	} else {
		printf("ERROR: test_bca_eth_call_has_access()\n");
	}
	
	if (test_bca_eth_call_get_ca_public_key()) {
		ret++;
	} else {
		printf("ERROR: test_bca_eth_call_get_ca_public_key()\n");
	}
	
	if (test_bca_eth_call_get_auth_key_sign()) {
		ret++;
	} else {
		printf("ERROR: test_bca_eth_call_get_auth_key_sign()\n");
	}
	
	
	return ret;
}
