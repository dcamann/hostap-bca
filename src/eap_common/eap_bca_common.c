/*
 * EAP-BCA common routines
 * Copyright (c) 2017, David Amann
 */

#include "includes.h"
#include <sys/un.h>

#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>

#include "common.h"
#include "eap_common/eap_defs.h"
#include "utils/wpabuf.h"
#include "crypto/sha256.h"
#include "crypto/aes_wrap.h"
#include "crypto/crypto.h"
#include "crypto/random.h"
#include "eap_bca_common.h"
#include "utils/cJSON.h"

// #include "crypto/ec/ec_lcl.h"



int bca_EC_POINT_to_oct(const EC_KEY *key, const EC_POINT *p, u8 *out);
int bca_oct_to_EC_POINT(const EC_KEY *key, const u8 *in, EC_POINT **p);




int bca_EC_KEY_set_private_key_by_oct(EC_KEY *eckey, const u8 *privKey, const size_t privKey_len)
{
	BIGNUM *bn;
	
	bn = BN_bin2bn(privKey, privKey_len, NULL);
	if (bn == NULL)
		return -1;
	
	if (!EC_KEY_set_private_key(eckey, bn)) {
		BN_clear_free(bn);
		return -1;
	}
	
	return 0;
}

static int bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    int i;
    BN_ULONG l;

    bn_check_top(a);
    i = BN_num_bytes(a);
    if (tolen == -1)
        tolen = i;
    else if (tolen < i)
        return -1;
    /* Add leading zeroes if necessary */
    if (tolen > i) {
        memset(to, 0, tolen - i);
        to += tolen - i;
    }
    while (i--) {
        l = a->d[i / BN_BYTES];
        *(to++) = (unsigned char)(l >> (8 * (i % BN_BYTES))) & 0xff;
    }
    return tolen;
}





u64 bca_time_now()
{
	struct os_time now;
	u64 timestamp;
	
	os_get_time(&now);
	
	timestamp = ((u64) now.sec) * 1000L;
	timestamp += ((u64) now.usec) / 1000;
	return timestamp;
}


int bca_ecdh_create_private_key(u8 *privKey)
{
	EC_KEY *eckey;
	
    const BIGNUM *priv_key_bn;
    u8 priv_key_buf[BCA_ECDH_KEY_LENGTH];
	
	
	// curve_name = "secp256r1" -> NID_X9_62_prime256v1
	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL)
		return -1;
	
	if (!EC_KEY_generate_key(eckey)) {
		EC_KEY_free(eckey);
		return -1;
	}
	
	priv_key_bn = EC_KEY_get0_private_key(eckey);
	
	if (priv_key_bn == NULL ||
		bn2binpad(priv_key_bn, priv_key_buf, BCA_ECDH_KEY_LENGTH) == -1)
	{
		EC_KEY_free(eckey);
		return -1;
	}
	
	os_memcpy(privKey, priv_key_buf, BCA_ECDH_KEY_LENGTH);
	EC_KEY_free(eckey);
	return 0;
}

int bca_ecdsa_create_private_key(u8 *privKey)
{
	return bca_ecdh_create_private_key(privKey);
}


int bca_ecdh_create_public_key(const u8 *privKey, u8 *pubKey)
{
	EC_KEY *eckey;
	const BIGNUM *ecprivatekey;
	EC_POINT *ecpubkey;
	const EC_GROUP *group;
	
	
	// curve_name = "secp256r1" -> NID_X9_62_prime256v1
	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL)
		return -1;
	
	if (bca_EC_KEY_set_private_key_by_oct(eckey, privKey, BCA_ECDSA_KEY_LENGTH)) {
		EC_KEY_free(eckey);
		return -1;
	}
	
	group = EC_KEY_get0_group(eckey);
	ecprivatekey = EC_KEY_get0_private_key(eckey);
	ecpubkey = EC_POINT_new(group);
	
	if (!EC_POINT_mul(group, ecpubkey, ecprivatekey, NULL, NULL, NULL)) {
		EC_KEY_free(eckey);
		return -1;
	}
	
	//ecpubkey = EC_KEY_get0_public_key(eckey);
	
	if (ecpubkey == NULL) {
		EC_KEY_free(eckey);
		return -1;
	}
	
	if (bca_EC_POINT_to_oct(eckey, ecpubkey, pubKey)) {
		EC_KEY_free(eckey);
		EC_POINT_free((EC_POINT *) ecpubkey);
		return -1;
	}
	
	EC_KEY_free(eckey);
	//EC_POINT_free((EC_POINT *) ecpubkey);
	
	return 0;
}


int bca_ecdsa_create_public_key(const u8 *privKey, u8 *pubKey)
{
	return bca_ecdh_create_public_key(privKey, pubKey);
}


int bca_hash_dsa_key(const u8 *pubKey, u8 *keyHash)
{
	const u8 *sha256_vector_addr[1];
	size_t sha256_vector_len[1];
	
	sha256_vector_addr[0] = pubKey;
	sha256_vector_len[0] = 2 * BCA_ECDSA_KEY_LENGTH;
	
	if (sha256_vector(1, sha256_vector_addr, sha256_vector_len, keyHash))
		return -1;
	
	return  0;
}

int bca_hash_dh_key(const u8 *pubKey, u8 *keyHash)
{
	return bca_hash_dsa_key(pubKey, keyHash);
}


void bin2hexstr2(const u8 *bin, const size_t bin_len, unsigned char *str)
{
	unsigned int i;
	static const unsigned char hexchars[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	
	for (i = 0; i < bin_len; ++i) {
		str[i * 2]       = hexchars[(bin[i] >> 4) & 0xf];
		str[(i * 2) + 1] = hexchars[ bin[i] & 0xf];
	}
	
	str[i * 2] = 0;
}

void printHex2(const u8 *bin, const size_t bin_len, const char *preStr)
{
	unsigned char *hexstr;
	
	hexstr = os_malloc(2*bin_len + 1);
	
	bin2hexstr2(bin, bin_len, hexstr);
	
	if (preStr != NULL)
		printf("%s", preStr);
	
	printf("%s\n", hexstr);
}




int bca_ecdh_generate_key(const u8 *privKey, const u8 *pubKey, u8 *key)
{
	EC_KEY *eckey;
	EC_POINT *ecpubkey = NULL;
	
    BN_CTX *ctx;
	const EC_GROUP *group;
	const BIGNUM *ecprivatekey;
	EC_POINT *sharedPoint;
	u8 sharedPointBin[2 * BCA_ECDH_KEY_LENGTH];
	
	
	// curve_name = "secp256r1" -> NID_X9_62_prime256v1
	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL)
		return -1;
	
	if (bca_EC_KEY_set_private_key_by_oct(eckey, privKey, BCA_ECDSA_KEY_LENGTH)) {
		EC_KEY_free(eckey);
		return -1;
	}
	
	if (bca_oct_to_EC_POINT(eckey, pubKey, &ecpubkey)) {
		EC_KEY_free(eckey);
		return -1;
	}
	
	ctx = BN_CTX_new();
    if (ctx == NULL) {
		EC_KEY_free(eckey);
		return -1;
	}
	
	group = EC_KEY_get0_group(eckey);
	ecprivatekey = EC_KEY_get0_private_key(eckey);
	sharedPoint = EC_POINT_new(group);
	
	
	if (EC_POINT_is_at_infinity(group, ecpubkey)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Error ecpubkey = INV.");
		EC_KEY_free(eckey);
		return -1;
	}
	
	
	// if (ECDH_compute_key(key, BCA_ECDH_KEY_LENGTH, ecpubkey, eckey, NULL) != BCA_ECDH_KEY_LENGTH) {
	// 	return -1;
	// }
	
	if (sharedPoint == NULL) {
		EC_KEY_free(eckey);
		return -1;
	}
	
	
	// if (hexstr2bin("A728B5C4A96D155ABB9E6B0A340A47D181716FC71E6A5D7611D2DA3AFFEF0061443272EC2B40E3AD526424C33C8A42451580425724A00420F0150D64E787ECDB", hexstrbuf, 64)) {
	// 	EC_KEY_free(eckey);
	// 	return -1;
	// }
	// bca_oct_to_EC_POINT(eckey, hexstrbuf, &sharedPoint);
	
	
/** Computes r = generator * n + q * m
 *  \param  group  underlying EC_GROUP object
 *  \param  r      EC_POINT object for the result
 *  \param  n      BIGNUM with the multiplier for the group generator (optional)
 *  \param  q      EC_POINT object with the first factor of the second summand
 *  \param  m      BIGNUM with the second factor of the second summand
 *  \param  ctx    BN_CTX object (optional)
 *  \return 1 on success and 0 if an error occurred
 
int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);

EC_POINT_mul(e->group, (EC_POINT *) res , NULL, (const EC_POINT *) p, (const BIGNUM *) b, e->bnctx)
*/
	if (!EC_POINT_mul(group, sharedPoint, NULL, ecpubkey, ecprivatekey, ctx)) {
		EC_KEY_free(eckey);
		return -1;
	}
	BN_CTX_free(ctx);
	
	
	if (EC_POINT_is_at_infinity(group, sharedPoint)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Error sharedPoint = INV.");
		EC_KEY_free(eckey);
		return -1;
	}
	
	if (bca_EC_POINT_to_oct(eckey, sharedPoint, sharedPointBin)) {
		EC_KEY_free(eckey);
		return -1;
	}
	os_memcpy(key, sharedPointBin, BCA_ECDH_KEY_LENGTH);
	
	EC_POINT_free(ecpubkey);
	EC_KEY_free(eckey);
	return 0;
}


int bca_ecdh_generate_key_by_dsa_keys(const u8 *privKey, const u8 *pubKey, u8 *key)
{
	return bca_ecdh_generate_key(privKey, pubKey, key);
}


int bca_ecdsa_sign(const u8 *msg, size_t msg_len, const u8 *privKey, u8 *sign)
{
	EC_KEY *eckey;
	const u8 *sha256_vector_addr[1];
	size_t sha256_vector_len[1];
	u8 hash[SHA256_MAC_LEN];
 	ECDSA_SIG *ecdsa_sign;
    const BIGNUM *sign_r, *sign_s;
    u8 bn_buf[BCA_ECDSA_KEY_LENGTH];
	
	sha256_vector_addr[0] = msg;
	sha256_vector_len[0] = msg_len;
	
	// curve_name = "secp256r1" -> NID_X9_62_prime256v1
	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL)
		return -1;
	
	if (bca_EC_KEY_set_private_key_by_oct(eckey, privKey, BCA_ECDSA_KEY_LENGTH) ||
		sha256_vector(1, sha256_vector_addr, sha256_vector_len, hash))
	{
		EC_KEY_free(eckey);
		return -1;
	}
	
	/** Computes the ECDSA signature of the given hash value using
	 *  the supplied private key and returns the created signature.
	 *  \param  dgst      pointer to the hash value
	 *  \param  dgst_len  length of the hash value
	 *  \param  eckey     EC_KEY object containing a private EC key
	 *  \return pointer to a ECDSA_SIG structure or NULL if an error occurred
	 */
	ecdsa_sign = ECDSA_do_sign(hash, SHA256_MAC_LEN, eckey);
	if (ecdsa_sign == NULL) {
		EC_KEY_free(eckey);
		return -1;
	}
	
	//ECDSA_SIG_get0(ecdsa_sign, &sign_r, &sign_s);
	sign_r = ecdsa_sign->r;
	sign_s = ecdsa_sign->s;
	
	
	if (bn2binpad(sign_r, bn_buf, BCA_ECDSA_KEY_LENGTH) == -1) {
		EC_KEY_free(eckey);
		return -1;
	}
	os_memcpy(sign, bn_buf, BCA_ECDSA_KEY_LENGTH);
	
	if (bn2binpad(sign_s, bn_buf, BCA_ECDSA_KEY_LENGTH) == -1) {
		EC_KEY_free(eckey);
		return -1;
	}
	os_memcpy(sign + BCA_ECDSA_KEY_LENGTH, bn_buf, BCA_ECDSA_KEY_LENGTH);
	
	EC_KEY_free(eckey);
	return 0;
}


Boolean bca_ecdsa_validate(const u8 *msg, size_t msg_len, const u8 *sign, const u8 *pubKey)
{
	EC_KEY *eckey;
	int sign_verify_res;
	const u8 *sha256_vector_addr[1];
	size_t sha256_vector_len[1];
	u8 hash[SHA256_MAC_LEN];
	ECDSA_SIG *ecdsa_sign;
    BIGNUM *sign_r, *sign_s;
	EC_POINT *ecpubkey = NULL;
	
	sha256_vector_addr[0] = msg;
	sha256_vector_len[0] = msg_len;
	
	// curve_name = "secp256r1" -> NID_X9_62_prime256v1
	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL)
		return FALSE;
	
	if (bca_oct_to_EC_POINT(eckey, pubKey, &ecpubkey) ||
		!EC_KEY_set_public_key(eckey, ecpubkey))
	{
		if (ecpubkey != NULL) {
			EC_POINT_free(ecpubkey);
		}
		EC_KEY_free(eckey);
		return FALSE;
	}
	EC_POINT_free(ecpubkey);
	
	
	if (sha256_vector(1, sha256_vector_addr, sha256_vector_len, hash)) {
		EC_KEY_free(eckey);
		return FALSE;
	}
	
	sign_r = BN_bin2bn(sign, BCA_ECDSA_KEY_LENGTH, NULL);
	sign_s = BN_bin2bn(sign + BCA_ECDSA_KEY_LENGTH, BCA_ECDSA_KEY_LENGTH, NULL);
	
	ecdsa_sign = ECDSA_SIG_new();
	//ECDSA_SIG_set0(ecdsa_sign, sign_r, sign_s);
	ecdsa_sign->r = sign_r;
	ecdsa_sign->s = sign_s;
	
	/** Verifies that the supplied signature is a valid ECDSA
	 *  signature of the supplied hash value using the supplied public key.
	 *  \param  dgst      pointer to the hash value
	 *  \param  dgst_len  length of the hash value
	 *  \param  sig       ECDSA_SIG structure
	 *  \param  eckey     EC_KEY object containing a public EC key
	 *  \return 1 if the signature is valid, 0 if the signature is invalid
	 *          and -1 on error
	 */
	sign_verify_res = ECDSA_do_verify(hash, SHA256_MAC_LEN, ecdsa_sign, eckey);
	
	if (sign_verify_res != 1) {
		EC_KEY_free(eckey);
		return FALSE;
	}
	
	EC_KEY_free(eckey);
	return TRUE;
}



void bca_prf(const u8 *secret, size_t secret_len, const char *label, const u8 *seed, size_t seed_len, u8 *out, size_t length)
{
	tls_prf_sha256(secret, secret_len, label, seed, seed_len, out, length);
}


int bca_generate_master_secret(const u8 *sharedKey, size_t sharedKeyLen, const u64 timestamp, const u8 *authKeyHash, const u8 *peerKeyHash, u8 *masterSecret)
{
	u8 prf_seed[8 + (2 * BCA_KEY_HASH_LENGTH)];
	
	if (sharedKey == NULL || authKeyHash == NULL || peerKeyHash == NULL || masterSecret == NULL)
		return -1;
	
	WPA_PUT_BE64(prf_seed, timestamp);
	os_memcpy(prf_seed + 8,                       peerKeyHash, BCA_KEY_HASH_LENGTH);
	os_memcpy(prf_seed + 8 + BCA_KEY_HASH_LENGTH, authKeyHash, BCA_KEY_HASH_LENGTH);
	// masterSecret := prf(sharedKey, "master secret", timestamp ◦ peerKeyHash ◦ authKeyHash, MasterSecretLength)
	bca_prf(sharedKey, sharedKeyLen,
			"master secret",
			prf_seed, 8 + (2 * BCA_KEY_HASH_LENGTH),
			masterSecret, BCA_MASTER_SECRET_LENGTH);
	return 0;
}

int bca_generate_key_block(const u8 *masterSecret, const u64 timestamp, const u8 *authKeyHash, const u8 *peerKeyHash, u8 *keyBlock)
{
	u8 prf_seed[8 + (2 * BCA_KEY_HASH_LENGTH)];
	
	if (masterSecret == NULL || authKeyHash == NULL || peerKeyHash == NULL || keyBlock == NULL)
		return -1;
	
	WPA_PUT_BE64(prf_seed, timestamp);
	os_memcpy(prf_seed + 8,                       authKeyHash, BCA_KEY_HASH_LENGTH);
	os_memcpy(prf_seed + 8 + BCA_KEY_HASH_LENGTH, peerKeyHash, BCA_KEY_HASH_LENGTH);
	// keyBlock := prf(masterSecret, "key expansion", timestamp ◦ authKeyHash ◦ peerKeyHash, KeyBlockLength)
	bca_prf(masterSecret, BCA_MASTER_SECRET_LENGTH,
			"key expansion",
			prf_seed, 8 + (2 * BCA_KEY_HASH_LENGTH),
			keyBlock, BCA_KEY_BLOCK_LENGTH);
	return 0;
}

int bca_generate_msk_key_block(const u8 *masterSecret, const u64 timestamp, const u8 *authKeyHash, const u8 *peerKeyHash, u8 *mskBlock)
{
	u8 prf_seed[8 + (2 * BCA_KEY_HASH_LENGTH)];
	
	if (masterSecret == NULL || authKeyHash == NULL || peerKeyHash == NULL || mskBlock == NULL)
		return -1;
	
	WPA_PUT_BE64(prf_seed, timestamp);
	os_memcpy(prf_seed + 8,                       peerKeyHash, BCA_KEY_HASH_LENGTH);
	os_memcpy(prf_seed + 8 + BCA_KEY_HASH_LENGTH, authKeyHash, BCA_KEY_HASH_LENGTH);
	// mskBlock := prf(masterSecret, "client EAP encryption", timestamp ◦ peerKeyHash ◦ authKeyHash, KeyBlockLength)
	bca_prf(masterSecret, BCA_MASTER_SECRET_LENGTH,
			"client EAP encryption",
			prf_seed, 8 + (2 * BCA_KEY_HASH_LENGTH),
			mskBlock, EAP_MSK_LEN + EAP_EMSK_LEN);
	return 0;
}


// crypt = os_malloc(BCA_CIPHER_NONCE_EX_LENGTH + msg_len + BCA_CIPHER_BLOCK_LENGTH);
// os_free(crypt);
int bca_cipher_encryption(const u8 *msg, const size_t msg_len, const struct bca_cipher_parameters *cipher_parameters, u8 *crypt)
{
	u8 iv[BCA_CIPHER_GCM_IV_LENGTH];
	u8 tag[BCA_CIPHER_BLOCK_LENGTH];
	u8 nonce_explicit[BCA_CIPHER_NONCE_EX_LENGTH];
	
	if (random_get_bytes(nonce_explicit, BCA_CIPHER_NONCE_EX_LENGTH))
		return -1;
	
	if (crypt == NULL)
		return -1;
	
	os_memcpy(iv, cipher_parameters->salt, BCA_CIPHER_SALT_LENGTH);
	os_memcpy(iv + BCA_CIPHER_SALT_LENGTH, nonce_explicit, BCA_CIPHER_NONCE_EX_LENGTH);
	
	os_memcpy(crypt, nonce_explicit, BCA_CIPHER_NONCE_EX_LENGTH);
	
	if (aes_gcm_ae(cipher_parameters->key, BCA_CIPHER_KEY_LENGTH,
				   iv, BCA_CIPHER_GCM_IV_LENGTH,
				   msg, msg_len,
				   0, 0,
				   crypt + BCA_CIPHER_NONCE_EX_LENGTH, tag)) {
		return -1;
	}
	
	os_memcpy(crypt + BCA_CIPHER_NONCE_EX_LENGTH + msg_len, tag, BCA_CIPHER_BLOCK_LENGTH);
	return 0;
}


// msg = os_malloc(msg_len);
// os_free(msg);
int bca_cipher_decryption(const u8 *crypt, const size_t crypt_len, const struct bca_cipher_parameters *cipher_parameters, u8 *msg)
{
	u8 iv[BCA_CIPHER_GCM_IV_LENGTH];
	u8 tag[BCA_CIPHER_BLOCK_LENGTH];
	u8 nonce_explicit[BCA_CIPHER_NONCE_EX_LENGTH];
	size_t msg_len;
	
	if (crypt_len < (BCA_CIPHER_NONCE_EX_LENGTH + BCA_CIPHER_BLOCK_LENGTH))
		return -1;
	
	msg_len = crypt_len - BCA_CIPHER_NONCE_EX_LENGTH - BCA_CIPHER_BLOCK_LENGTH;
	
	if (msg == NULL)
		return -1;
	
	os_memcpy(nonce_explicit, crypt, BCA_CIPHER_NONCE_EX_LENGTH);
	
	os_memcpy(iv, cipher_parameters->salt, BCA_CIPHER_SALT_LENGTH);
	os_memcpy(iv + BCA_CIPHER_SALT_LENGTH, nonce_explicit, BCA_CIPHER_NONCE_EX_LENGTH);
	
	os_memcpy(tag, crypt + BCA_CIPHER_NONCE_EX_LENGTH + msg_len, BCA_CIPHER_BLOCK_LENGTH);
	
	if (aes_gcm_ad(cipher_parameters->key, BCA_CIPHER_KEY_LENGTH, iv, BCA_CIPHER_GCM_IV_LENGTH, crypt + BCA_CIPHER_NONCE_EX_LENGTH, msg_len, NULL, 0, tag, msg))
		return -1;
	
	return 0;
}


u8 * bca_derive_session_id(const u64 timestamp, const u8 *authKeyHash, const u8 *peerKeyHash, size_t *len)
{
	u8 *out;

	if (authKeyHash == NULL || peerKeyHash == NULL || len == NULL)
		return NULL;

	*len = 8 + 8 + (2 * BCA_KEY_HASH_LENGTH);
	out = os_malloc(*len);
	if (out == NULL)
		return NULL;
	
	/* sessionId = <EAP type> ◦ timestamp ◦ authKeyHash ◦ peerKeyHash */
	out[0] = EAP_TYPE_EXPANDED;
	WPA_PUT_BE24(out + 1, EAP_VENDOR_BCA);
	WPA_PUT_BE32(out + 4, EAP_VENDOR_TYPE_BCA);
	WPA_PUT_BE64(out + 8, timestamp);
	os_memcpy(out + 8,                       authKeyHash, BCA_KEY_HASH_LENGTH);
	os_memcpy(out + 8 + BCA_KEY_HASH_LENGTH, peerKeyHash, BCA_KEY_HASH_LENGTH);
	
	return out;
}




int bca_EC_POINT_to_oct(const EC_KEY *key, const EC_POINT *p, u8 *out)
{
	const EC_GROUP *group;
	u8 ecpoint_buf[1 + (2*BCA_ECDSA_KEY_LENGTH) + 10];
	
	unsigned long err_res;
	const char *err_file;
	int err_line;
	const char *err_data;
	int err_flags;
	size_t res;
	
	
	group = EC_KEY_get0_group(key);
	
	/** Encodes a EC_POINT object to a octet string
	 *  \param  group  underlying EC_GROUP object
	 *  \param  p      EC_POINT object
	 *  \param  form   point conversion form
	 *  \param  buf    memory buffer for the result. If NULL the function returns
	 *                 required buffer size.
	 *  \param  len    length of the memory buffer
	 *  \param  ctx    BN_CTX object (optional)
	 *  \return the length of the encoded octet string or 0 if an error occurred
	 */
	if ((res = EC_POINT_point2oct(group, p, POINT_CONVERSION_UNCOMPRESSED, ecpoint_buf, 1 + (2*BCA_ECDSA_KEY_LENGTH), NULL)) == 0
/*!= (1 + (2*BCA_ECDSA_KEY_LENGTH))*/)
	{
		wpa_printf(MSG_ERROR, "EAP-BCA: ERROR in bca_EC_POINT_to_oct, function: EC_POINT_point2oct");
		
		err_res = ERR_peek_last_error_line_data(&err_file, &err_line, &err_data, &err_flags);
		
		if (err_res > 0)
			wpa_printf(MSG_ERROR, "EAP-BCA: Error data: %ld '%s' %d %s %d\n", err_res, err_file, err_line, err_data, err_flags);
		
		return -1;
	}
	
	os_memcpy(out, ecpoint_buf + 1, (2*BCA_ECDSA_KEY_LENGTH));
	return 0;
}


int bca_oct_to_EC_POINT(const EC_KEY *key, const u8 *in, EC_POINT **point)
{
	const EC_GROUP *group;
	u8 ecpoint_buf[1 + (2*BCA_ECDSA_KEY_LENGTH)];
	
	group = EC_KEY_get0_group(key);
	
	if (*point == NULL)
		*point = EC_POINT_new(group);
	
	ecpoint_buf[0] = POINT_CONVERSION_UNCOMPRESSED;
	os_memcpy(ecpoint_buf + 1, in, (2*BCA_ECDSA_KEY_LENGTH));
	
	/** Decodes a EC_POINT from a octet string
	 *  \param  group  underlying EC_GROUP object
	 *  \param  p      EC_POINT object
	 *  \param  buf    memory buffer with the encoded ec point
	 *  \param  len    length of the encoded ec point
	 *  \param  ctx    BN_CTX object (optional)
	 *  \return 1 on success and 0 if an error occurred
	 */
	if (!EC_POINT_oct2point(group, *point, ecpoint_buf, 1 + (2*BCA_ECDSA_KEY_LENGTH), NULL)) {
		return -1;
	}
	
	return 0;
}





void bca_eth_bin2jsonHex(const u8 *data, size_t data_len, char *strbuffer)
{
	unsigned int i;
	static const unsigned char hexchars[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	
	for (i = 0; i < data_len; ++i) {
		strbuffer[i * 2]       = hexchars[(data[i] >> 4) & 0xf];
		strbuffer[(i * 2) + 1] = hexchars[ data[i] & 0xf];
	}
	strbuffer[i * 2] = 0;
}




int bca_eth_send_ipc_request(const char *ipc_file_path, const char *req_msg, char *recv_buffer, size_t recv_buffer_size)
{
	int geth_ipc_socket;
	struct sockaddr_un address;
	int size;
	u64 timeout;
	
	geth_ipc_socket = socket(PF_LOCAL, SOCK_STREAM, 0);
	if(geth_ipc_socket <= 0) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Can't create socket");
		return -1;
	}
	
	address.sun_family = AF_LOCAL;
	strcpy(address.sun_path, ipc_file_path);
	
	if (connect(geth_ipc_socket, (struct sockaddr *) &address, sizeof(address))) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Can't open socket");
		return -1;
	}
	
	wpa_printf(MSG_DEBUG, "EAP-BCA: geth is connected");
	
	send(geth_ipc_socket, req_msg, strlen(req_msg), 0);
	
	size = 0;
	timeout = bca_time_now() + 2000;
	do {
		size += recv(geth_ipc_socket, recv_buffer + size, recv_buffer_size - 1 - size, 0);
		if (size > 0 && recv_buffer[size - 1] == 0x0a)
			break;
		os_sleep(0, 1000); // sleep 1ms
	} while (size <= 0 && timeout <= bca_time_now());
	
	recv_buffer[size] = '\0';
	
	close(geth_ipc_socket);
	
	return 0;
}


/**
 * 
 * param_data - include the methode ID
 */
int bca_eth_call(const char *ipc_file_path, const u8 *contract_addr, const u8 *from_addr, const u8 *param_data, size_t param_data_len, u8 **result, size_t *result_len)
{
	char *req_msg;
	size_t req_msg_len;
	
	char *from_addr_hex;
	char *to_addr_hex;
	char *param_data_hex;
	char *buffer;
	
	const static char *req_msg_prototype  = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"from\":\"0x%s\",\"to\":\"0x%s\",\"data\":\"0x%s\"},\"latest\"],\"id\":1}\n";
	
	req_msg_len = strlen(req_msg_prototype) - (2 * 3) + (2 * 40) + (2 * param_data_len);
	
	req_msg = os_malloc(req_msg_len + 1);
	from_addr_hex = os_malloc(40 + 1);
	to_addr_hex = os_malloc(40 + 1);
	param_data_hex = os_malloc(2 * param_data_len + 1);
	
	if (req_msg == NULL ||
		from_addr_hex == NULL ||
		to_addr_hex == NULL ||
		param_data_hex == NULL) {
		wpa_printf(MSG_ERROR, "EAP-BCA: memory allocation fail in function %s", __func__);
		return -1;
	}
	
	bca_eth_bin2jsonHex(from_addr,  20, from_addr_hex);
	bca_eth_bin2jsonHex(contract_addr, 20, to_addr_hex);
	bca_eth_bin2jsonHex(param_data, param_data_len, param_data_hex);
	
	sprintf(req_msg, req_msg_prototype, from_addr_hex, to_addr_hex, param_data_hex);
	
	wpa_printf(MSG_DEBUG, "EAP-BCA: sending request message to geth via IPC");
	wpa_hexdump(MSG_DEBUG, "EAP-BCA: geth request message", req_msg, strlen(req_msg));
	
	
	buffer = os_malloc(1024);
	
	if (bca_eth_send_ipc_request(ipc_file_path, req_msg, buffer, 1024)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Can't send ipc request to geth");
		os_free(buffer);
		return -1;
	}
	
	wpa_hexdump(MSG_DEBUG, "EAP-BCA: geth response message", buffer, strlen(buffer));
	
	cJSON * root = cJSON_Parse(buffer);
	cJSON * err = cJSON_GetObjectItem(root, "error");
	if (err) {
		cJSON * err_msg = cJSON_GetObjectItem(root, "message");
		if (err_msg) {
			wpa_printf(MSG_ERROR, "EAP-BCA: JSON-RPC error - %s", cJSON_Print(err_msg));
		} else {
			wpa_printf(MSG_ERROR, "EAP-BCA: JSON-RPC error (no message)");
		}
		os_free(buffer);
		cJSON_Delete(root);
		return -1;
	}
	
	cJSON * result_obj = cJSON_GetObjectItem(root, "result");
	char * result_str = result_obj->valuestring;
	
	if (strlen(result_str) <= 2) {
		*result_len = 0;
		*result = NULL;
		
		cJSON_Delete(root);
		os_free(buffer);
		return 0;
	} else if (strlen(result_str) & 1) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Incorrect hex string length (%d)", strlen(result_str));
		cJSON_Delete(root);
		os_free(buffer);
		return -1;
	} else {
		*result_len = (strlen(result_str) - 2) / 2;
		*result = os_malloc(*result_len);
	} 
	
	if (hexstr2bin(result_str + 2, *result, *result_len)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: hexstr2bin fail");
		cJSON_Delete(root);
		os_free(buffer);
		return -1;
	}
	
	wpa_hexdump(MSG_DEBUG, "EAP-BCA: geth response message result", *result, *result_len);
	
	cJSON_Delete(root);
	os_free(buffer);
	return 0;
}


int bca_eth_aaa_contract_call_has_access(const char *ipc_file_path, const u8 *contract_addr, const u8 *from_addr, const u8 *access_token, u8 *has_access)
{
	const size_t param_data_len = 4 + BCA_ACCESS_TOKEN_LENGTH;
	u8 *param_data;
	u8 *result;
	size_t result_len;
	
	param_data = os_malloc(param_data_len);
	
	WPA_PUT_BE32(param_data, BCA_ETH_AAA_CONTRACT_METHODE_HAS_ACCESS);
	os_memcpy(param_data + 4, access_token, BCA_ACCESS_TOKEN_LENGTH);
	
	if (bca_eth_call(ipc_file_path, contract_addr, from_addr, param_data, param_data_len, &result, &result_len)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Error in bca_eth_call");
		os_free(param_data);
		return -1;
	}
	
	if (result_len > 0) {
		*has_access = result[31];
	} else {
		*has_access = 0;
	}
	
	os_free(result);
	os_free(param_data);
	return 0;
}


int bca_eth_aaa_contract_call_get_ca_public_key(const char *ipc_file_path, const u8 *contract_addr, const u8 *from_addr, u8 *ca_public_key)
{
	const size_t param_data_len = 4;
	u8 *param_data;
	u8 *result;
	size_t result_len;
	
	param_data = os_malloc(param_data_len);
	
	WPA_PUT_BE32(param_data, BCA_ETH_AAA_CONTRACT_METHODE_GET_CA_PUBLIC_KEY);
	
	if (bca_eth_call(ipc_file_path, contract_addr, from_addr, param_data, param_data_len, &result, &result_len)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Error in bca_eth_call");
		os_free(param_data);
		return -1;
	}
	
	if (result_len < (4 * 32)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Error in bca_eth_call result");
		os_free(result);
		os_free(param_data);
		return -1;
	}
	
	os_memcpy(ca_public_key, result + 64, 2 * BCA_ECDSA_KEY_LENGTH);
	
	os_free(result);
	os_free(param_data);
	return 0;
}


int bca_eth_aaa_contract_call_get_auth_key_sign(const char *ipc_file_path,
		const u8 *contract_addr, const u8 *from_addr,
		const u8 *auth_key_hash, u8 *is_found, u8 *auth_key_sign)
{
	const size_t param_data_len = 4 + BCA_KEY_HASH_LENGTH;
	u8 *param_data;
	u8 *result;
	size_t result_len;
	
	param_data = os_malloc(param_data_len);
	
	WPA_PUT_BE32(param_data, BCA_ETH_AAA_CONTRACT_METHODE_GET_AUTH_KEY_SIGN);
	os_memcpy(param_data + 4, auth_key_hash, BCA_KEY_HASH_LENGTH);
	
	if (bca_eth_call(ipc_file_path, contract_addr, from_addr, param_data, param_data_len, &result, &result_len)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Error in bca_eth_call");
		os_free(param_data);
		return -1;
	}
	
	if (result_len < (2 * 32)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Error in bca_eth_call result");
		os_free(result);
		os_free(param_data);
		return -1;
	}
	
	*is_found = result[31];
	
	if (is_found) {
		if (result_len < (5 * 32)) {
			wpa_printf(MSG_ERROR, "EAP-BCA: Error in bca_eth_call result");
			os_free(result);
			os_free(param_data);
			return -1;
		}
		
		os_memcpy(auth_key_sign, result + (3 * 32), 2 * BCA_ECDSA_KEY_LENGTH);
	}
	
	os_free(result);
	os_free(param_data);
	return 0;
}


int bca_eth_aaa_contract_gen_access_token(const u8 *peer_key_hash, const u8 *psk, u8 *access_token)
{
	u8 hash_msg[BCA_KEY_HASH_LENGTH + BCA_CONTRACT_PSK_LENGTH];
	const u8 *sha256_vector_addr[1];
	size_t sha256_vector_len[1];
	
	
	os_memcpy(hash_msg,                       peer_key_hash, BCA_KEY_HASH_LENGTH);
	os_memcpy(hash_msg + BCA_KEY_HASH_LENGTH, psk,           BCA_CONTRACT_PSK_LENGTH);
	
	sha256_vector_addr[0] = hash_msg;
	sha256_vector_len[0] = BCA_KEY_HASH_LENGTH + BCA_CONTRACT_PSK_LENGTH;
	
	if (sha256_vector(1, sha256_vector_addr, sha256_vector_len, access_token))
		return -1;
	
	return  0;
}


int bca_eth_sendTransaction(const char *ipc_file_path, const u8 *contract_addr, const u8 *from_addr, const u8 *param_data, size_t param_data_len, u8 **result, size_t *result_len)
{
	char *req_msg;
	size_t req_msg_len;
	
	char *from_addr_hex;
	char *to_addr_hex;
	char *param_data_hex;
	char *buffer;
	
	const static char *req_msg_prototype  = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"0x%s\",\"to\":\"0x%s\",\"data\":\"0x%s\"}],\"id\":1}\n";
	
	req_msg_len = strlen(req_msg_prototype) - (2 * 3) + (2 * 40) + (2 * param_data_len);
	
	req_msg = os_malloc(req_msg_len + 1);
	from_addr_hex = os_malloc(40 + 1);
	to_addr_hex = os_malloc(40 + 1);
	param_data_hex = os_malloc(2 * param_data_len + 1);
	
	if (req_msg == NULL ||
		from_addr_hex == NULL ||
		to_addr_hex == NULL ||
		param_data_hex == NULL) {
		wpa_printf(MSG_ERROR, "EAP-BCA: memory allocation fail in function %s", __func__);
		return -1;
	}
	
	bca_eth_bin2jsonHex(from_addr,  20, from_addr_hex);
	bca_eth_bin2jsonHex(contract_addr, 20, to_addr_hex);
	bca_eth_bin2jsonHex(param_data, param_data_len, param_data_hex);
	
	sprintf(req_msg, req_msg_prototype, from_addr_hex, to_addr_hex, param_data_hex);
	
	wpa_printf(MSG_DEBUG, "EAP-BCA: sending request message to geth via IPC");
	wpa_hexdump(MSG_DEBUG, "EAP-BCA: geth request message", req_msg, strlen(req_msg));
	
	
	buffer = os_malloc(1024);
	
	if (bca_eth_send_ipc_request(ipc_file_path, req_msg, buffer, 1024)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Can't send ipc request to geth");
		os_free(buffer);
		return -1;
	}
	
	wpa_hexdump(MSG_DEBUG, "EAP-BCA: geth response message", buffer, strlen(buffer));
	
	cJSON * root = cJSON_Parse(buffer);
	cJSON * err = cJSON_GetObjectItem(root, "error");
	if (err) {
		cJSON * err_msg = cJSON_GetObjectItem(root, "message");
		if (err_msg) {
			wpa_printf(MSG_ERROR, "EAP-BCA: JSON-RPC error - %s", cJSON_Print(err_msg));
		} else {
			wpa_printf(MSG_ERROR, "EAP-BCA: JSON-RPC error (no message)");
		}
		os_free(buffer);
		return -1;
	}
	
	cJSON * result_obj = cJSON_GetObjectItem(root, "result");
	char * result_str = result_obj->valuestring;
	
	if (strlen(result_str) <= 2) {
		*result_len = 0;
		*result = NULL;
		
		cJSON_Delete(root);
		os_free(buffer);
		return 0;
	} else if (strlen(result_str) & 1) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Incorrect hex string length (%d)", strlen(result_str));
		cJSON_Delete(root);
		os_free(buffer);
		return -1;
	} else {
		*result_len = (strlen(result_str) - 2) / 2;
		*result = os_malloc(*result_len);
	} 
	
	if (hexstr2bin(result_str + 2, *result, *result_len)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: hexstr2bin fail");
		cJSON_Delete(root);
		os_free(buffer);
		return -1;
	}
	
	wpa_hexdump(MSG_DEBUG, "EAP-BCA: geth response message result", *result, *result_len);
	
	cJSON_Delete(root);
	os_free(buffer);
	return 0;
}


int bca_eth_unlockAccount(const char *ipc_file_path, const u8 *account_addr, const char *passphrase)
{
	const int unlocktime = 3;
	char *req_msg;

	char *account_addr_hex;
	char *buffer;

	// {"jsonrpc":"2.0","method":"personal_unlockAccount","params":["0x08aef3ccd9a2f8b73de99ace3cd35aa80f22f88f","",5],"id":1}
	const static char *req_msg_prototype  = "{\"jsonrpc\":\"2.0\",\"method\":\"personal_unlockAccount\",\"params\":[\"0x%s\",\"%s\",%d],\"id\":1}\n";

	req_msg = os_malloc(strlen(req_msg_prototype) - (2 * 3) + 40 + 6 + 1);
	account_addr_hex = os_malloc(40 + 1);

	if (req_msg == NULL ||
		account_addr_hex == NULL) {
		wpa_printf(MSG_ERROR, "EAP-BCA: memory allocation fail in function %s", __func__);
		return -1;
	}

	bca_eth_bin2jsonHex(account_addr,  20, account_addr_hex);

	sprintf(req_msg, req_msg_prototype, account_addr_hex, passphrase, unlocktime);

	wpa_printf(MSG_DEBUG, "EAP-BCA: sending unlockAccount message to geth via IPC");
	wpa_hexdump(MSG_DEBUG, "EAP-BCA: geth request message", req_msg, strlen(req_msg));
	
	buffer = os_malloc(1024);
	
	if (bca_eth_send_ipc_request(ipc_file_path, req_msg, buffer, 1024)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Can't send ipc request to geth");
		os_free(buffer);
		return -1;
	}
	
	wpa_hexdump(MSG_DEBUG, "EAP-BCA: geth response message", buffer, strlen(buffer));
	
	cJSON * root = cJSON_Parse(buffer);
	cJSON * err = cJSON_GetObjectItem(root, "error");
	if (err) {
		cJSON * err_msg = cJSON_GetObjectItem(root, "message");
		if (err_msg) {
			wpa_printf(MSG_ERROR, "EAP-BCA: JSON-RPC error - %s", cJSON_Print(err_msg));
		} else {
			wpa_printf(MSG_ERROR, "EAP-BCA: JSON-RPC error (no message)");
		}
		cJSON_Delete(root);
		os_free(buffer);
		return -1;
	}
	
	cJSON * result_obj = cJSON_GetObjectItem(root, "result");
	
	if (result_obj->type != cJSON_True) {
		wpa_printf(MSG_ERROR, "EAP-BCA: bca_eth_unlockAccount fail");
		cJSON_Delete(root);
		os_free(buffer);
		return -1;
	}
	
	cJSON_Delete(root);
	os_free(buffer);
	return 0;
}


int bca_eth_aaa_contract_update_accounting(const char *ipc_file_path, const u8 *contract_addr, const u8 *auth_addr, const char *auth_passphrase, const u8 *access_token, const u8 *accounting_msg, size_t accounting_msg_len)
{
	const size_t param_data_len = 4 + BCA_ACCESS_TOKEN_LENGTH + BCA_ACCOUNTING_MSG_LENGTH;
	u8 *param_data;
	u8 *result;
	size_t result_len;
	
	if (accounting_msg_len > BCA_ACCOUNTING_MSG_LENGTH) {
		wpa_printf(MSG_ERROR, "EAP-BCA: accounting_msg_len > %d not supported", BCA_ACCOUNTING_MSG_LENGTH);
		return -1;
	}
	
	if (bca_eth_unlockAccount(ipc_file_path, auth_addr, auth_passphrase)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: unlock authenticator account fail");
		return -1;
	}
	
	param_data = os_malloc(param_data_len);
	
	WPA_PUT_BE32(param_data, BCA_ETH_AAA_CONTRACT_METHODE_UPDATE_ACCOUNTING);
	os_memcpy(param_data + 4, access_token, BCA_ACCESS_TOKEN_LENGTH);
	os_memset(param_data + 4 + BCA_ACCESS_TOKEN_LENGTH, 0, BCA_ACCOUNTING_MSG_LENGTH);
	os_memcpy(param_data + 4 + BCA_ACCESS_TOKEN_LENGTH, accounting_msg, accounting_msg_len);
	
	if (bca_eth_sendTransaction(ipc_file_path, contract_addr, auth_addr, param_data, param_data_len, &result, &result_len)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - Error in bca_eth_sendTransaction", __func__);
		os_free(param_data);
		return -1;
	}
	
	if (result_len != 32) {
		wpa_printf(MSG_ERROR, "EAP-BCA: %s - unexpected result", __func__);
		os_free(param_data);
		return -1;
	}
	
	os_free(result);
	os_free(param_data);
	return 0;
}


int bca_eth_aaa_contract_call_get_accounting_entry_count(
		const char *ipc_file_path, const u8 *contract_addr, const u8 *from_addr,
		const u8 *access_token, u64 *count)
{
	const size_t param_data_len = 4 + BCA_ACCESS_TOKEN_LENGTH;
	u8 *param_data;
	u8 *result;
	size_t result_len;
	
	param_data = os_malloc(param_data_len);
	
	WPA_PUT_BE32(param_data, BCA_ETH_AAA_CONTRACT_METHODE_GET_ACCOUNTING_ENTRY_COUNT);
	os_memcpy(param_data + 4, access_token, BCA_ACCESS_TOKEN_LENGTH);
	
	if (bca_eth_call(ipc_file_path, contract_addr, from_addr, param_data, param_data_len, &result, &result_len)) {
		wpa_printf(MSG_ERROR, "EAP-BCA: Error in bca_eth_call");
		os_free(param_data);
		return -1;
	}
	
	if (result_len == 32) {
		*count = WPA_GET_BE64(result + 32 - 8);
	} else {
		return -1;
	}
	
	os_free(result);
	os_free(param_data);
	return 0;
}
