1// src/ecdsa_verify.c
#include "ecdsa_verify.h"
#include "base64.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <glib.h>

// Helper: Verify EC key curve
static int verify_ec_curve(EVP_PKEY *pkey, int expected_nid) {
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    int nid = EC_GROUP_get_curve_name(group);

    EC_KEY_free(ec_key);
    return (nid == expected_nid);
}

// Helper: Generic ECDSA verification
static int ecdsa_verify_generic(const char *data,
                                const char *signature_b64url,
                                const char *public_key_pem,
                                const EVP_MD *md_type,
                                int expected_nid,
                                size_t expected_sig_len,
                                size_t component_len) {
    gsize sig_len;
    guchar *signature = base64url_decode(signature_b64url, &sig_len);

    if (!signature) {
        return 0;
    }

    // Verify signature length
    if (sig_len != expected_sig_len) {
        g_free(signature);
        return 0;
    }

    // Load public key
    BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
    if (!bio) {
        g_free(signature);
        return 0;
    }

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        g_free(signature);
        return 0;
    }

    // Verify it's an EC key with correct curve
    if (EVP_PKEY_id(pkey) != EVP_PKEY_EC || !verify_ec_curve(pkey, expected_nid)) {
        EVP_PKEY_free(pkey);
        g_free(signature);
        return 0;
    }

    // Convert raw signature (r || s) to DER format
    ECDSA_SIG *ec_sig = ECDSA_SIG_new();
    if (!ec_sig) {
        EVP_PKEY_free(pkey);
        g_free(signature);
        return 0;
    }

    BIGNUM *r = BN_bin2bn(signature, component_len, NULL);
    BIGNUM *s = BN_bin2bn(signature + component_len, component_len, NULL);

    if (!r || !s) {
        if (r) BN_free(r);
        if (s) BN_free(s);
        ECDSA_SIG_free(ec_sig);
        EVP_PKEY_free(pkey);
        g_free(signature);
        return 0;
    }

    ECDSA_SIG_set0(ec_sig, r, s);

    unsigned char *der_sig = NULL;
    int der_len = i2d_ECDSA_SIG(ec_sig, &der_sig);
    ECDSA_SIG_free(ec_sig);

    if (der_len <= 0) {
        EVP_PKEY_free(pkey);
        g_free(signature);
        return 0;
    }

    // Verify signature
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result = 0;

    if (ctx &&
        EVP_DigestVerifyInit(ctx, NULL, md_type, NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, data, strlen(data)) == 1 &&
        EVP_DigestVerifyFinal(ctx, der_sig, der_len) == 1) {
        result = 1;
    }

    if (ctx) EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(der_sig);
    g_free(signature);

    return result;
}

// ES256: P-256 (secp256r1), SHA-256, 64-byte signature
int ecdsa_verify_es256(gchar *data,
                       const char *signature_b64url,
                       const char *public_key_pem) {
    return ecdsa_verify_generic(
        data,
        signature_b64url,
        public_key_pem,
        EVP_sha256(),
        NID_X9_62_prime256v1, // secp256r1 / P-256
        64, // Total signature length
        32 // Each component (r, s) is 32 bytes
    );
}

// ES384: P-384 (secp384r1), SHA-384, 96-byte signature
int ecdsa_verify_es384(gchar *data,
                       const char *signature_b64url,
                       const char *public_key_pem) {
    return ecdsa_verify_generic(
        data,
        signature_b64url,
        public_key_pem,
        EVP_sha384(),
        NID_secp384r1, // secp384r1 / P-384
        96, // Total signature length
        48 // Each component (r, s) is 48 bytes
    );
}

// ES512: P-521 (secp521r1), SHA-512, 132-byte signature
int ecdsa_verify_es512(gchar *data,
                       const char *signature_b64url,
                       const char *public_key_pem) {
    return ecdsa_verify_generic(
        data,
        signature_b64url,
        public_key_pem,
        EVP_sha512(),
        NID_secp521r1, // secp521r1 / P-521
        132, // Total signature length (note: P-521, not P-512!)
        66 // Each component (r, s) is 66 bytes
    );
}


// #include <openssl/evp.h>
// #include <openssl/ec.h>
// #include <openssl/rsa.h>
// #include <openssl/pem.h>
// #include <openssl/bio.h>
// #include <lua/lua.h>
// #include <glib.h>
// #include "base64.h"
//
// static int verify_key_curve(EVP_PKEY *pkey) {
//     EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
//     if (!ec_key) return 0;
//
//     const EC_GROUP *group = EC_KEY_get0_group(ec_key);
//     int nid = EC_GROUP_get_curve_name(group);
//
//     EC_KEY_free(ec_key);
//
//     // NID_X9_62_prime256v1 is secp256r1/P-256
//     return (nid == NID_X9_62_prime256v1);
// }
//
// int ecdsa_verify_es256(gchar *header_payload,
// const char *signature_b64,
// const char *public_key_pem) {
//     gsize sig_len;
//     guchar *signature = base64url_decode(signature_b64, &sig_len);
//
//     BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
//     EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
//     BIO_free(bio);
//
//     if (!pkey) {
//         g_free(signature);
//         return 0;
//     }
//
//     // Verify it's an EC key with P-256 curve
//     if (EVP_PKEY_id(pkey) != EVP_PKEY_EC || !verify_key_curve(pkey)) {
//         EVP_PKEY_free(pkey);
//         g_free(signature);
//         return 0;
//     }
//
//     // JWT ECDSA signatures are raw (r || s), 64 bytes for P-256
//     if (sig_len != 64) {
//         EVP_PKEY_free(pkey);
//         g_free(signature);
//         return 0;
//     }
//
//     // Convert raw signature to DER format for OpenSSL
//     ECDSA_SIG *ec_sig = ECDSA_SIG_new();
//     BIGNUM *r = BN_bin2bn(signature, 32, NULL);
//     BIGNUM *s = BN_bin2bn(signature + 32, 32, NULL);
//     ECDSA_SIG_set0(ec_sig, r, s);
//
//     unsigned char *der_sig = NULL;
//     int der_len = i2d_ECDSA_SIG(ec_sig, &der_sig);
//     ECDSA_SIG_free(ec_sig);
//
//     // Verify signature
//     EVP_MD_CTX *ctx = EVP_MD_CTX_new();
//     int result = 0;
//
//     if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
//         EVP_DigestVerifyUpdate(ctx, header_payload, strlen(header_payload)) == 1 &&
//         EVP_DigestVerifyFinal(ctx, der_sig, der_len) == 1) {
//         result = 1;
//         }
//
//     EVP_MD_CTX_free(ctx);
//     EVP_PKEY_free(pkey);
//     OPENSSL_free(der_sig);
//     g_free(signature);
//     return result;
// }
