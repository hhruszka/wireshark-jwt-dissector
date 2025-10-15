// src/ecdsa_verify_gnutls.c
// GnuTLS implementation
#ifdef _WIN32
    #include <windows.h>   // Includes BaseTsd.h indirectly
    // OR explicitly:
    // #include <BaseTsd.h>

    #ifndef _SSIZE_T_DEFINED
        typedef SSIZE_T ssize_t;
        #define _SSIZE_T_DEFINED
    #endif
#endif

#include "ecdsa_verify.h"
#include "base64.h"
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <glib.h>
#include <string.h>

// Helper: Convert raw ECDSA signature (r || s) to DER format for GnuTLS
// GnuTLS expects DER-encoded ECDSA signatures
static unsigned char* raw_to_der_ecdsa_sig(const unsigned char *raw_sig,
                                           size_t component_len,
                                           size_t *der_len) {
    // Very simplified DER encoding for ECDSA signatures
    // SEQUENCE { INTEGER r, INTEGER s }

    // Count leading zeros that need to be stripped (but keep one if high bit is set)
    size_t r_start = 0, s_start = 0;
    while (r_start < component_len - 1 && raw_sig[r_start] == 0) r_start++;
    while (s_start < component_len - 1 && raw_sig[component_len + s_start] == 0) s_start++;

    // Check if we need to add a 0x00 byte (if high bit is set)
    int r_needs_zero = (raw_sig[r_start] & 0x80) ? 1 : 0;
    int s_needs_zero = (raw_sig[component_len + s_start] & 0x80) ? 1 : 0;

    size_t r_len = component_len - r_start + r_needs_zero;
    size_t s_len = component_len - s_start + s_needs_zero;

    // Calculate DER length: SEQUENCE(1) + len(1) + INT(1) + r_len_byte(1) + r_data + INT(1) + s_len_byte(1) + s_data
    // For simplicity, assuming lengths fit in one byte
    *der_len = 2 + (2 + r_len) + (2 + s_len);
    unsigned char *der = g_malloc(*der_len);

    size_t pos = 0;
    der[pos++] = 0x30; // SEQUENCE
    der[pos++] = (2 + r_len) + (2 + s_len); // Total length

    // R integer
    der[pos++] = 0x02; // INTEGER
    der[pos++] = r_len;
    if (r_needs_zero) der[pos++] = 0x00;
    memcpy(der + pos, raw_sig + r_start, component_len - r_start);
    pos += component_len - r_start;

    // S integer
    der[pos++] = 0x02; // INTEGER
    der[pos++] = s_len;
    if (s_needs_zero) der[pos++] = 0x00;
    memcpy(der + pos, raw_sig + component_len + s_start, component_len - s_start);
    pos += component_len - s_start;

    return der;
}

// Helper: Verify EC key curve
static int verify_ec_curve_gnutls(gnutls_pubkey_t pubkey, gnutls_ecc_curve_t expected_curve) {
    gnutls_ecc_curve_t curve;
    unsigned int bits;

    if (gnutls_pubkey_get_pk_algorithm(pubkey, &bits) != GNUTLS_PK_EC) {
        return 0;
    }

    // Get curve from public key
    if (gnutls_pubkey_export_ecc_raw(pubkey, &curve, NULL, NULL) != GNUTLS_E_SUCCESS) {
        return 0;
    }

    return (curve == expected_curve);
}

// Helper: Generic ECDSA verification
static int ecdsa_verify_generic_gnutls(const char *data,
                                       const char *signature_b64url,
                                       const char *public_key_pem,
                                       gnutls_sign_algorithm_t sign_algo,
                                       gnutls_ecc_curve_t expected_curve,
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

    gnutls_pubkey_t pubkey;
    gnutls_datum_t key_data;
    gnutls_datum_t data_datum;
    gnutls_datum_t sig_data;
    int result = 0;

    // Initialize public key
    if (gnutls_pubkey_init(&pubkey) != GNUTLS_E_SUCCESS) {
        g_free(signature);
        return 0;
    }

    // Import PEM public key
    key_data.data = (unsigned char *)public_key_pem;
    key_data.size = strlen(public_key_pem);

    if (gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
        gnutls_pubkey_deinit(pubkey);
        g_free(signature);
        return 0;
    }

    // Verify curve
    if (!verify_ec_curve_gnutls(pubkey, expected_curve)) {
        gnutls_pubkey_deinit(pubkey);
        g_free(signature);
        return 0;
    }

    // Convert raw signature to DER format
    size_t der_len;
    unsigned char *der_sig = raw_to_der_ecdsa_sig(signature, component_len, &der_len);

    // Prepare data and signature
    data_datum.data = (unsigned char *)data;
    data_datum.size = strlen(data);
    sig_data.data = der_sig;
    sig_data.size = der_len;

    // Verify signature
    if (gnutls_pubkey_verify_data2(pubkey, sign_algo, 0, &data_datum, &sig_data) >= 0) {
        result = 1;
    }

    gnutls_pubkey_deinit(pubkey);
    g_free(der_sig);
    g_free(signature);

    return result;
}

// ES256: P-256 (secp256r1), SHA-256, 64-byte signature
int ecdsa_verify_es256(gchar *data,
                       const char *signature_b64url,
                       const char *public_key_pem) {
    return ecdsa_verify_generic_gnutls(
        data,
        signature_b64url,
        public_key_pem,
        GNUTLS_SIGN_ECDSA_SHA256,
        GNUTLS_ECC_CURVE_SECP256R1,
        64, // Total signature length
        32  // Each component (r, s) is 32 bytes
    );
}

// ES384: P-384 (secp384r1), SHA-384, 96-byte signature
int ecdsa_verify_es384(gchar *data,
                       const char *signature_b64url,
                       const char *public_key_pem) {
    return ecdsa_verify_generic_gnutls(
        data,
        signature_b64url,
        public_key_pem,
        GNUTLS_SIGN_ECDSA_SHA384,
        GNUTLS_ECC_CURVE_SECP384R1,
        96, // Total signature length
        48  // Each component (r, s) is 48 bytes
    );
}

// ES512: P-521 (secp521r1), SHA-512, 132-byte signature
int ecdsa_verify_es512(gchar *data,
                       const char *signature_b64url,
                       const char *public_key_pem) {
    return ecdsa_verify_generic_gnutls(
        data,
        signature_b64url,
        public_key_pem,
        GNUTLS_SIGN_ECDSA_SHA512,
        GNUTLS_ECC_CURVE_SECP521R1,
        132, // Total signature length (note: P-521, not P-512!)
        66   // Each component (r, s) is 66 bytes
    );
}
