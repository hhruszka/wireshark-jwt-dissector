//
// Created by Henryk Hruszka on 10/10/2025.
// GnuTLS implementation
//
#ifdef _WIN32
    #include <windows.h>   // Includes BaseTsd.h indirectly
    // OR explicitly:
    // #include <BaseTsd.h>

    #ifndef _SSIZE_T_DEFINED
        typedef SSIZE_T ssize_t;
        #define _SSIZE_T_DEFINED
    #endif
#endif

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <glib.h>
#include "base64.h"
#include "rsa_verify.h"

int rsa_verify_rs256(gchar *header_payload,
                        const char *signature_b64,
                        const char *public_key_pem) {
    gsize sig_len;
    guchar *signature = base64url_decode(signature_b64, &sig_len);

    if (!signature) {
        return 0;
    }

    gnutls_pubkey_t pubkey;
    gnutls_datum_t key_data;
    gnutls_datum_t data;
    gnutls_datum_t sig_data;
    int result = 0;

    // Initialize public key structure
    if (gnutls_pubkey_init(&pubkey) != GNUTLS_E_SUCCESS) {
        g_free(signature);
        return 0;
    }

    // Prepare key data
    key_data.data = (unsigned char *)public_key_pem;
    key_data.size = strlen(public_key_pem);

    // Import PEM public key
    if (gnutls_pubkey_import(pubkey, &key_data, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
        gnutls_pubkey_deinit(pubkey);
        g_free(signature);
        return 0;
    }

    // Prepare data and signature
    data.data = (unsigned char *)header_payload;
    data.size = strlen(header_payload);
    sig_data.data = signature;
    sig_data.size = sig_len;

    // Verify signature with RSA-SHA256
    if (gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_RSA_SHA256,
                                    0, &data, &sig_data) >= 0) {
        result = 1;
    }

    gnutls_pubkey_deinit(pubkey);
    g_free(signature);
    return result;
}
