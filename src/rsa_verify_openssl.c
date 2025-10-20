//
// Created by Henryk Hruszka on 10/10/2025.
//
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <glib.h>
#include <jwt/base64.h>

int rsa_verify_rs256(gchar *header_payload,
                        const char *signature_b64,
                        const char *public_key_pem) {
    gsize sig_len;
    guchar *signature = base64url_decode(signature_b64, &sig_len);

    BIO *bio = BIO_new_mem_buf(public_key_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!pkey) {
        g_free(signature);
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result = 0;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, header_payload, strlen(header_payload)) == 1 &&
        EVP_DigestVerifyFinal(ctx, signature, sig_len) == 1) {
        result = 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    g_free(signature);
    return result;
}
