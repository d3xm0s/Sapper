// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// TLS helpers: in-memory self-signed server cert, pinning client.

#include "tls_util.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <cstdio>

namespace sapper {

namespace {

X509* make_cert(EVP_PKEY* key) {
    X509* x = X509_new();
    if (x == nullptr) {
        return nullptr;
    }
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3650L * 24 * 3600);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("sapper"),
                               -1, -1, 0);
    X509_set_issuer_name(x, name);
    X509_set_pubkey(x, key);
    if (X509_sign(x, key, EVP_sha256()) == 0) {
        X509_free(x);
        return nullptr;
    }
    return x;
}

}  // namespace

SSL_CTX* make_server_ctx() {
    EVP_PKEY* key = EVP_RSA_gen(2048);
    if (key == nullptr) {
        return nullptr;
    }
    X509* cert = make_cert(key);
    if (cert == nullptr) {
        EVP_PKEY_free(key);
        return nullptr;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (ctx != nullptr &&
        (SSL_CTX_use_certificate(ctx, cert) != 1 ||
         SSL_CTX_use_PrivateKey(ctx, key) != 1)) {
        SSL_CTX_free(ctx);
        ctx = nullptr;
    }
    X509_free(cert);
    EVP_PKEY_free(key);
    return ctx;
}

SSL_CTX* make_client_ctx() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        return nullptr;
    }
    // The tunnel carries its own PSK auth; cert identity is pinned manually
    // after the handshake when the operator asks for it.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    return ctx;
}

std::string peer_fingerprint(SSL* ssl) {
    X509* x = SSL_get1_peer_certificate(ssl);
    if (x == nullptr) {
        return {};
    }
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned int md_len = sizeof(md);
    X509_digest(x, EVP_sha256(), md, &md_len);
    X509_free(x);

    std::string out;
    char buf[3];
    for (unsigned int i = 0; i < md_len; ++i) {
        std::snprintf(buf, sizeof(buf), "%02x", md[i]);
        out += buf;
    }
    return out;
}

}  // namespace sapper
