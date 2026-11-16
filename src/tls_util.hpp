// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// TLS helpers: in-memory self-signed server cert, pinning client.

#pragma once

#include <openssl/ssl.h>

#include <string>

namespace sapper {

// Build an SSL_CTX serving a freshly generated self-signed certificate
// (RSA-2048, CN=sapper). Null on failure.
SSL_CTX* make_server_ctx();

// Build an SSL_CTX for the agent side. Verification is manual: the caller
// compares the peer fingerprint against the pin after the handshake.
SSL_CTX* make_client_ctx();

// SHA-256 fingerprint of the peer certificate, lowercase hex.
std::string peer_fingerprint(SSL* ssl);

}  // namespace sapper
