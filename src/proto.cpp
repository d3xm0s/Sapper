// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// Wire framing and channel model shared by server and agent.

#include "proto.hpp"

#include <openssl/hmac.h>

#include <cstring>

namespace sapper {

namespace {

constexpr uint32_t kMaxPayload = 4 * 1024 * 1024;

bool read_exact(SSL* ssl, void* buf, std::size_t len) {
    auto* p = static_cast<uint8_t*>(buf);
    std::size_t got = 0;
    while (got < len) {
        int n = SSL_read(ssl, p + got, static_cast<int>(len - got));
        if (n <= 0) {
            return false;
        }
        got += static_cast<std::size_t>(n);
    }
    return true;
}

uint32_t load32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

void store32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

}  // namespace

bool read_frame(SSL* ssl, Frame& out) {
    uint8_t hdr[9];
    if (!read_exact(ssl, hdr, sizeof(hdr))) {
        return false;
    }
    uint32_t len = load32(hdr + 5);
    if (len > kMaxPayload) {
        return false;
    }
    out.type = hdr[0];
    out.channel = load32(hdr + 1);
    out.payload.resize(len);
    return len == 0 || read_exact(ssl, out.payload.data(), len);
}

bool write_frame(SSL* ssl, std::mutex& mtx, uint8_t type, uint32_t channel,
                 const void* data, uint32_t len) {
    if (len > kMaxPayload) {
        return false;
    }
    std::vector<uint8_t> buf(9 + len);
    buf[0] = type;
    store32(buf.data() + 1, channel);
    store32(buf.data() + 5, len);
    if (len > 0) {
        std::memcpy(buf.data() + 9, data, len);
    }
    std::lock_guard<std::mutex> lock(mtx);
    std::size_t sent = 0;
    while (sent < buf.size()) {
        int n = SSL_write(ssl, buf.data() + sent,
                          static_cast<int>(buf.size() - sent));
        if (n <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

bool write_frame(SSL* ssl, std::mutex& mtx, uint8_t type, uint32_t channel,
                 const std::string& s) {
    return write_frame(ssl, mtx, type, channel, s.data(),
                       static_cast<uint32_t>(s.size()));
}

std::vector<uint8_t> auth_proof(const std::string& key,
                                const std::vector<uint8_t>& nonce) {
    std::vector<uint8_t> mac(EVP_MAX_MD_SIZE);
    unsigned int mac_len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         nonce.data(), nonce.size(), mac.data(), &mac_len);
    mac.resize(mac_len);
    return mac;
}

}  // namespace sapper
