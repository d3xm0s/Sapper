// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// Wire framing and channel model shared by server and agent.

#pragma once

#include <openssl/ssl.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace sapper {

// One frame: [type u8][channel u32 LE][length u32 LE][payload]
enum : uint8_t {
    F_HELLO = 0,     // server -> agent: 32-byte auth nonce
    F_AUTH = 1,      // agent -> server: HMAC-SHA256(key, nonce)
    F_AUTH_OK = 2,
    F_AUTH_FAIL = 3,
    F_OPEN = 4,      // server -> agent: payload "host:port"
    F_OPEN_OK = 5,
    F_OPEN_FAIL = 6,
    F_DATA = 7,
    F_CLOSE = 8,
    F_PING = 9,
    F_PONG = 10,
};

struct Frame {
    uint8_t type = 0;
    uint32_t channel = 0;
    std::vector<uint8_t> payload;
};

// Blocking read of one frame. False on EOF or garbage length.
bool read_frame(SSL* ssl, Frame& out);

// Serialized write of one frame; callers share the connection.
bool write_frame(SSL* ssl, std::mutex& mtx, uint8_t type, uint32_t channel,
                 const void* data, uint32_t len);

bool write_frame(SSL* ssl, std::mutex& mtx, uint8_t type, uint32_t channel,
                 const std::string& s);

// HMAC-SHA256(key, nonce) as raw bytes for the AUTH frame.
std::vector<uint8_t> auth_proof(const std::string& key,
                                const std::vector<uint8_t>& nonce);

}  // namespace sapper
