// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// Minimal SOCKS5 server-side negotiation (no-auth, CONNECT).

#include "socks.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace sapper {

namespace {

bool read_exact(int fd, void* buf, std::size_t len) {
    auto* p = static_cast<uint8_t*>(buf);
    std::size_t got = 0;
    while (got < len) {
        ssize_t n = ::recv(fd, p + got, len - got, 0);
        if (n <= 0) {
            return false;
        }
        got += static_cast<std::size_t>(n);
    }
    return true;
}

}  // namespace

bool socks5_negotiate(int fd, std::string& target) {
    uint8_t head[2];
    if (!read_exact(fd, head, 2) || head[0] != 0x05) {
        return false;
    }
    std::vector<uint8_t> methods(head[1]);
    if (!methods.empty() && !read_exact(fd, methods.data(), methods.size())) {
        return false;
    }
    // no-auth always
    uint8_t greet_reply[2] = {0x05, 0x00};
    if (::send(fd, greet_reply, 2, MSG_NOSIGNAL) != 2) {
        return false;
    }

    uint8_t req[4];
    if (!read_exact(fd, req, 4) || req[0] != 0x05 || req[1] != 0x01) {
        return false;
    }

    std::string host;
    switch (req[3]) {
        case 0x01: {  // IPv4
            uint8_t a[4];
            if (!read_exact(fd, a, 4)) {
                return false;
            }
            char buf[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, a, buf, sizeof(buf));
            host = buf;
            break;
        }
        case 0x03: {  // domain
            uint8_t len = 0;
            if (!read_exact(fd, &len, 1) || len == 0) {
                return false;
            }
            std::vector<char> d(len);
            if (!read_exact(fd, d.data(), d.size())) {
                return false;
            }
            host.assign(d.begin(), d.end());
            break;
        }
        case 0x04: {  // IPv6
            uint8_t a[16];
            if (!read_exact(fd, a, 16)) {
                return false;
            }
            char buf[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, a, buf, sizeof(buf));
            host = buf;
            break;
        }
        default:
            return false;
    }

    uint8_t p[2];
    if (!read_exact(fd, p, 2)) {
        return false;
    }
    target = host + ":" + std::to_string((p[0] << 8) | p[1]);
    return true;
}

bool socks5_reply(int fd, bool granted) {
    uint8_t rep[10] = {0x05, granted ? uint8_t(0x00) : uint8_t(0x05),
                       0x00, 0x01, 0, 0, 0, 0, 0, 0};
    return ::send(fd, rep, sizeof(rep), MSG_NOSIGNAL) == sizeof(rep);
}

}  // namespace sapper
