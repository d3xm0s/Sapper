// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// Agent side: dials out to the operator, opens channels into its network.

#include "agent.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "proto.hpp"
#include "tls_util.hpp"

namespace sapper {

namespace {

struct SslDeleter {
    void operator()(SSL* s) const { if (s) { SSL_shutdown(s); SSL_free(s); } }
};

std::mutex g_write_mtx;
std::map<uint32_t, int> g_channels;  // channel -> target fd
std::mutex g_chan_mtx;

int connect_tcp(const std::string& host, int port, int timeout_ms) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        return -1;
    }
    int fd = -1;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        if (::connect(fd, p->ai_addr, p->ai_addrlen) != 0 && errno == EINPROGRESS) {
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLOUT;
            if (::poll(&pfd, 1, timeout_ms) > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 &&
                    err == 0) {
                    break;  // connected
                }
            }
        } else if (errno == 0) {
            break;  // instant connect
        }
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    return fd;
}

// Pump target socket -> tunnel.
void target_pump(SSL* ssl, uint32_t chan, int fd) {
    uint8_t buf[16384];
    while (true) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        if (!write_frame(ssl, g_write_mtx, F_DATA, chan, buf,
                         static_cast<uint32_t>(n))) {
            break;
        }
    }
    write_frame(ssl, g_write_mtx, F_CLOSE, chan, nullptr, 0);
    std::lock_guard<std::mutex> lock(g_chan_mtx);
    auto it = g_channels.find(chan);
    if (it != g_channels.end()) {
        ::close(it->second);
        g_channels.erase(it);
    }
}

void open_channel(SSL* ssl, uint32_t chan, const std::string& target) {
    std::size_t colon = target.rfind(':');
    if (colon == std::string::npos) {
        write_frame(ssl, g_write_mtx, F_OPEN_FAIL, chan, nullptr, 0);
        return;
    }
    std::string host = target.substr(0, colon);
    int port = std::atoi(target.c_str() + colon + 1);

    int fd = connect_tcp(host, port, 10000);
    if (fd < 0) {
        write_frame(ssl, g_write_mtx, F_OPEN_FAIL, chan, nullptr, 0);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(g_chan_mtx);
        g_channels[chan] = fd;
    }
    write_frame(ssl, g_write_mtx, F_OPEN_OK, chan, nullptr, 0);
    std::thread(target_pump, ssl, chan, fd).detach();
}

// One tunnel session. Returns when the connection drops.
void session(SSL* ssl) {
    Frame f;
    while (read_frame(ssl, f)) {
        switch (f.type) {
            case F_OPEN: {
                std::string target(f.payload.begin(), f.payload.end());
                open_channel(ssl, f.channel, target);
                break;
            }
            case F_DATA: {
                std::lock_guard<std::mutex> lock(g_chan_mtx);
                auto it = g_channels.find(f.channel);
                if (it != g_channels.end() && !f.payload.empty()) {
                    ::send(it->second, f.payload.data(), f.payload.size(),
                           MSG_NOSIGNAL);
                }
                break;
            }
            case F_CLOSE: {
                std::lock_guard<std::mutex> lock(g_chan_mtx);
                auto it = g_channels.find(f.channel);
                if (it != g_channels.end()) {
                    ::close(it->second);
                    g_channels.erase(it);
                }
                break;
            }
            case F_PING:
                write_frame(ssl, g_write_mtx, F_PONG, 0, nullptr, 0);
                break;
            default:
                break;
        }
    }
}

bool handshake(SSL* ssl, const std::string& key) {
    Frame f;
    if (!read_frame(ssl, f) || f.type != F_HELLO || f.payload.size() != 32) {
        return false;
    }
    auto proof = auth_proof(key, f.payload);
    if (!write_frame(ssl, g_write_mtx, F_AUTH, 0, proof.data(),
                     static_cast<uint32_t>(proof.size()))) {
        return false;
    }
    return read_frame(ssl, f) && f.type == F_AUTH_OK;
}

}  // namespace

int run_agent(const std::string& addr, const std::string& key,
              const std::string& pin) {
    std::size_t colon = addr.rfind(':');
    if (colon == std::string::npos) {
        std::fprintf(stderr, "[!] agent needs host:port of the server\n");
        return 2;
    }
    std::string host = addr.substr(0, colon);
    int port = std::atoi(addr.c_str() + colon + 1);

    SSL_CTX* ctx = make_client_ctx();
    if (ctx == nullptr) {
        std::fprintf(stderr, "[!] cannot create TLS context\n");
        return 1;
    }

    int backoff = 1;
    while (true) {
        int fd = connect_tcp(host, port, 10000);
        if (fd < 0) {
            std::fprintf(stderr, "[*] server unreachable, retry in %ds\n",
                         backoff);
            ::sleep(static_cast<unsigned int>(backoff));
            if (backoff < 60) {
                backoff *= 2;
            }
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, host.c_str());
        if (SSL_connect(ssl) != 1) {
            SSL_free(ssl);
            ::close(fd);
            ::sleep(2);
            continue;
        }

        std::string fp = peer_fingerprint(ssl);
        if (!pin.empty() && pin != fp) {
            std::fprintf(stderr,
                         "[!] server cert pin mismatch (got %s) - bailing\n",
                         fp.c_str());
            SSL_free(ssl);
            ::close(fd);
            return 1;
        }

        if (!handshake(ssl, key)) {
            std::fprintf(stderr, "[!] auth failed\n");
            SSL_free(ssl);
            ::close(fd);
            ::sleep(5);
            continue;
        }

        backoff = 1;
        std::fprintf(stderr, "[+] tunnel up, server cert sha256=%s\n",
                     fp.c_str());

        session(ssl);

        std::fprintf(stderr, "[!] tunnel down, reconnecting\n");
        {
            std::lock_guard<std::mutex> lock(g_chan_mtx);
            for (auto& [id, cfd] : g_channels) {
                ::close(cfd);
            }
            g_channels.clear();
        }
        SSL_free(ssl);
        ::close(fd);
        ::sleep(2);
    }
}

}  // namespace sapper
