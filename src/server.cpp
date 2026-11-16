// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// Operator side: TLS listener for agents + local SOCKS5 frontend.

#include "server.hpp"

#include <arpa/inet.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <thread>

#include "proto.hpp"
#include "socks.hpp"
#include "tls_util.hpp"

namespace sapper {

namespace {

struct SslDeleter {
    void operator()(SSL* s) const { if (s) { SSL_shutdown(s); SSL_free(s); } }
};

// The currently attached agent. One pivot is enough for most ops; a newly
// connected agent replaces a dead or older one.
struct Agent {
    SSL* ssl = nullptr;
    std::mutex write_mtx;
    std::map<uint32_t, int> channels;         // channel -> local socks fd
    std::mutex chan_mtx;
    std::map<uint32_t, int> open_results;     // channel -> 1 ok / 0 fail
    std::mutex open_mtx;
    std::atomic<bool> alive{false};
    uint32_t next_chan = 1;
};

std::shared_ptr<Agent> g_agent;
std::mutex g_agent_mtx;

void log(const std::string& a, const std::string& b) {
    std::fprintf(stderr, "%s%s\n", a.c_str(), b.c_str());
    std::fflush(stderr);
}

// Agent reader: dispatch frames to channels until the tunnel dies.
void agent_reader(std::shared_ptr<Agent> ag) {
    Frame f;
    while (ag->alive.load() && read_frame(ag->ssl, f)) {
        switch (f.type) {
            case F_DATA: {
                std::lock_guard<std::mutex> lock(ag->chan_mtx);
                auto it = ag->channels.find(f.channel);
                if (it != ag->channels.end() && !f.payload.empty()) {
                    ::send(it->second, f.payload.data(), f.payload.size(),
                           MSG_NOSIGNAL);
                }
                break;
            }
            case F_OPEN_OK:
            case F_OPEN_FAIL: {
                std::lock_guard<std::mutex> lock(ag->open_mtx);
                ag->open_results[f.channel] = (f.type == F_OPEN_OK) ? 1 : 0;
                break;
            }
            case F_CLOSE: {
                std::lock_guard<std::mutex> lock(ag->chan_mtx);
                auto it = ag->channels.find(f.channel);
                if (it != ag->channels.end()) {
                    ::close(it->second);
                    ag->channels.erase(it);
                }
                break;
            }
            case F_PING:
                write_frame(ag->ssl, ag->write_mtx, F_PONG, 0, nullptr, 0);
                break;
            default:
                break;
        }
    }

    // Tunnel died: fail every channel so socks clients do not hang.
    ag->alive.store(false);
    std::lock_guard<std::mutex> lock(ag->chan_mtx);
    for (auto& [id, fd] : ag->channels) {
        ::close(fd);
    }
    ag->channels.clear();
    {
        std::lock_guard<std::mutex> olock(ag->open_mtx);
        for (auto& [id, st] : ag->open_results) {
            st = 0;
        }
    }
    log("[!] agent tunnel lost", "");
}

// Handshake with a freshly accepted agent connection.
void agent_handshake(SSL* ssl, int fd, const std::string& key) {
    std::vector<uint8_t> nonce(32);
    RAND_bytes(nonce.data(), static_cast<int>(nonce.size()));

    std::mutex mtx;
    if (!write_frame(ssl, mtx, F_HELLO, 0, nonce.data(),
                     static_cast<uint32_t>(nonce.size()))) {
        ::close(fd);
        return;
    }

    Frame f;
    if (!read_frame(ssl, f) || f.type != F_AUTH ||
        f.payload != auth_proof(key, nonce)) {
        write_frame(ssl, mtx, F_AUTH_FAIL, 0, nullptr, 0);
        ::close(fd);
        return;
    }
    write_frame(ssl, mtx, F_AUTH_OK, 0, nullptr, 0);

    auto ag = std::make_shared<Agent>();
    ag->ssl = ssl;
    ag->alive.store(true);
    {
        std::lock_guard<std::mutex> lock(g_agent_mtx);
        g_agent = ag;
    }
    log("[+] agent attached", "");

    agent_reader(ag);  // blocks until the tunnel dies
    ::close(fd);
}

// Pump local socks client -> tunnel.
void channel_pump(std::shared_ptr<Agent> ag, uint32_t chan, int fd) {
    uint8_t buf[16384];
    while (ag->alive.load()) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        if (!write_frame(ag->ssl, ag->write_mtx, F_DATA, chan, buf,
                         static_cast<uint32_t>(n))) {
            break;
        }
    }
    if (ag->alive.load()) {
        write_frame(ag->ssl, ag->write_mtx, F_CLOSE, chan, nullptr, 0);
    }
    {
        std::lock_guard<std::mutex> lock(ag->chan_mtx);
        auto it = ag->channels.find(chan);
        if (it != ag->channels.end()) {
            ::close(it->second);
            ag->channels.erase(it);
        }
    }
}

// One SOCKS client: negotiate, open a channel through the tunnel, pump.
void socks_client(int fd) {
    std::string target;
    if (!socks5_negotiate(fd, target)) {
        ::close(fd);
        return;
    }

    std::shared_ptr<Agent> ag;
    {
        std::lock_guard<std::mutex> lock(g_agent_mtx);
        ag = g_agent;
    }
    if (!ag || !ag->alive.load()) {
        log("[!] socks client to ", target + " dropped: no agent");
        socks5_reply(fd, false);
        ::close(fd);
        return;
    }

    uint32_t chan;
    {
        std::lock_guard<std::mutex> lock(ag->chan_mtx);
        chan = ag->next_chan++;
        ag->channels[chan] = fd;
    }

    if (!write_frame(ag->ssl, ag->write_mtx, F_OPEN, chan, target)) {
        socks5_reply(fd, false);
        ::close(fd);
        return;
    }

    // Wait for the agent to answer the OPEN.
    int result = -1;
    for (int i = 0; i < 3000 && result < 0; ++i) {  // up to 15 s
        {
            std::lock_guard<std::mutex> lock(ag->open_mtx);
            auto it = ag->open_results.find(chan);
            if (it != ag->open_results.end()) {
                result = it->second;
                ag->open_results.erase(it);
                break;
            }
        }
        ::usleep(5000);
    }

    if (result != 1) {
        log("[!] open ", target + " failed");
        socks5_reply(fd, false);
        std::lock_guard<std::mutex> lock(ag->chan_mtx);
        ag->channels.erase(chan);
        ::close(fd);
        return;
    }

    socks5_reply(fd, true);
    log("[+] channel ", target + " open");
    channel_pump(ag, chan, fd);
}

int listen_on(const std::string& addr) {
    std::size_t colon = addr.rfind(':');
    std::string host = addr.substr(0, colon);
    int port = std::atoi(addr.c_str() + colon + 1);

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(port));
    if (host.empty() || host == "*") {
        sa.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) {
        ::close(fd);
        return -1;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0 ||
        ::listen(fd, 64) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

int run_server(const std::string& bind_addr, const std::string& socks_addr,
               const std::string& key) {
    SSL_CTX* ctx = make_server_ctx();
    if (ctx == nullptr) {
        std::fprintf(stderr, "[!] cannot create TLS context\n");
        return 1;
    }

    int agent_fd = listen_on(bind_addr);
    int socks_fd = listen_on(socks_addr);
    if (agent_fd < 0 || socks_fd < 0) {
        std::fprintf(stderr, "[!] cannot bind listeners\n");
        return 1;
    }

    std::fprintf(stderr, "[+] sapper server: agents on %s, socks5 on %s\n",
                 bind_addr.c_str(), socks_addr.c_str());

    // SOCKS frontend
    std::thread([socks_fd] {
        while (true) {
            int c = ::accept(socks_fd, nullptr, nullptr);
            if (c >= 0) {
                std::thread(socks_client, c).detach();
            }
        }
    }).detach();

    // Agent frontend
    while (true) {
        int c = ::accept(agent_fd, nullptr, nullptr);
        if (c < 0) {
            continue;
        }
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, c);
        if (SSL_accept(ssl) != 1) {
            SSL_free(ssl);
            ::close(c);
            continue;
        }
        std::thread(agent_handshake, ssl, c, key).detach();
    }
}

}  // namespace sapper
