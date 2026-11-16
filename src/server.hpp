// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// Operator side: TLS listener for agents + local SOCKS5 frontend.

#pragma once

#include <string>

namespace sapper {

// Listen for agents on bind_addr and serve SOCKS5 on socks_addr.
// Blocks forever; Ctrl-C to stop.
int run_server(const std::string& bind_addr, const std::string& socks_addr,
               const std::string& key);

}  // namespace sapper
