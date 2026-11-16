// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// Agent side: dials out to the operator, opens channels into its network.

#pragma once

#include <string>

namespace sapper {

// Connect to the operator at addr (host:port), authenticate with key, and
// serve channel requests. Reconnects with backoff forever.
// pin, when non-empty, must equal the server cert SHA-256 (lowercase hex).
int run_agent(const std::string& addr, const std::string& key,
              const std::string& pin);

}  // namespace sapper
