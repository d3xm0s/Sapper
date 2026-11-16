// SPDX-License-Identifier: MIT
// sapper - reverse TLS pivot with SOCKS5 multiplexing
// Minimal SOCKS5 server-side negotiation (no-auth, CONNECT).

#pragma once

#include <string>

namespace sapper {

// Run the SOCKS5 greeting and CONNECT request on an accepted client socket.
// On success returns true and fills target with "host:port". The final reply
// is NOT sent here - call socks5_reply once the channel is up or failed.
bool socks5_negotiate(int fd, std::string& target);

// Final CONNECT reply: rep 0x00 = granted, 0x05 = refused.
bool socks5_reply(int fd, bool granted);

}  // namespace sapper
