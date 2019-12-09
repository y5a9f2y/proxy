#ifndef PROXY_PROTOCOL_SOCKS5_H_H_H
#define PROXY_PROTOCOL_SOCKS5_H_H_H

#include <memory>

#include "core/tunnel.h"

namespace proxy {
namespace protocol {
namespace socks5 {

class ProxyProtoSocks5 {

public:

    static bool on_handshake(std::shared_ptr<proxy::core::ProxyTunnel> &);
    static bool on_request(std::shared_ptr<proxy::core::ProxyTunnel> &);
    static const char VERSION;

};

}
}
}


#endif
