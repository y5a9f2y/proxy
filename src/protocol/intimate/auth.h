#ifndef PROXY_PROTOCOL_INTIMATE_AUTH_H_H_H
#define PROXY_PROTOCOL_INTIMATE_AUTH_H_H_H

#include <memory>

#include "core/stm.h"
#include "core/tunnel.h"

namespace proxy {
namespace protocol {
namespace intimate {

class ProxyProtoAuthenticate {

public:
    static proxy::core::ProxyStmEvent on_identification_send(
        std::shared_ptr<proxy::core::ProxyTunnel> &);
    static proxy::core::ProxyStmEvent on_identification_receive(
        std::shared_ptr<proxy::core::ProxyTunnel> &);

};

}
}
}



#endif
