#ifndef PROXY_PROTOCOL_INTIMATE_ACK_H_H_H
#define PROXY_PROTOCOL_INTIMATE_ACK_H_H_H

#include <memory>

#include "core/tunnel.h"

namespace proxy {
namespace protocol {
namespace intimate {

enum class ProxyProtoAckDirect {
    PROXY_PROTO_ACK_EP0,
    PROXY_PROTO_ACK_EP1
};

class ProxyProtoAck {

public:
    static bool on_ack_send(std::shared_ptr<proxy::core::ProxyTunnel> &, ProxyProtoAckDirect);
    static bool on_ack_receive(std::shared_ptr<proxy::core::ProxyTunnel> &, ProxyProtoAckDirect);

};

}
}
}

#endif
