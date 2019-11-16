#ifndef PROXY_PROTOCOL_INTIMATE_TRANS_H_H_H
#define PROXY_PROTOCOL_INTIMATE_TRANS_H_H_H

#include <memory>

#include "core/stm.h"
#include "core/tunnel.h"

namespace proxy {
namespace protocol {
namespace intimate {

class ProxyProtoTransmit {

public:
    static void *on_encryption_transmit(void *);
    static void *on_encryption_transmit_reverse(void *);
    static void *on_decryption_transmit(void *);
    static void *on_decryption_transmit_reverse(void *);
    static void *on_transmit(void *);
    static void *on_transmit_reverse(void *);

private:
    static proxy::core::ProxyStmEvent _on_encryption_transmit(
        std::shared_ptr<proxy::core::ProxyTunnel> &, bool);
    static proxy::core::ProxyStmEvent _on_decryption_transmit(
        std::shared_ptr<proxy::core::ProxyTunnel> &, bool);
    static proxy::core::ProxyStmEvent _on_transmit(
        std::shared_ptr<proxy::core::ProxyTunnel> &, bool);

};

}
}
}



#endif
