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
    static void *on_enc_mode_transmit_ep0_ep1(void *);
    static void *on_enc_mode_transmit_ep1_ep0(void *);
    static void *on_dec_mode_transmit_ep0_ep1(void *);
    static void *on_dec_mode_transmit_ep1_ep0(void *);
    static void *on_trans_mode_transmit_ep0_ep1(void *);
    static void *on_trans_mode_transmit_ep1_ep0(void *);

private:
    static proxy::core::ProxyStmEvent _on_enc_mode_transmit(
        std::shared_ptr<proxy::core::ProxyTunnel> &, bool);
    static proxy::core::ProxyStmEvent _on_dec_mode_transmit(
        std::shared_ptr<proxy::core::ProxyTunnel> &, bool);
    static proxy::core::ProxyStmEvent _on_trans_mode_transmit(
        std::shared_ptr<proxy::core::ProxyTunnel> &, bool);
    static const size_t _TRANSMIT_BUFFER_SIZE;

};

}
}
}



#endif
