#include "protocol/intimate/trans.h"

#include "core/buffer.h"

using proxy::core::ProxyStmEvent;
using proxy::core::ProxyTunnel;
using proxy::core::ProxyBuffer;

namespace proxy {
namespace protocol {
namespace intimate {

void *ProxyProtoTransmit::on_encryption_transmit(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_encryption_transmit(tunnel, true);
    return nullptr;

}

void *ProxyProtoTransmit::on_encryption_transmit_reverse(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_encryption_transmit(tunnel, false);
    return nullptr;

}

void *ProxyProtoTransmit::on_decryption_transmit(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_decryption_transmit(tunnel, true);
    return nullptr;

}

void *ProxyProtoTransmit::on_decryption_transmit_reverse(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_decryption_transmit(tunnel, false);
    return nullptr;

}

void *ProxyProtoTransmit::on_transmit(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_transmit(tunnel, true);
    return nullptr;

}

void *ProxyProtoTransmit::on_transmit_reverse(void *args) {

    std::shared_ptr<ProxyTunnel> tunnel = *reinterpret_cast<std::shared_ptr<ProxyTunnel> *>(args);
    ProxyProtoTransmit::_on_transmit(tunnel, false);
    return nullptr;

}

ProxyStmEvent ProxyProtoTransmit::_on_encryption_transmit(std::shared_ptr<ProxyTunnel> &tunnel,
    bool flag) {

    return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;

}

ProxyStmEvent ProxyProtoTransmit::_on_decryption_transmit(std::shared_ptr<ProxyTunnel> &tunnel,
    bool flag) {

    return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;

}

ProxyStmEvent ProxyProtoTransmit::_on_transmit(std::shared_ptr<ProxyTunnel> &tunnel, bool flag) {

    return ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL;

}

}
}
}
