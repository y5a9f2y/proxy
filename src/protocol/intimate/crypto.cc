#include "protocol/intimate/crypto.h"
#include "core/buffer.h"

using proxy::core::ProxyStmEvent;
using proxy::core::ProxyTunnel;
using proxy::core::ProxyBuffer;

namespace proxy {
namespace protocol {
namespace intimate {

ProxyStmEvent ProxyProtoCryptoNegotiate::on_rsa_pubkey_request(
    std::shared_ptr<ProxyTunnel> &tunnel) {

    return ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE;
}

ProxyStmEvent ProxyProtoCryptoNegotiate::on_rsa_pubkey_response(
    std::shared_ptr<ProxyTunnel> &tunnel) {

    return ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND;

}

}
}
}
