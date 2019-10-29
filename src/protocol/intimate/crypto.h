#ifndef PROXY_PROTOCOL_INTIMATE_CRYPTO_H_H_H
#define PROXY_PROTOCOL_INTIMATE_CRYPTO_H_H_H

#include <memory>

#include "core/tunnel.h"
#include "core/stm.h"

namespace proxy {
namespace protocol {
namespace intimate {

class ProxyProtoCryptoNegotiate {

public:
    static proxy::core::ProxyStmEvent on_rsa_pubkey_request(
        std::shared_ptr<proxy::core::ProxyTunnel> &);
    static proxy::core::ProxyStmEvent on_rsa_pubkey_response(
        std::shared_ptr<proxy::core::ProxyTunnel> &);

    static proxy::core::ProxyStmEvent on_aes_key_iv_send(
        std::shared_ptr<proxy::core::ProxyTunnel> &);
    static proxy::core::ProxyStmEvent on_aes_key_iv_recieve(
        std::shared_ptr<proxy::core::ProxyTunnel> &);

};


}
}
}


#endif
