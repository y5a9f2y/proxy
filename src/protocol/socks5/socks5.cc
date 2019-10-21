#include "protocol/socks5/socks5.h"

namespace proxy {
namespace protocol {
namespace socks5 {

proxy::core::ProxyStmEvent ProxyProtoSocks5::on_establish(
    std::shared_ptr<proxy::core::ProxyTunnel> &tunnel) {

    return proxy::core::ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_OK;

}

}
}
}
