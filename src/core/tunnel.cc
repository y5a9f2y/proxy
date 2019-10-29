#include "core/tunnel.h"
#include "core/server.h"

namespace proxy {
namespace core {

ssize_t ProxyTunnel::read_from_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    return _from->read_eq(n, buffer);
}

ssize_t ProxyTunnel::write_from_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    return _from->write_eq(n, buffer);
}

ssize_t ProxyTunnel::read_to_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    return _to->read_eq(n, buffer);
}

ssize_t ProxyTunnel::write_to_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    return _to->write_eq(n, buffer);
}

}
}
