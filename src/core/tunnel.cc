#include "core/tunnel.h"
#include "core/server.h"

namespace proxy {
namespace core {

ssize_t ProxyTunnel::read_from_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    return _from.get()->read_eq(n, buffer);
}

}
}
