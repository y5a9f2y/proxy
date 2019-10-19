#include <exception>
#include <memory>

#include "core/stm.h"
#include "core/server.h"
#include "core/tunnel.h"

#include "glog/logging.h"

namespace proxy {
namespace core {

void *ProxyStm::startup(void *args) {

    ProxyStmFlowArgs *p = (ProxyStmFlowArgs *)(args);

    std::shared_ptr<ProxySocket> fd(p->fd);

    switch(p->server->config().mode()) {
        case ProxyServerType::Encryption:
            return _startup_encryption_flow(fd, p->server);
        case ProxyServerType::Transmission:
            return _startup_transmission_flow(fd, p->server);
        case ProxyServerType::Decryption:
            return _startup_decryption_flow(fd, p->server);
        default:
            LOG(INFO) << "unknown mode " << static_cast<int>(p->server->config().mode())
                << " from " << fd->to_string();
            break;
    }

    return nullptr;

}


void *ProxyStm::_startup_encryption_flow(std::shared_ptr<ProxySocket> fd, ProxyServer *server) {

    return nullptr;

}

void *ProxyStm::_startup_transmission_flow(std::shared_ptr<ProxySocket> fd, ProxyServer *server) {

    return nullptr;

}

void *ProxyStm::_startup_decryption_flow(std::shared_ptr<ProxySocket> fd, ProxyServer *server) {

    return nullptr;

}

std::string ProxyStmHelper::state2string(ProxyStmState state) {

    switch(state) {
        case ProxyStmState::PROXY_STM_ENCRYPTION_READY:
            return "PROXY_STM_ENCRYPTION_READY";
        case ProxyStmState::PROXY_STM_TRANSMISSION_READY:
            return "PROXY_STM_TRANSMISSION_READY";
        case ProxyStmState::PROXY_STM_DECRYPTION_READY:
            return "PROXY_STM_DECRYPTION_READY";
        default:
            return "UNKNOWN";
    }

}

}
}
