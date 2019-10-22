#include <exception>
#include <memory>

#include "core/stm.h"
#include "core/server.h"
#include "core/tunnel.h"
#include "protocol/socks5/socks5.h"

#include "glog/logging.h"

namespace proxy {
namespace core {

void *ProxyStm::startup(void *args) {

    ProxyStmFlowArgs *p = (ProxyStmFlowArgs *)(args);

    std::shared_ptr<ProxySocket> fd(p->fd);

    switch(p->server->config().mode()) {
        case ProxyServerType::Encryption:
            _encryption_flow_startup(fd, p->server);
            break;
        case ProxyServerType::Transmission:
            _transmission_flow_startup(fd, p->server);
            break;
        case ProxyServerType::Decryption:
            _decryption_flow_startup(fd, p->server);
            break;
        default:
            LOG(INFO) << "unknown mode " << static_cast<int>(p->server->config().mode())
                << " from " << fd->to_string();
            break;
    }

    delete p;

    return nullptr;

}


void ProxyStm::_encryption_flow_startup(std::shared_ptr<ProxySocket> fd, ProxyServer *server) {

    std::shared_ptr<ProxyTunnel> tunnel = std::make_shared<ProxyTcpTunnel>(std::move(fd),
        std::move(nullptr), server, ProxyStmState::PROXY_STM_ENCRYPTION_READY);

    server->add_tunnel(tunnel);

    ProxyStmHelper::switch_state(tunnel, ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH);

    _encryption_flow_establish(tunnel);

}

void ProxyStm::_encryption_flow_establish(std::shared_ptr<ProxyTunnel> &tunnel) {

    ProxyStmEvent ret = proxy::protocol::socks5::ProxyProtoSocks5::on_establish(tunnel);

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_OK:
            break;
        case ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_NOACCEPT:
            break;
        case ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_FAIL:
            break;
        default:
            LOG(ERROR) << "the result of on_establish of connection "
                << tunnel->from()->to_string() << " error: the value is "
                << ProxyStmHelper::event2string(ret);
            break;
    }

}

void ProxyStm::_transmission_flow_startup(std::shared_ptr<ProxySocket> fd, ProxyServer *server) {

}

void ProxyStm::_decryption_flow_startup(std::shared_ptr<ProxySocket> fd, ProxyServer *server) {

}

const ProxyStmTranslation ProxyStmHelper::stm_table[] = {

    {ProxyStmState::PROXY_STM_ENCRYPTION_READY,
        ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH,
        ProxyStmState::PROXY_STM_ENCRYPTION_ESTABLISHING},

    {ProxyStmState::PROXY_STM_ENCRYPTION_ESTABLISHING,
        ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_OK,
        ProxyStmState::PROXY_STM_ENCRYPTION_CONNECTING_REMOTE},

    {ProxyStmState::PROXY_STM_ENCRYPTION_ESTABLISHING,
        ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_NOACCEPT,
        ProxyStmState::PROXY_STM_ENCRYPTION_NOACCEPT_SENDING},

    {ProxyStmState::PROXY_STM_ENCRYPTION_ESTABLISHING,
        ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_FAIL,
        ProxyStmState::PROXY_STM_ENCRYPTION_ERROR},

    {ProxyStmState::PROXY_STM_ENCRYPTION_CONNECTING_REMOTE,
        ProxyStmEvent::PROXY_STM_EVENT_CONNECT_OK,
        ProxyStmState::PROXY_STM_ENCRYPTION_USERPASS_NEGOTIATING},

    {ProxyStmState::PROXY_STM_ENCRYPTION_CONNECTING_REMOTE,
        ProxyStmEvent::PROXY_STM_EVENT_CONNECT_FAIL,
        ProxyStmState::PROXY_STM_ENCRYPTION_ERROR},

};

std::string ProxyStmHelper::state2string(ProxyStmState state) {

    switch(state) {
        case ProxyStmState::PROXY_STM_ENCRYPTION_READY:
            return "PROXY_STM_ENCRYPTION_READY";
        case ProxyStmState::PROXY_STM_ENCRYPTION_ESTABLISHING:
            return "PROXY_STM_ENCRYPTION_ESTABLISHING";
        case ProxyStmState::PROXY_STM_ENCRYPTION_NOACCEPT_SENDING:
            return "PROXY_STM_ENCRYPTION_NOACCEPT_SENDING";
        case ProxyStmState::PROXY_STM_ENCRYPTION_CONNECTING_REMOTE:
            return "PROXY_STM_ENCRYPTION_CONNECTING_REMOTE";
        case ProxyStmState::PROXY_STM_ENCRYPTION_USERPASS_NEGOTIATING:
            return "PROXY_STM_ENCRYPTION_USERPASS_NEGOTIATING";
        case ProxyStmState::PROXY_STM_ENCRYPTION_ERROR:
            return "PROXY_STM_ENCRYPTION_ERROR";
        case ProxyStmState::PROXY_STM_TRANSMISSION_READY:
            return "PROXY_STM_TRANSMISSION_READY";
        case ProxyStmState::PROXY_STM_DECRYPTION_READY:
            return "PROXY_STM_DECRYPTION_READY";
        default:
            return "UNKNOWN";
    }

}

std::string ProxyStmHelper::event2string(ProxyStmEvent event) {

    switch(event) {
        case ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH:
            return "PROXY_STM_EVENT_ESTABLISH";
        case ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_OK:
            return "PROXY_STM_EVENT_ESTABLISH_OK";
        case ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_FAIL:
            return "PROXY_STM_EVENT_ESTABLISH_FAIL";
        case ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_NOACCEPT:
            return "PROXY_STM_EVENT_ESTABLISH_NOACCEPT";
        case ProxyStmEvent::PROXY_STM_EVENT_CONNECT_OK:
            return "PROXY_STM_EVENT_CONNECT_OK";
        case ProxyStmEvent::PROXY_STM_EVENT_CONNECT_FAIL:
            return "PROXY_STM_EVENT_CONNECT_FAIL";
        default:
            return "UNKNOWN";
    }

}

bool ProxyStmHelper::switch_state(std::shared_ptr<ProxyTunnel> &tunnel, ProxyStmEvent ev) {


    for(size_t i = 0; i < sizeof(ProxyStmHelper::stm_table) /
        sizeof(ProxyStmHelper::stm_table[0]); ++i) {

        if(tunnel->state() == ProxyStmHelper::stm_table[i].from &&
            ev == ProxyStmHelper::stm_table[i].event) {
            tunnel->state(ProxyStmHelper::stm_table[i].to);
            return true;
        }

    }

    LOG(ERROR) << "the tunnel state is " << ProxyStmHelper::state2string(tunnel->state())
        << ", the event is " << ProxyStmHelper::event2string(ev) << ", unknown translation";

    return false;

}

}
}
