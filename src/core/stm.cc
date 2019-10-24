#include <exception>
#include <memory>

#include "sys/types.h"
#include "sys/socket.h"

#include "core/stm.h"
#include "core/server.h"
#include "core/tunnel.h"
#include "core/socket.h"
#include "protocol/socks5/socks5.h"
#include "protocol/intimate/crypto.h"

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

    _encryption_flow_rsa_negotiate(tunnel);

}

void ProxyStm::_encryption_flow_rsa_negotiate(std::shared_ptr<ProxyTunnel> &tunnel) {

    try {
        tunnel->to(std::make_shared<ProxySocket>(AF_INET, SOCK_STREAM, 0));
        tunnel->to()->host(tunnel->server()->config().remote_host());
        tunnel->to()->port(tunnel->server()->config().remote_port());
    } catch(const std::exception &ex) {
        LOG(ERROR) << "create the remote socket fd from " << tunnel->from()->to_string()
            << "error: " << ex.what();
        return;
    }

    ProxyStmEvent ret =
        proxy::protocol::intimate::ProxyProtoCryptoNegotiate::on_rsa_pubkey_request(tunnel);

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE:
            break;
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL:
            break;
        default:
            break;
    }

}


void ProxyStm::_transmission_flow_startup(std::shared_ptr<ProxySocket> fd, ProxyServer *server) {

}

void ProxyStm::_decryption_flow_startup(std::shared_ptr<ProxySocket> fd, ProxyServer *server) {

    std::shared_ptr<ProxyTunnel> tunnel = std::make_shared<ProxyTcpTunnel>(std::move(fd),
        std::move(nullptr), server, ProxyStmState::PROXY_STM_DECRYPTION_READY);

    server->add_tunnel(tunnel);

    ProxyStmHelper::switch_state(tunnel, ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH);

    _decryption_flow_rsa_negotiate(tunnel);

}


void ProxyStm::_decryption_flow_rsa_negotiate(std::shared_ptr<ProxyTunnel> &tunnel) {

    ProxyStmEvent ret =
        proxy::protocol::intimate::ProxyProtoCryptoNegotiate::on_rsa_pubkey_response(tunnel);

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE:
            break;
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL:
            break;
        default:
            break;
    }

}

const ProxyStmTranslation ProxyStmHelper::stm_table[] = {

    {ProxyStmState::PROXY_STM_ENCRYPTION_READY,
        ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH,
        ProxyStmState::PROXY_STM_ENCRYPTION_RSA_NEGOTIATING},

    {ProxyStmState::PROXY_STM_DECRYPTION_READY,
        ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH,
        ProxyStmState::PROXY_STM_DECRYPTION_RSA_NEGOTIATING}

};

const std::unordered_map<ProxyStmState, std::string> ProxyStmHelper::ProxyStmStateString = {
    {ProxyStmState::PROXY_STM_ENCRYPTION_READY, "PROXY_STM_ENCRYPTION_READY"},
    {ProxyStmState::PROXY_STM_ENCRYPTION_RSA_NEGOTIATING, "PROXY_STM_ENCRYPTION_RSA_NEGOTIATING"},
    {ProxyStmState::PROXY_STM_TRANSMISSION_READY, "PROXY_STM_TRANSMISSION_READY"},
    {ProxyStmState::PROXY_STM_DECRYPTION_READY, "PROXY_STM_DECRYPTION_READY"},
    {ProxyStmState::PROXY_STM_DECRYPTION_RSA_NEGOTIATING, "PROXY_STM_DECRYPTION_RSA_NEGOTIATING"},
};

const std::unordered_map<ProxyStmEvent, std::string> ProxyStmHelper::ProxyStmEventString = {
    {ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH, "PROXY_STM_EVENT_ESTABLISH"},
    {ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND, "PROXY_STM_EVENT_RSA_PUBKEY_SEND"},
    {ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE, "PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE"},
    {ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL, "PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL"}
};

std::string ProxyStmHelper::state2string(ProxyStmState state) {

    auto p = ProxyStmStateString.find(state);
    if(p == ProxyStmStateString.end()) {
        return "UNKNOWN";
    }
    return p->second;

}

std::string ProxyStmHelper::event2string(ProxyStmEvent event) {

    auto p = ProxyStmEventString.find(event);
    if(p == ProxyStmEventString.end()) {
        return "UNKNOWN";
    }
    return p->second;

}

bool ProxyStmHelper::switch_state(std::shared_ptr<ProxyTunnel> &tunnel, ProxyStmEvent ev) {


    for(size_t i = 0; i < sizeof(ProxyStmHelper::stm_table) /
        sizeof(ProxyStmHelper::stm_table[0]); ++i) {

        if(tunnel->state() == ProxyStmHelper::stm_table[i].from &&
            ev == ProxyStmHelper::stm_table[i].event) {

            LOG(INFO) << "the tunnel state of " << tunnel->from()->to_string()
                << " switch from " << ProxyStmHelper::state2string(tunnel->state()) << " to "
                << ProxyStmHelper::state2string(ProxyStmHelper::stm_table[i].to);

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
