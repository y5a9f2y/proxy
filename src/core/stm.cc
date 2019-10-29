#include <exception>
#include <memory>

#include "sys/types.h"
#include "sys/socket.h"

#include "core/stm.h"
#include "core/server.h"
#include "core/tunnel.h"
#include "core/socket.h"
#include "crypto/aes.h"
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

    try {
        tunnel->to()->connect();
    } catch(const std::exception &ex) {
        LOG(ERROR) << ex.what();
        return;
    }

    ProxyStmEvent ret =
        proxy::protocol::intimate::ProxyProtoCryptoNegotiate::on_rsa_pubkey_request(tunnel);


    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE:
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL:
            ProxyStmHelper::switch_state(tunnel, ret);
            break;
        default:
            LOG(ERROR) << tunnel->to_string() << ": the rsa public key request return unexpected"
                << ProxyStmHelper::event2string(ret);
            return;
    }

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE:
            _encryption_flow_aes_negotiate(tunnel);
            break;
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL:
        default:
            return;
    }

    return;

}

void ProxyStm::_encryption_flow_aes_negotiate(std::shared_ptr<ProxyTunnel> &tunnel) {

    std::shared_ptr<proxy::crypto::ProxyCryptoAesKeyAndIv> key_iv =
        proxy::crypto::ProxyCryptoAes::generate_key_and_iv();

    tunnel->aes_key(key_iv->key());
    tunnel->aes_iv(key_iv->iv());

    if(tunnel->aes_key().size() != proxy::crypto::ProxyCryptoAes::AES_KEY_SIZE) {
        LOG(ERROR) << tunnel->to_string() << ": unexpect aes key size "
            << tunnel->aes_key().size();
        return;
    }

    if(tunnel->aes_iv().size() != proxy::crypto::ProxyCryptoAes::AES_IV_SIZE) {
        LOG(ERROR) << tunnel->to_string() << ": unexpect aes iv size "
            << tunnel->aes_iv().size();
        return;
    }

    ProxyStmEvent ret =
        proxy::protocol::intimate::ProxyProtoCryptoNegotiate::on_aes_key_iv_send(tunnel);

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_SEND:
        case ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL:
            ProxyStmHelper::switch_state(tunnel, ret);
            break;
        default:
            LOG(ERROR) << tunnel->to_string() << ": the aes send method return unexpected "
                << ProxyStmHelper::event2string(ret);
            break;
    }

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_SEND:
            // TODO
            break;
        case ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL:
        default:
            return;
    }

    return;

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
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND:
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL:
            ProxyStmHelper::switch_state(tunnel, ret);
            break;
        default:
            LOG(ERROR) << "the rsa public key response to " << tunnel->from()->to_string()
                << " return unexpected " << ProxyStmHelper::event2string(ret);
            return;
    }

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND:
            _decryption_flow_aes_negotiate(tunnel);
            break;
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL:
        default:
            return;
    }

    return;

}

void ProxyStm::_decryption_flow_aes_negotiate(std::shared_ptr<ProxyTunnel> &tunnel) {

    ProxyStmEvent ret =
        proxy::protocol::intimate::ProxyProtoCryptoNegotiate::on_aes_key_iv_recieve(tunnel);

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_RECIEVE:
        case ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL:
            ProxyStmHelper::switch_state(tunnel, ret);
            break;
        default:
            LOG(ERROR) << tunnel->to_string() << ": the aes recieve method return unexpected "
                << ProxyStmHelper::event2string(ret);
            break;
    }

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_RECIEVE:
            // TODO
            break;
        case ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL:
        default:
            return;
    }

    return;
}

const ProxyStmTranslation ProxyStmHelper::stm_table[] = {

    {ProxyStmState::PROXY_STM_ENCRYPTION_READY,
        ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH,
        ProxyStmState::PROXY_STM_ENCRYPTION_RSA_NEGOTIATING},

    {ProxyStmState::PROXY_STM_ENCRYPTION_RSA_NEGOTIATING,
        ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE,
        ProxyStmState::PROXY_STM_ENCRYPTION_AES_NEGOTIATING},

    {ProxyStmState::PROXY_STM_ENCRYPTION_RSA_NEGOTIATING,
        ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL,
        ProxyStmState::PROXY_STM_ENCRYPTION_FAIL},

    {ProxyStmState::PROXY_STM_DECRYPTION_READY,
        ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH,
        ProxyStmState::PROXY_STM_DECRYPTION_RSA_NEGOTIATING},

    {ProxyStmState::PROXY_STM_DECRYPTION_RSA_NEGOTIATING,
        ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND,
        ProxyStmState::PROXY_STM_DECRYPTION_AES_NEGOTIATING},

    {ProxyStmState::PROXY_STM_DECRYPTION_RSA_NEGOTIATING,
        ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL,
        ProxyStmState::PROXY_STM_DECRYPTION_FAIL},

};

const std::unordered_map<ProxyStmState, std::string> ProxyStmHelper::ProxyStmStateString = {
    {ProxyStmState::PROXY_STM_ENCRYPTION_READY, "PROXY_STM_ENCRYPTION_READY"},
    {ProxyStmState::PROXY_STM_ENCRYPTION_RSA_NEGOTIATING, "PROXY_STM_ENCRYPTION_RSA_NEGOTIATING"},
    {ProxyStmState::PROXY_STM_ENCRYPTION_AES_NEGOTIATING, "PROXY_STM_ENCRYPTION_AES_NEGOTIATING"},
    {ProxyStmState::PROXY_STM_ENCRYPTION_FAIL, "PROXY_STM_ENCRYPTION_FAIL"},
    {ProxyStmState::PROXY_STM_TRANSMISSION_READY, "PROXY_STM_TRANSMISSION_READY"},
    {ProxyStmState::PROXY_STM_DECRYPTION_READY, "PROXY_STM_DECRYPTION_READY"},
    {ProxyStmState::PROXY_STM_DECRYPTION_RSA_NEGOTIATING, "PROXY_STM_DECRYPTION_RSA_NEGOTIATING"},
    {ProxyStmState::PROXY_STM_DECRYPTION_AES_NEGOTIATING, "PROXY_STM_DECRYPTION_AES_NEGOTIATING"},
    {ProxyStmState::PROXY_STM_DECRYPTION_FAIL, "PROXY_STM_DECRYPTION_FAIL"}
};

const std::unordered_map<ProxyStmEvent, std::string> ProxyStmHelper::ProxyStmEventString = {
    {ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH, "PROXY_STM_EVENT_ESTABLISH"},
    {ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND, "PROXY_STM_EVENT_RSA_PUBKEY_SEND"},
    {ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE, "PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE"},
    {ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL, "PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL"},
    {ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_SEND, "PROXY_STM_EVENT_AES_KEY_SEND"},
    {ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_RECIEVE, "PROXY_STM_EVENT_AES_KEY_RECIEVE"},
    {ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL, "PROXY_STM_EVENT_AES_NEGOTIATING_FAIL"}
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
