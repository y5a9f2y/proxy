#include <exception>
#include <memory>

#include "stdlib.h"
#include "sys/types.h"
#include "sys/socket.h"

#include "core/stm.h"
#include "core/server.h"
#include "core/tunnel.h"
#include "core/socket.h"
#include "crypto/aes.h"
#include "protocol/socks5/socks5.h"
#include "protocol/intimate/crypto.h"
#include "protocol/intimate/auth.h"
#include "protocol/intimate/trans.h"

#include "glog/logging.h"

extern "C" {
#include "coroutine/coroutine.h"
}

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

    std::shared_ptr<ProxyTunnel> tunnel = std::make_shared<ProxyTunnel>(std::move(fd),
        std::move(nullptr), server, ProxyStmState::PROXY_STM_ENCRYPTION_READY);

    server->add_tunnel(tunnel);

    ProxyStmHelper::switch_state(tunnel, ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH);

    _encryption_flow_rsa_negotiate(tunnel);

}

void ProxyStm::_encryption_flow_rsa_negotiate(std::shared_ptr<ProxyTunnel> &tunnel) {

    try {
        tunnel->ep1(std::make_shared<ProxyTcpSocket>(AF_INET, 0));
        tunnel->ep1()->host(tunnel->server()->config().remote_host());
        tunnel->ep1()->port(tunnel->server()->config().remote_port());
    } catch(const std::exception &ex) {
        LOG(ERROR) << "create the remote socket fd from " << tunnel->ep0()->to_string()
            << "error: " << ex.what();
        return;
    }

    try {
        tunnel->ep1()->connect();
    } catch(const std::exception &ex) {
        LOG(ERROR) << ex.what();
        return;
    }

    ProxyStmEvent ret =
        proxy::protocol::intimate::ProxyProtoCryptoNegotiate::on_rsa_pubkey_request(tunnel);

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECEIVE:
        case ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL:
            ProxyStmHelper::switch_state(tunnel, ret);
            break;
        default:
            LOG(ERROR) << tunnel->ep0_ep1_string() 
                << ": the rsa public key request return unexpected"
                << ProxyStmHelper::event2string(ret);
            return;
    }

    if(ret == ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECEIVE) {
        _encryption_flow_aes_negotiate(tunnel);
    }

    return;

}

void ProxyStm::_encryption_flow_aes_negotiate(std::shared_ptr<ProxyTunnel> &tunnel) {

    using proxy::protocol::intimate::ProxyProtoCryptoNegotiate;
    using proxy::protocol::intimate::ProxyProtoCryptoNegotiateDirect;

    std::shared_ptr<proxy::crypto::ProxyCryptoAesKeyAndIv> key_iv =
        proxy::crypto::ProxyCryptoAes::generate_key_and_iv();
    tunnel->aes_key(key_iv->key());
    tunnel->aes_iv(key_iv->iv());
    tunnel->aes_ctx_setup(proxy::crypto::ProxyCryptoAesContextType::AES_CONTEXT_ENCRYPT_TYPE);

    key_iv = proxy::crypto::ProxyCryptoAes::generate_key_and_iv();
    tunnel->aes_key_peer(key_iv->key());
    tunnel->aes_iv_peer(key_iv->iv());
    tunnel->aes_ctx_peer_setup(proxy::crypto::ProxyCryptoAesContextType::AES_CONTEXT_DECRYPT_TYPE);

    ProxyStmEvent ret = ProxyProtoCryptoNegotiate::on_aes_key_iv_send(tunnel,
        ProxyProtoCryptoNegotiateDirect::PROXY_PROTO_CRYPTO_NEGOTIATE_EP1);

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_SEND:
        case ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL:
            ProxyStmHelper::switch_state(tunnel, ret);
            break;
        default:
            LOG(ERROR) << tunnel->ep0_ep1_string() << ": the aes send method return unexpected "
                << ProxyStmHelper::event2string(ret);
            break;
    }

    LOG(INFO) << tunnel->ep0_ep1_string()
        << " [aes_key:" << tunnel->aes_key()
        << "][aes_iv:" << tunnel->aes_iv()
        << "][aes_key_peer:" << tunnel->aes_key_peer()
        << "][aes_iv_peer:" << tunnel->aes_iv_peer() << "]";

    if(ret == ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_SEND) {
        _encryption_flow_authenticate(tunnel);
    }
    
    return;

}

void ProxyStm::_encryption_flow_authenticate(std::shared_ptr<ProxyTunnel> &tunnel) {

    ProxyStmEvent ret =
        proxy::protocol::intimate::ProxyProtoAuthenticate::on_identification_send(tunnel);

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_OK:
        case ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL:
            ProxyStmHelper::switch_state(tunnel, ret);
            break;
        default:
            LOG(ERROR) << tunnel->ep0_ep1_string()
                << ": the authentication method return unexpected "
                << ProxyStmHelper::event2string(ret);
    }

    if(ret == ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_OK) {
        _encryption_flow_transmit(tunnel);
    }

    return;

}

void ProxyStm::_encryption_flow_transmit(std::shared_ptr<ProxyTunnel> &tunnel) {

    co_thread_t *c;
    co_thread_t *c_r;

    if(!(c = coroutine_create(
        proxy::protocol::intimate::ProxyProtoTransmit::on_enc_mode_transmit_ep0_ep1,
        reinterpret_cast<void *>(&tunnel)))) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": create the ep0-ep1 coroutine error: "
            << strerror(errno);
        return;
    }

    if(!(c_r = coroutine_create(
        proxy::protocol::intimate::ProxyProtoTransmit::on_enc_mode_transmit_ep1_ep0,
        reinterpret_cast<void *>(&tunnel)))) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": create the ep1-ep0 coroutine error: "
            << strerror(errno);
        return;
    
    }

    coroutine_join(c, NULL);
    coroutine_join(c_r, NULL);

    //ProxyStmHelper::switch_state(tunnel, ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL);

    return;

}


void ProxyStm::_transmission_flow_startup(std::shared_ptr<ProxySocket> fd, ProxyServer *server) {

}

void ProxyStm::_decryption_flow_startup(std::shared_ptr<ProxySocket> fd, ProxyServer *server) {

    std::shared_ptr<ProxyTunnel> tunnel = std::make_shared<ProxyTunnel>(std::move(fd),
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
            LOG(ERROR) << "the rsa public key response to " << tunnel->ep0()->to_string()
                << " return unexpected " << ProxyStmHelper::event2string(ret);
            return;
    }

    if(ret == ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND) {
        _decryption_flow_aes_negotiate(tunnel);
    }

    return;

}

void ProxyStm::_decryption_flow_aes_negotiate(std::shared_ptr<ProxyTunnel> &tunnel) {

    using proxy::protocol::intimate::ProxyProtoCryptoNegotiate;
    using proxy::protocol::intimate::ProxyProtoCryptoNegotiateDirect;

    ProxyStmEvent ret = ProxyProtoCryptoNegotiate::on_aes_key_iv_receive(tunnel,
        ProxyProtoCryptoNegotiateDirect::PROXY_PROTO_CRYPTO_NEGOTIATE_EP0);

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_RECEIVE:
        case ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL:
            ProxyStmHelper::switch_state(tunnel, ret);
            break;
        default:
            LOG(ERROR) << tunnel->ep0_ep1_string() << ": the aes receive method return unexpected "
                << ProxyStmHelper::event2string(ret);
            break;
    }

    LOG(INFO) << tunnel->ep0_ep1_string()
        << " [aes_key:" << tunnel->aes_key()
        << "][aes_iv:" << tunnel->aes_iv()
        << "][aes_key_peer:" << tunnel->aes_key_peer()
        << "][aes_iv_peer:" << tunnel->aes_iv_peer() << "]";

    if(ret == ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_RECEIVE) {
        _decryption_flow_authenticate(tunnel);
    }

    return;

}

void ProxyStm::_decryption_flow_authenticate(std::shared_ptr<ProxyTunnel> &tunnel) {

    ProxyStmEvent ret =
        proxy::protocol::intimate::ProxyProtoAuthenticate::on_identification_receive(tunnel);

    switch(ret) {
        case ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_OK:
        case ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL:
            ProxyStmHelper::switch_state(tunnel, ret);
            break;
        default:
            LOG(ERROR) << tunnel->ep0_ep1_string()
                << ": the authentication method return unexpected "
                << ProxyStmHelper::event2string(ret);
            break;
    }

    if(ret == ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_OK) {
        _decryption_flow_socks5_negotiate(tunnel);
    }

    return;

}


void ProxyStm::_decryption_flow_socks5_negotiate(std::shared_ptr<ProxyTunnel> &tunnel) {

    if(!proxy::protocol::socks5::ProxyProtoSocks5::on_handshake(tunnel)) {
        ProxyStmHelper::switch_state(tunnel, ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_HANDSHAKE_FAIL);
        return;
    }

    ProxyStmHelper::switch_state(tunnel, ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_HANDSHAKE_OK);

    if(!proxy::protocol::socks5::ProxyProtoSocks5::on_request(tunnel)) {
        ProxyStmHelper::switch_state(tunnel, ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_REQUEST_FAIL);
        return;
    }

    ProxyStmHelper::switch_state(tunnel, ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_REQUEST_OK);

//    _decryption_flow_transmit(tunnel);

}

void ProxyStm::_decryption_flow_transmit(std::shared_ptr<ProxyTunnel> &tunnel) {

    return;

}

const ProxyStmTranslation ProxyStmHelper::stm_table[] = {

    {ProxyStmState::PROXY_STM_ENCRYPTION_READY,
        ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH,
        ProxyStmState::PROXY_STM_ENCRYPTION_RSA_NEGOTIATING},

    {ProxyStmState::PROXY_STM_ENCRYPTION_RSA_NEGOTIATING,
        ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECEIVE,
        ProxyStmState::PROXY_STM_ENCRYPTION_AES_NEGOTIATING},

    {ProxyStmState::PROXY_STM_ENCRYPTION_RSA_NEGOTIATING,
        ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL,
        ProxyStmState::PROXY_STM_ENCRYPTION_FAIL},

    {ProxyStmState::PROXY_STM_ENCRYPTION_AES_NEGOTIATING,
        ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_SEND,
        ProxyStmState::PROXY_STM_ENCRYPTION_AUTHENTICATING},

    {ProxyStmState::PROXY_STM_ENCRYPTION_AES_NEGOTIATING,
        ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL,
        ProxyStmState::PROXY_STM_ENCRYPTION_FAIL},

    {ProxyStmState::PROXY_STM_ENCRYPTION_AUTHENTICATING,
        ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_OK,
        ProxyStmState::PROXY_STM_ENCRYPTION_TRANSMITTING},

    {ProxyStmState::PROXY_STM_ENCRYPTION_AUTHENTICATING,
        ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL,
        ProxyStmState::PROXY_STM_ENCRYPTION_FAIL},

    {ProxyStmState::PROXY_STM_ENCRYPTION_TRANSMITTING,
        ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_OK,
        ProxyStmState::PROXY_STM_ENCRYPTION_DONE},

    {ProxyStmState::PROXY_STM_ENCRYPTION_TRANSMITTING,
        ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL,
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

    {ProxyStmState::PROXY_STM_DECRYPTION_AES_NEGOTIATING,
        ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_RECEIVE,
        ProxyStmState::PROXY_STM_DECRYPTION_AUTHENTICATING},

    {ProxyStmState::PROXY_STM_DECRYPTION_AES_NEGOTIATING,
        ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL,
        ProxyStmState::PROXY_STM_DECRYPTION_FAIL},

    {ProxyStmState::PROXY_STM_DECRYPTION_AUTHENTICATING,
        ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_OK,
        ProxyStmState::PROXY_STM_DECRYPTION_SOCKS5_HANDSHAKING},

    {ProxyStmState::PROXY_STM_DECRYPTION_AUTHENTICATING,
        ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL,
        ProxyStmState::PROXY_STM_DECRYPTION_FAIL},

    {ProxyStmState::PROXY_STM_DECRYPTION_SOCKS5_HANDSHAKING,
        ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_HANDSHAKE_OK,
        ProxyStmState::PROXY_STM_DECRYPTION_SOCKS5_REQUESTING},

    {ProxyStmState::PROXY_STM_DECRYPTION_SOCKS5_HANDSHAKING,
        ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_HANDSHAKE_FAIL,
        ProxyStmState::PROXY_STM_DECRYPTION_FAIL},

    {ProxyStmState::PROXY_STM_DECRYPTION_SOCKS5_REQUESTING,
        ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_REQUEST_OK,
        ProxyStmState::PROXY_STM_DECRYPTION_TRANSMITTING},

    {ProxyStmState::PROXY_STM_DECRYPTION_SOCKS5_REQUESTING,
        ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_REQUEST_FAIL,
        ProxyStmState::PROXY_STM_DECRYPTION_FAIL},

    {ProxyStmState::PROXY_STM_DECRYPTION_TRANSMITTING,
        ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_OK,
        ProxyStmState::PROXY_STM_DECRYPTION_DONE},

    {ProxyStmState::PROXY_STM_DECRYPTION_TRANSMITTING,
        ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL,
        ProxyStmState::PROXY_STM_DECRYPTION_FAIL}

};

const std::unordered_map<ProxyStmState, std::string> ProxyStmHelper::ProxyStmStateString = {
    {ProxyStmState::PROXY_STM_ENCRYPTION_READY, "PROXY_STM_ENCRYPTION_READY"},
    {ProxyStmState::PROXY_STM_ENCRYPTION_RSA_NEGOTIATING, "PROXY_STM_ENCRYPTION_RSA_NEGOTIATING"},
    {ProxyStmState::PROXY_STM_ENCRYPTION_AES_NEGOTIATING, "PROXY_STM_ENCRYPTION_AES_NEGOTIATING"},
    {ProxyStmState::PROXY_STM_ENCRYPTION_AUTHENTICATING, "PROXY_STM_ENCRYPTION_AUTHENTICATING"},
    {ProxyStmState::PROXY_STM_ENCRYPTION_TRANSMITTING, "PROXY_STM_ENCRYPTION_TRANSMITTING"},
    {ProxyStmState::PROXY_STM_ENCRYPTION_FAIL, "PROXY_STM_ENCRYPTION_FAIL"},
    {ProxyStmState::PROXY_STM_ENCRYPTION_DONE, "PROXY_STM_ENCRYPTION_DONE"},
    {ProxyStmState::PROXY_STM_TRANSMISSION_READY, "PROXY_STM_TRANSMISSION_READY"},
    {ProxyStmState::PROXY_STM_DECRYPTION_READY, "PROXY_STM_DECRYPTION_READY"},
    {ProxyStmState::PROXY_STM_DECRYPTION_RSA_NEGOTIATING, "PROXY_STM_DECRYPTION_RSA_NEGOTIATING"},
    {ProxyStmState::PROXY_STM_DECRYPTION_AES_NEGOTIATING, "PROXY_STM_DECRYPTION_AES_NEGOTIATING"},
    {ProxyStmState::PROXY_STM_DECRYPTION_AUTHENTICATING, "PROXY_STM_DECRYPTION_AUTHENTICATING"},
    {ProxyStmState::PROXY_STM_DECRYPTION_SOCKS5_HANDSHAKING,
        "PROXY_STM_DECRYPTION_SOCKS5_HANDSHAKING"},
    {ProxyStmState::PROXY_STM_DECRYPTION_SOCKS5_REQUESTING,
        "PROXY_STM_DECRYPTION_SOCKS5_REQUESTING"},
    {ProxyStmState::PROXY_STM_DECRYPTION_TRANSMITTING, "PROXY_STM_DECRYPTION_TRANSMITTING"},
    {ProxyStmState::PROXY_STM_DECRYPTION_FAIL, "PROXY_STM_DECRYPTION_FAIL"},
    {ProxyStmState::PROXY_STM_DECRYPTION_DONE, "PROXY_STM_DECRYPTION_DONE"}
};

const std::unordered_map<ProxyStmEvent, std::string> ProxyStmHelper::ProxyStmEventString = {
    {ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH, "PROXY_STM_EVENT_ESTABLISH"},
    {ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND, "PROXY_STM_EVENT_RSA_PUBKEY_SEND"},
    {ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECEIVE, "PROXY_STM_EVENT_RSA_PUBKEY_RECEIVE"},
    {ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL, "PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL"},
    {ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_SEND, "PROXY_STM_EVENT_AES_KEY_SEND"},
    {ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_RECEIVE, "PROXY_STM_EVENT_AES_KEY_RECEIVE"},
    {ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL, "PROXY_STM_EVENT_AES_NEGOTIATING_FAIL"},
    {ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_OK, "PROXY_STM_EVENT_AUTHENTICATING_OK"},
    {ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL, "PROXY_STM_EVENT_AUTHENTICATING_FAIL"},
    {ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_HANDSHAKE_OK, "PROXY_STM_EVENT_SOCKS5_HANDSHAKE_OK"},
    {ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_HANDSHAKE_FAIL, "PROXY_STM_EVENT_SOCKS5_HANDSHAKE_FAIL"},
    {ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_REQUEST_OK, "PROXY_STM_EVENT_SOCKS5_REQUEST_OK"},
    {ProxyStmEvent::PROXY_STM_EVENT_SOCKS5_REQUEST_FAIL, "PROXY_STM_EVENT_SOCKS5_REQUEST_FAIL"},
    {ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_OK, "PROXY_STM_EVENT_TRANSMISSION_OK"},
    {ProxyStmEvent::PROXY_STM_EVENT_TRANSMISSION_FAIL, "PROXY_STM_EVENT_TRANSMISSION_FAIL"}
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

            LOG(INFO) << tunnel->ep0_ep1_string() << " switch "
                << ProxyStmHelper::state2string(tunnel->state()) << "->"
                << ProxyStmHelper::state2string(ProxyStmHelper::stm_table[i].to);

            tunnel->state(ProxyStmHelper::stm_table[i].to);

            return true;

        }

    }

    LOG(ERROR) << "unknown translation: " << tunnel->ep0_ep1_string() << " with "
        << ProxyStmHelper::state2string(tunnel->state()) << "[event: "
        << ProxyStmHelper::event2string(ev) << "]";

    return false;

}

}
}
