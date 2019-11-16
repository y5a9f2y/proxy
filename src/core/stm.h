#ifndef PROXY_CORE_STM_H_H_H
#define PROXY_CORE_STM_H_H_H

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <unordered_map>

#include "core/config.h"
#include "core/socket.h"

namespace proxy {
namespace core {

class ProxyServer;
class ProxyTunnel;

enum class ProxyStmState {

    PROXY_STM_ENCRYPTION_READY,
    PROXY_STM_ENCRYPTION_RSA_NEGOTIATING,
    PROXY_STM_ENCRYPTION_AES_NEGOTIATING,
    PROXY_STM_ENCRYPTION_AUTHENTICATING,
    PROXY_STM_ENCRYPTION_TRANSMITTING,
    PROXY_STM_ENCRYPTION_FAIL,
    PROXY_STM_ENCRYPTION_DONE,
    PROXY_STM_TRANSMISSION_READY,
    PROXY_STM_DECRYPTION_READY,
    PROXY_STM_DECRYPTION_RSA_NEGOTIATING,
    PROXY_STM_DECRYPTION_AES_NEGOTIATING,
    PROXY_STM_DECRYPTION_AUTHENTICATING,
    PROXY_STM_DECRYPTION_TRANSMITTING,
    PROXY_STM_DECRYPTION_FAIL,
    PROXY_STM_DECRYPTION_DONE

};

enum class ProxyStmEvent {

    PROXY_STM_EVENT_ESTABLISH,
    PROXY_STM_EVENT_RSA_PUBKEY_SEND,
    PROXY_STM_EVENT_RSA_PUBKEY_RECEIVE,
    PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL,
    PROXY_STM_EVENT_AES_KEY_SEND,
    PROXY_STM_EVENT_AES_KEY_RECEIVE,
    PROXY_STM_EVENT_AES_NEGOTIATING_FAIL,
    PROXY_STM_EVENT_AUTHENTICATING_OK,
    PROXY_STM_EVENT_AUTHENTICATING_FAIL,
    PROXY_STM_EVENT_TRANSMISSION_OK,
    PROXY_STM_EVENT_TRANSMISSION_FAIL

};

class ProxyStmTranslation {
public:
    ProxyStmState from;
    ProxyStmEvent event;
    ProxyStmState to;
};

class ProxyStmFlowArgs {

public:
    ProxySocket *fd;
    ProxyServer *server;

};

class ProxyStm {

public:
    static void *startup(void *);
    virtual ~ProxyStm() =delete;

private:
    static void _encryption_flow_startup(std::shared_ptr<ProxySocket>, ProxyServer *);
    static void _encryption_flow_rsa_negotiate(std::shared_ptr<ProxyTunnel> &);
    static void _encryption_flow_aes_negotiate(std::shared_ptr<ProxyTunnel> &);
    static void _encryption_flow_authenticate(std::shared_ptr<ProxyTunnel> &);
    static void _encryption_flow_transmit(std::shared_ptr<ProxyTunnel> &);

    static void _transmission_flow_startup(std::shared_ptr<ProxySocket>, ProxyServer *);

    static void _decryption_flow_startup(std::shared_ptr<ProxySocket>, ProxyServer *);
    static void _decryption_flow_rsa_negotiate(std::shared_ptr<ProxyTunnel> &);
    static void _decryption_flow_aes_negotiate(std::shared_ptr<ProxyTunnel> &);
    static void _decryption_flow_authenticate(std::shared_ptr<ProxyTunnel> &);
    static void _decryption_flow_transmit(std::shared_ptr<ProxyTunnel> &);

};

class ProxyStmHelper {
public:
    static std::string state2string(ProxyStmState);
    static std::string event2string(ProxyStmEvent);
    static bool switch_state(std::shared_ptr<ProxyTunnel> &, ProxyStmEvent);
    virtual ~ProxyStmHelper() =delete;
    static const ProxyStmTranslation stm_table[];
    static const std::unordered_map<ProxyStmState, std::string> ProxyStmStateString;
    static const std::unordered_map<ProxyStmEvent, std::string> ProxyStmEventString;
};

}
}

namespace std {

template <>
struct hash<typename proxy::core::ProxyStmState> {
    size_t operator()(const proxy::core::ProxyStmState &s) const {
        return hash<int>()(static_cast<int>(s));
    }
};

template <>
struct hash<typename proxy::core::ProxyStmEvent> {
    size_t operator()(const proxy::core::ProxyStmEvent &e) const {
        return hash<int>()(static_cast<int>(e));
    }
};

}

#endif
