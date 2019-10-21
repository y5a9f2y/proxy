#ifndef PROXY_CORE_STM_H_H_H
#define PROXY_CORE_STM_H_H_H

#include <memory>
#include <string>
#include <utility>

#include "core/config.h"
#include "core/socket.h"

namespace proxy {
namespace core {

class ProxyServer;
class ProxyTunnel;

enum class ProxyStmState {

    PROXY_STM_ENCRYPTION_READY,
    PROXY_STM_ENCRYPTION_ESTABLISHING,
    PROXY_STM_ENCRYPTION_NEGOTIATING,
    PROXY_STM_ENCRYPTION_ERROR,

    PROXY_STM_TRANSMISSION_READY,
    PROXY_STM_DECRYPTION_READY

};

enum class ProxyStmEvent {
    PROXY_STM_EVENT_ESTABLISH,
    PROXY_STM_EVENT_ESTABLISH_OK,
    PROXY_STM_EVENT_ESTABLISH_FAIL
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
    static void *_encryption_flow_startup(std::shared_ptr<ProxySocket>, ProxyServer *);
    static void _encryption_flow_establish(std::shared_ptr<ProxyTunnel> &);

    static void *_transmission_flow_startup(std::shared_ptr<ProxySocket>, ProxyServer *);
    static void *_decryption_flow_startup(std::shared_ptr<ProxySocket>, ProxyServer *);

};

class ProxyStmHelper {
public:
    static std::string state2string(ProxyStmState);
    static std::string event2string(ProxyStmEvent);
    static bool switch_state(std::shared_ptr<ProxyTunnel> &, ProxyStmEvent);
    virtual ~ProxyStmHelper() =delete;
    static const ProxyStmTranslation stm_table[];
};

}
}




#endif
