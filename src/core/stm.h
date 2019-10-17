#ifndef PROXY_CORE_STM_H_H_H
#define PROXY_CORE_STM_H_H_H

#include <memory>
#include <string>
#include <utility>

#include "config.h"
#include "socket.h"

namespace proxy {
namespace core {

class ProxyServer;

enum class ProxyStmState {

    PROXY_STM_ENCRYPTION_READY,
    
    PROXY_STM_TRANSMISSION_READY,

    PROXY_STM_DECRYPTION_READY

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
    static void *_startup_encryption_flow(std::shared_ptr<ProxySocket>, ProxyServer *);
    static void *_startup_transmission_flow(std::shared_ptr<ProxySocket>, ProxyServer *);
    static void *_startup_decryption_flow(std::shared_ptr<ProxySocket>, ProxyServer *);

};

class ProxyStmHelper {
public:
    static std::string state2string(ProxyStmState);
    virtual ~ProxyStmHelper() =delete;
};

}
}




#endif
