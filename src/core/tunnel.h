#ifndef PROXY_CORE_TUNNEL_H_H_H
#define PROXY_CORE_TUNNEL_H_H_H

#include <memory>

#include "socket.h"
#include "stm.h"

namespace proxy {
namespace core {

class ProxyServer;

class ProxyTunnel {

public:
    ProxyTunnel(ProxySocket *from, ProxySocket *to, ProxyServer *server, ProxyStmState state) :
        _from(std::make_shared<ProxySocket>(std::move(*from))),
        _to(std::make_shared<ProxySocket>(std::move(*to))),
        _server(server), _state(state) {
        
    }
    virtual ~ProxyTunnel() =default;

protected:
    std::shared_ptr<ProxySocket> _from;
    std::shared_ptr<ProxySocket> _to;
    ProxyServer *_server;
    ProxyStmState _state;

};

class ProxyTcpTunnel : public ProxyTunnel {

public:
    ProxyTcpTunnel(ProxySocket *from, ProxySocket *to, ProxyServer *server, ProxyStmState state) : 
        ProxyTunnel(from, to, server, state) {
        
    }

};

}
}


#endif
