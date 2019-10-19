#ifndef PROXY_CORE_TUNNEL_H_H_H
#define PROXY_CORE_TUNNEL_H_H_H

#include <memory>

#include <stdlib.h>
#include <time.h>

#include "core/socket.h"
#include "core/stm.h"

namespace proxy {
namespace core {

class ProxyServer;

class ProxyTunnel {

public:
    ProxyTunnel(ProxySocket *from, ProxySocket *to, ProxyServer *server, ProxyStmState state) :
        _from(std::make_shared<ProxySocket>(std::move(*from))),
        _to(std::make_shared<ProxySocket>(std::move(*to))),
        _server(server), _state(state), _mtime(time(NULL)) {
        
    }
    virtual ~ProxyTunnel() =default;

    time_t mtime() const {
        return _mtime;
    }

protected:
    std::shared_ptr<ProxySocket> _from;
    std::shared_ptr<ProxySocket> _to;
    ProxyServer *_server;
    ProxyStmState _state;
    time_t _mtime;

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
