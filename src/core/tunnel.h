#ifndef PROXY_CORE_TUNNEL_H_H_H
#define PROXY_CORE_TUNNEL_H_H_H

#include <memory>
#include <utility>
#include <deque>

#include <stdlib.h>
#include <time.h>
#include <sys/types.h>

#include "core/buffer.h"
#include "core/socket.h"
#include "core/stm.h"

namespace proxy {
namespace core {

class ProxyServer;


class ProxyTunnel {

public:

    ProxyTunnel(ProxySocket *from, ProxySocket *to, ProxyServer *server, ProxyStmState state) :
        _from(from), _to(to), _server(server), _state(state), _mtime(time(NULL)) {}

    ProxyTunnel(const std::shared_ptr<ProxySocket> &from, const std::shared_ptr<ProxySocket> &to,
        ProxyServer *server, ProxyStmState state): _from(from), _to(to), _server(server),
        _state(state), _mtime(time(NULL)) {}
            
    ProxyTunnel(std::shared_ptr<ProxySocket> &&from, std::shared_ptr<ProxySocket> &&to,
        ProxyServer *server, ProxyStmState state) : _from(std::move(from)), _to(std::move(to)),
        _server(server), _state(state), _mtime(time(NULL)) {}

    virtual ~ProxyTunnel() =default;

    time_t mtime() const {
        return _mtime;
    }

    ProxyStmState state() const {
        return _state;
    }

    void state(ProxyStmState s) {
        _state = s;
    }

    const std::shared_ptr<ProxySocket> &from() const {
        return _from;
    }

    const std::shared_ptr<ProxySocket> &to() const {
        return _to;
    }

    const ProxyServer *server() const {
        return _server;
    }

    ssize_t read_from_eq(size_t, std::shared_ptr<ProxyBuffer> &);


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
        ProxyTunnel(from, to, server, state) {}

    ProxyTcpTunnel(const std::shared_ptr<ProxySocket> &from,
        const std::shared_ptr<ProxySocket> &to, ProxyServer *server, ProxyStmState state) :
        ProxyTunnel(from, to, server, state) {}

    ProxyTcpTunnel(std::shared_ptr<ProxySocket> &&from, std::shared_ptr<ProxySocket> &&to,
        ProxyServer *server, ProxyStmState state) : ProxyTunnel(from, to, server, state) {}

};

}
}


#endif
