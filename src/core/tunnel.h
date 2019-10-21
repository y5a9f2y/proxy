#ifndef PROXY_CORE_TUNNEL_H_H_H
#define PROXY_CORE_TUNNEL_H_H_H

#include <memory>
#include <utility>
#include <deque>

#include <stdlib.h>
#include <time.h>

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

    bool buffer_empty() const {
        return _buffer.empty();
    }

    std::shared_ptr<ProxyBuffer> buffer_back() {
        return _buffer.back();
    }

    std::shared_ptr<ProxyBuffer> buffer_front() {
        return _buffer.front();
    }

    void add_buffer(const std::shared_ptr<ProxyBuffer> &buffer) {
        _buffer.push_back(buffer);
    }

    void add_buffer(std::shared_ptr<ProxyBuffer> &&buffer) {
        _buffer.push_back(std::move(buffer));
    }

    void remove_buffer() {
        _buffer.pop_front();
    }

    ProxyStmState state() const {
        return _state;
    }

    void state(ProxyStmState s) {
        _state = s;
    }



protected:
    std::shared_ptr<ProxySocket> _from;
    std::shared_ptr<ProxySocket> _to;
    ProxyServer *_server;
    ProxyStmState _state;
    time_t _mtime;
    std::deque<std::shared_ptr<ProxyBuffer>> _buffer;

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
