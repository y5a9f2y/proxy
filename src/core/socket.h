#ifndef PROXY_CORE_SOCKET_H_H_H
#define PROXY_CORE_SOCKET_H_H_H

#include <memory>
#include <sstream>
#include <string>

#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern "C" {
#include "coroutine/coroutine.h"
}

#include "core/buffer.h"

namespace proxy {
namespace core {

class ProxySocket {

public:
    ProxySocket() : _fd(nullptr), _port(0) {}
    ProxySocket(int, int, int);
    ProxySocket(co_socket_t *fd, std::string host, uint16_t port) :
        _fd(fd), _host(host), _port(port) {}
    ProxySocket(const ProxySocket &) = delete;
    ProxySocket(ProxySocket &&);
    ~ProxySocket();

    void host(const std::string &h) {
        _host = h;
    }

    void port(uint16_t p) {
        _port = p;
    }

    std::string host() const {
        return _host;
    }

    uint16_t port() const {
        return _port;
    }

    std::string to_string() const {
        std::ostringstream oss;
        oss << _host << ":" << _port;
        return oss.str();
    }

    int bind(const struct sockaddr *, socklen_t);
    int listen(int);
    ProxySocket *accept();
    void connect();

    ssize_t read_eq(size_t, std::shared_ptr<ProxyBuffer> &);
    ssize_t write_eq(size_t, std::shared_ptr<ProxyBuffer> &);

private:
    co_socket_t *_fd;
    std::string _host;
    uint16_t _port;

};

}
}


#endif
