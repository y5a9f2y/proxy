#include <exception>
#include <stdexcept>

#include "core/socket.h"

namespace proxy {
namespace core {

ProxySocket::ProxySocket(int domain, int type, int protocol) :
    _fd(co_socket(domain, type, protocol)){
    if(!_fd) {
        throw std::runtime_error("create the non-blocking socket error");
    }
}

ProxySocket::ProxySocket(ProxySocket &&ps) : _fd(ps._fd), _host(ps._host), _port(ps._port) {
    ps._fd = nullptr;
    ps._host = "";
    ps._port = 0;
}

ProxySocket::~ProxySocket() {
    if(_fd) {
        co_close(_fd);
    }
}

int ProxySocket::bind(const struct sockaddr *addr, socklen_t addrlen) {
    return co_bind(_fd, addr, addrlen);
}

int ProxySocket::listen(int backlog) {
    return co_listen(_fd, backlog);
}

ProxySocket *ProxySocket::accept() {

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    co_socket_t *fd;

    if(!(fd = co_accept(_fd, reinterpret_cast<struct sockaddr *>(&addr), &addrlen))) {
        throw std::runtime_error(strerror(errno));
    }

    return new ProxySocket(fd, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

}

}
}
