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

void ProxySocket::connect() {

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
 
    addr.sin_family = AF_INET;
    addr.sin_port = htons(_port);
    if(!inet_aton(_host.c_str(), &addr.sin_addr)) {
        throw std::runtime_error("convert host of " + to_string() + "to struct in_addr error");
    }

    if(co_connect(_fd, reinterpret_cast<const struct sockaddr *>(&addr), addrlen) < 0) {
        throw std::runtime_error("connect" + to_string() + "error" + strerror(errno));
    }

    return;

}

ssize_t ProxySocket::read_eq(size_t n, std::shared_ptr<ProxyBuffer> &pb) {

    size_t nbytes = n;

    while(n) {
        ssize_t nread = co_read(_fd, pb->buffer + pb->cur, n);
        if(nread < 0) {
            return -1;
        } else if (nread == 0) {
            return nbytes - n;
        }
        pb->cur += nread;
        n -= nread;
    }

    return nbytes;

}

ssize_t ProxySocket::read(std::shared_ptr<ProxyBuffer> &pb) {

    if(pb->cur == pb->size) {
        return 0;
    }
    ssize_t nread = co_read(_fd, pb->buffer + pb->cur, pb->size - pb->cur);
    if(nread > 0) {
        pb->cur += static_cast<size_t>(nread);
    }
    return nread;

}

ssize_t ProxySocket::write_eq(size_t n, std::shared_ptr<ProxyBuffer> &pb) {

    size_t nbytes = n;

    while(n) {
        ssize_t nwrite = co_write(_fd, pb->buffer + pb->start, n);
        if(nwrite < 0) {
            return -1;
        }
        pb->start += nwrite;
        n -= nwrite;
    }

    return nbytes;

}

ssize_t ProxySocket::write(std::shared_ptr<ProxyBuffer> &pb) {

    if(pb->start == pb->cur) {
        return 0;
    }
    ssize_t nwrite = co_write(_fd, pb->buffer + pb->start, pb->cur - pb->start);
    if(nwrite > 0) {
        pb->start += static_cast<size_t>(nwrite);
    }
    return nwrite;

}

}

}
