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
    _used = true;
}

ProxySocket::ProxySocket(ProxySocket &&ps) : _fd(ps._fd), _host(ps._host),
    _port(ps._port), _used(true) {
    ps._fd = nullptr;
    ps._host = "";
    ps._port = 0;
    ps._used = false;
}

ProxySocket::~ProxySocket() {
    close();
}

void ProxySocket::close() {
    if(_used && _fd) {
        co_close(_fd);
        _used = false;
        _fd = nullptr;
    }
}

int ProxySocket::bind(const struct sockaddr *addr, socklen_t addrlen) {
    return co_bind(_fd, addr, addrlen);
}

void ProxySocket::connect() {

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
 
    addr.sin_family = AF_INET;
    addr.sin_port = htons(_port);
    if(!inet_aton(_host.c_str(), &addr.sin_addr)) {
        throw std::runtime_error("convert host of " + to_string() + " to struct in_addr error");
    }

    if(co_connect(_fd, reinterpret_cast<const struct sockaddr *>(&addr), addrlen) < 0) {
        throw std::runtime_error("connect " + to_string() + " error: " + strerror(errno));
    }

    addrlen = sizeof(addr);
    if(getsockname(co_socket_get_fd(_fd), reinterpret_cast<struct sockaddr *>(&addr),
        &addrlen) < 0) {
        throw std::runtime_error("get the socket name which connects to " + to_string()
            + " error: " + strerror(errno));
    }

    _host = inet_ntoa(addr.sin_addr);
    _port = ntohs(addr.sin_port);
    _used = true;

    return;

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

int ProxyTcpSocket::listen(int backlog) {
    return co_listen(_fd, backlog);
}

ProxyTcpSocket *ProxyTcpSocket::accept() {

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    co_socket_t *fd;

    if(!(fd = co_accept(_fd, reinterpret_cast<struct sockaddr *>(&addr), &addrlen))) {
        throw std::runtime_error(strerror(errno));
    }

    return new ProxyTcpSocket(fd, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

}

ssize_t ProxyTcpSocket::read_eq(size_t n, std::shared_ptr<ProxyBuffer> &pb) {

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

ssize_t ProxyTcpSocket::write_eq(size_t n, std::shared_ptr<ProxyBuffer> &pb) {

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

ssize_t ProxyTcpSocket::sendto(std::shared_ptr<ProxyBuffer> &pb, int flag,
    const struct sockaddr *addr, socklen_t addrlen) {

    if(pb->start == pb->cur) {
        return 0;
    }

    // when use the tcp, the addr/addrlen is ignored.
    ssize_t nwrite = co_sendto(_fd, pb->buffer + pb->start, pb->cur - pb->start, flag, NULL, 0);

    if(nwrite > 0) {
        pb->start += static_cast<size_t>(nwrite);
    }

    return nwrite;

}

ssize_t ProxyTcpSocket::recvfrom(std::shared_ptr<ProxyBuffer> &pb, int flag,
    struct sockaddr *addr, socklen_t *addrlen) {

    if(pb->cur == pb->size) {
        return 0;
    }
    
    // when use the tcp, the addr/addrlen is ignored
    ssize_t nread = co_recvfrom(_fd, pb->buffer + pb->cur, pb->size - pb->cur, flag, NULL, NULL);
    if(nread > 0) {
        pb->cur += static_cast<size_t>(nread);
    }
    return nread;

}

ssize_t ProxyUdpSocket::sendto(std::shared_ptr<ProxyBuffer> &pb, int flag,
    const struct sockaddr *addr, socklen_t addrlen) {

    if(pb->start == pb->cur) {
        return 0;
    }

    ssize_t nwrite = co_sendto(_fd, pb->buffer + pb->start, pb->cur - pb->start,
        flag, addr, addrlen);

    if(nwrite > 0) {
        pb->start += static_cast<size_t>(nwrite);
    }

    return nwrite;
}

ssize_t ProxyUdpSocket::recvfrom(std::shared_ptr<ProxyBuffer> &pb, int flag,
    struct sockaddr *addr, socklen_t *addrlen) {

    if(pb->cur == pb->size) {
        return 0;
    }
    
    ssize_t nread = co_recvfrom(_fd, pb->buffer + pb->cur, pb->size - pb->cur,
        flag, addr, addrlen);

    if(nread > 0) {
        pb->cur += static_cast<size_t>(nread);
    }
    return nread;
}

}

}
