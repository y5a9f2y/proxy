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
    virtual ~ProxySocket();

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
    void connect();
    ssize_t read(std::shared_ptr<ProxyBuffer> &);
    ssize_t write(std::shared_ptr<ProxyBuffer> &);

    virtual std::string type() const =0;
    virtual int listen(int) =0;
    virtual ProxySocket *accept() =0;
    virtual ssize_t read_eq(size_t, std::shared_ptr<ProxyBuffer> &) =0;
    virtual ssize_t write_eq(size_t, std::shared_ptr<ProxyBuffer> &) =0;
    virtual ssize_t sendto(std::shared_ptr<ProxyBuffer> &, int,
        const struct sockaddr *, socklen_t) =0;
    virtual ssize_t recvfrom(std::shared_ptr<ProxyBuffer> &, int,
        struct sockaddr *, socklen_t *) =0;

protected:
    co_socket_t *_fd;
    std::string _host;
    uint16_t _port;

};


class ProxyTcpSocket : public ProxySocket {

public:
    ProxyTcpSocket() : ProxySocket() {}
    ProxyTcpSocket(int domain, int protocol) : ProxySocket(domain, SOCK_STREAM, protocol) {}
    ProxyTcpSocket(co_socket_t *fd, std::string host,
        uint16_t port) : ProxySocket(fd, host, port) {}
    ProxyTcpSocket(ProxyTcpSocket &&fd) : ProxySocket(std::move(fd)) {}

    virtual std::string type() const override{
        return "tcp";
    }

    virtual int listen(int) override;
    virtual ProxyTcpSocket *accept() override;
    virtual ssize_t read_eq(size_t, std::shared_ptr<ProxyBuffer> &) override;
    virtual ssize_t write_eq(size_t, std::shared_ptr<ProxyBuffer> &) override;
    virtual ssize_t sendto(std::shared_ptr<ProxyBuffer> &, int,
        const struct sockaddr *, socklen_t) override;
    virtual ssize_t recvfrom(std::shared_ptr<ProxyBuffer> &, int,
        struct sockaddr *, socklen_t *) override;

};


class ProxyUdpSocket : public ProxySocket {

public:
    ProxyUdpSocket() : ProxySocket() {}
    ProxyUdpSocket(int domain, int protocol) : ProxySocket(domain, SOCK_DGRAM, protocol) {}
    ProxyUdpSocket(co_socket_t *fd, std::string host,
        uint16_t port) : ProxySocket(fd, host, port) {}
    ProxyUdpSocket(ProxyUdpSocket &&fd) : ProxyUdpSocket(std::move(fd)) {}

    virtual std::string type() const override{
        return "udp";
    }

    virtual int listen(int) override{
        return -1;
    }

    virtual ProxyUdpSocket *accept() override{
        return nullptr;
    }

    virtual ssize_t read_eq(size_t, std::shared_ptr<ProxyBuffer> &) override {
        return -1;
    }

    virtual ssize_t write_eq(size_t, std::shared_ptr<ProxyBuffer> &) override {
        return -1;
    };

    virtual ssize_t sendto(std::shared_ptr<ProxyBuffer> &, int,
        const struct sockaddr *, socklen_t) override;

    virtual ssize_t recvfrom(std::shared_ptr<ProxyBuffer> &, int,
        struct sockaddr *, socklen_t *) override;

};

}
}


#endif
