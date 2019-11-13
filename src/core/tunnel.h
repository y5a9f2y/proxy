#ifndef PROXY_CORE_TUNNEL_H_H_H
#define PROXY_CORE_TUNNEL_H_H_H

#include <memory>
#include <string>
#include <utility>
#include <deque>

#include <stdlib.h>
#include <time.h>
#include <sys/types.h>

#include "core/buffer.h"
#include "core/socket.h"
#include "core/stm.h"
#include "crypto/aes.h"

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

    std::shared_ptr<ProxySocket> from() {
        return _from;
    }

    std::shared_ptr<ProxySocket> to() {
        return _to;
    }

    void from(const std::shared_ptr<ProxySocket> &f) {
        _from = f;
    }

    void to(const std::shared_ptr<ProxySocket> &t) {
        _to = t;
    }

    const ProxyServer *server() const {
        return _server;
    }

    ProxyServer *server() {
        return _server;
    }

    const std::string &rsa_key() const {
        return _rsa_key;
    }

    void rsa_key(const std::string &key) {
        _rsa_key = key;
    }

    void rsa_key(std::string &&key) {
        _rsa_key = std::move(key);
    }

    const std::string &aes_iv() const {
        return _aes_iv;
    }

    void aes_iv(const std::string &iv) {
        _aes_iv = iv;
    }

    void aes_iv(std::string &&iv) {
        _aes_iv = std::move(iv);
    }

    const std::string &aes_key() const {
        return _aes_key;
    }

    void aes_key(const std::string &key) {
        _aes_key = key;
    }

    void aes_key(std::string &&key) {
        _aes_key = std::move(key);
    }

    std::string to_string() const {
        return _from->to_string() + "->" + _to->to_string();
    }

    std::string to_reverse_string() const {
        return _to->to_string() + "->" + _from->to_string();
    }

    bool aes_ctx_setup(proxy::crypto::ProxyCryptoAesContextType ty) {
        _aes_ctx = std::make_shared<proxy::crypto::ProxyCryptoAesContext>();
        return _aes_ctx->setup(ty, _aes_key, _aes_iv);
    }

    std::shared_ptr<proxy::crypto::ProxyCryptoAesContext> &aes_ctx() {
        return _aes_ctx;
    }

    const std::shared_ptr<proxy::crypto::ProxyCryptoAesContext> &aes_ctx() const {
        return _aes_ctx;
    }

    ssize_t read_from_eq(size_t, std::shared_ptr<ProxyBuffer> &);
    ssize_t write_from_eq(size_t, std::shared_ptr<ProxyBuffer> &);
    ssize_t read_to_eq(size_t, std::shared_ptr<ProxyBuffer> &);
    ssize_t write_to_eq(size_t, std::shared_ptr<ProxyBuffer> &);

    bool read_decrypted_byte_from(unsigned char &);
    bool read_decrypted_byte_to(unsigned char &);
    bool read_decrypted_4bytes_from(uint32_t &);
    bool read_decrypted_4bytes_to(uint32_t &);
    bool read_decrypted_string_from(size_t, std::string &);
    bool read_decrypted_string_to(size_t, std::string &);

protected:
    std::shared_ptr<ProxySocket> _from;
    std::shared_ptr<ProxySocket> _to;
    ProxyServer *_server;
    ProxyStmState _state;
    time_t _mtime;
    std::string _rsa_key;
    std::string _aes_iv;
    std::string _aes_key;
    std::shared_ptr<proxy::crypto::ProxyCryptoAesContext> _aes_ctx;

    bool _read_decrypted_byte(unsigned char &, bool);
    bool _read_decrypted_4bytes(uint32_t &, bool);
    bool _read_decrypted_string(size_t, std::string &, bool);

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
