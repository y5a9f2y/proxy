#ifndef PROXY_CORE_TUNNEL_H_H_H
#define PROXY_CORE_TUNNEL_H_H_H

#include <memory>
#include <string>
#include <sstream>
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

    ProxyTunnel(ProxySocket *ep0, ProxySocket *ep1, ProxyServer *server, ProxyStmState state) :
        _ep0(ep0), _ep1(ep1), _server(server), _state(state), _mtime(time(NULL)) {}

    ProxyTunnel(const std::shared_ptr<ProxySocket> &ep0, const std::shared_ptr<ProxySocket> &ep1,
        ProxyServer *server, ProxyStmState state): _ep0(ep0), _ep1(ep1), _server(server),
        _state(state), _mtime(time(NULL)) {}
            
    ProxyTunnel(std::shared_ptr<ProxySocket> &&ep0, std::shared_ptr<ProxySocket> &&ep1,
        ProxyServer *server, ProxyStmState state) : _ep0(std::move(ep0)), _ep1(std::move(ep1)),
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

    const std::shared_ptr<ProxySocket> &ep0() const {
        return _ep0;
    }

    const std::shared_ptr<ProxySocket> &ep1() const {
        return _ep1;
    }

    std::shared_ptr<ProxySocket> ep0() {
        return _ep0;
    }

    std::shared_ptr<ProxySocket> ep1() {
        return _ep1;
    }

    void ep0(const std::shared_ptr<ProxySocket> &ep) {
        _ep0 = ep;
    }

    void ep1(const std::shared_ptr<ProxySocket> &ep) {
        _ep1 = ep;
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

    const std::string &aes_iv_peer() const {
        return _aes_iv_peer;
    }

    void aes_iv_peer(const std::string &iv) {
        _aes_iv_peer = iv;
    }

    void aes_iv_peer(std::string &&iv) {
        _aes_iv_peer = std::move(iv);
    }

    const std::string &aes_key_peer() const {
        return _aes_key_peer;
    }

    void aes_key_peer(const std::string &key) {
        _aes_key_peer = key;
    }

    void aes_key_peer(std::string &&key) {
        _aes_key_peer = std::move(key);
    }

    std::string ep0_ep1_string() const {
        if(!_ep1) {
            return _ep0->to_string();
        }
        return _ep0->to_string() + "->" + _ep1->to_string();
    }

    std::string ep1_ep0_string() const {
        if(!_ep0) {
            return _ep1->to_string();
        }
        return _ep1->to_string() + "->" + _ep0->to_string();
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

    bool aes_ctx_peer_setup(proxy::crypto::ProxyCryptoAesContextType ty) {
        _aes_ctx_peer = std::make_shared<proxy::crypto::ProxyCryptoAesContext>();
        return _aes_ctx_peer->setup(ty, _aes_key_peer, _aes_iv_peer);
    }

    std::shared_ptr<proxy::crypto::ProxyCryptoAesContext> &aes_ctx_peer() {
        return _aes_ctx_peer;
    }

    const std::shared_ptr<proxy::crypto::ProxyCryptoAesContext> &aes_ctx_peer() const {
        return _aes_ctx_peer;
    }

    ssize_t read_ep0_eq(size_t, std::shared_ptr<ProxyBuffer> &);
    ssize_t write_ep0_eq(size_t, std::shared_ptr<ProxyBuffer> &);
    ssize_t read_ep1_eq(size_t, std::shared_ptr<ProxyBuffer> &);
    ssize_t write_ep1_eq(size_t, std::shared_ptr<ProxyBuffer> &);

    bool read_decrypted_byte_from_ep0(unsigned char &);
    bool read_decrypted_byte_from_ep1(unsigned char &);
    bool read_decrypted_4bytes_from_ep0(uint32_t &);
    bool read_decrypted_4bytes_from_ep1(uint32_t &);
    bool read_decrypted_string_from_ep0(size_t, std::string &);
    bool read_decrypted_string_from_ep1(size_t, std::string &);

protected:

    std::shared_ptr<ProxySocket> _ep0;
    std::shared_ptr<ProxySocket> _ep1;
    ProxyServer *_server;
    ProxyStmState _state;
    time_t _mtime;

    std::string _rsa_key;

    std::string _aes_iv;
    std::string _aes_key;
    std::shared_ptr<proxy::crypto::ProxyCryptoAesContext> _aes_ctx;

    std::string _aes_iv_peer;
    std::string _aes_key_peer;
    std::shared_ptr<proxy::crypto::ProxyCryptoAesContext> _aes_ctx_peer;

    bool _read_decrypted_byte(unsigned char &, bool);
    bool _read_decrypted_4bytes(uint32_t &, bool);
    bool _read_decrypted_string(size_t, std::string &, bool);

};


class ProxyTcpTunnel : public ProxyTunnel {

public:

    ProxyTcpTunnel(ProxySocket *ep0, ProxySocket *ep1, ProxyServer *server, ProxyStmState state) : 
        ProxyTunnel(ep0, ep1, server, state) {}

    ProxyTcpTunnel(const std::shared_ptr<ProxySocket> &ep0,
        const std::shared_ptr<ProxySocket> &ep1, ProxyServer *server, ProxyStmState state) :
        ProxyTunnel(ep0, ep1, server, state) {}

    ProxyTcpTunnel(std::shared_ptr<ProxySocket> &&ep0, std::shared_ptr<ProxySocket> &&ep1,
        ProxyServer *server, ProxyStmState state) :
        ProxyTunnel(std::move(ep0), std::move(ep1), server, state) {}

};

}
}


#endif
