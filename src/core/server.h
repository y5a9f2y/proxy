#ifndef PROXY_CORE_SERVER_H_H_H
#define PROXY_CORE_SERVER_H_H_H

#include <memory>
#include <queue>
#include <vector>

#include "core/config.h"
#include "core/socket.h"
#include "crypto/rsa.h"

extern "C" {
#include "coroutine/coroutine.h"
}

namespace proxy {
namespace core {

class ProxyTunnel;


class ProxyServerTunnelRule {

public:
    bool operator()(const std::weak_ptr<ProxyTunnel> &, const std::weak_ptr<ProxyTunnel> &);

};


class ProxyServer {

public:

    ProxyServer(const ProxyConfig &config) : _config(config),
        _ts(co_get_current_time()), _ep0_ep1_bytes(0), _ep1_ep0_bytes(0) {}

    bool setup();
    bool teardown();
    void run();

    const ProxyConfig &config() const {
        return _config;
    }

    std::shared_ptr<proxy::crypto::ProxyCryptoRsaKeypair> rsa_keypair() {
        return _rsa_keypair;
    }

    const std::shared_ptr<proxy::crypto::ProxyCryptoRsaKeypair> rsa_keypair() const {
        return _rsa_keypair;
    }

    void add_tunnel(const std::shared_ptr<ProxyTunnel> &u) {
        _tunnels.push(u);
    }

    void add_ep0_ep1_data_amount(int64_t amount) {
        _ep0_ep1_bytes += amount;
    }

    void add_ep1_ep0_data_amount(int64_t amount) {
        _ep1_ep0_bytes += amount;
    }


private:

    bool _daemonize();
    bool _setup_coroutine_framework();
    bool _teardown_coroutine_framework();
    bool _setup_listen_socket();
    bool _setup_tunnel_gc_loop();
    bool _setup_statistic_loop();
    bool _init_signals();
    void _run_loop();

    bool _no_tunnels() const {
        return _tunnels.empty();
    }

    void _remove_tunnel() {
        _tunnels.pop();
    }

    std::shared_ptr<ProxyTunnel> _get_least_recent_used_tunnel() {
        return _tunnels.top().lock();
    }

    ProxyConfig _config;
    co_time_t _ts;
    int64_t _ep0_ep1_bytes;
    int64_t _ep1_ep0_bytes;
    std::shared_ptr<ProxySocket> _listen_socket;
    std::priority_queue<std::weak_ptr<ProxyTunnel>,
        std::vector<std::weak_ptr<ProxyTunnel>>, ProxyServerTunnelRule> _tunnels;
    std::shared_ptr<proxy::crypto::ProxyCryptoRsaKeypair> _rsa_keypair;

    static void _server_signal_handler(int);
    static void *_tunnel_gc_loop(void *);
    static void *_statistic_loop(void *);

};

}
}

#endif
