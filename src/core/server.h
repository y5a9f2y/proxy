#ifndef PROXY_CORE_SERVER_H_H_H
#define PROXY_CORE_SERVER_H_H_H

#include <memory>
#include <queue>
#include <vector>

#include "core/config.h"
#include "core/socket.h"

namespace proxy {
namespace core {

class ProxyTunnel;


class ProxyServerTunnelRule {

public:
    bool operator()(const std::weak_ptr<ProxyTunnel> &, const std::weak_ptr<ProxyTunnel> &);

};


class ProxyServer {

public:

    ProxyServer(const ProxyConfig &config) : _config(config) {}

    bool setup();
    bool teardown();
    void run();

    const ProxyConfig &config() const {
        return _config;
    }

    bool no_tunnels() const {
        return _tunnels.empty();
    }

    void add_tunnel(const std::shared_ptr<ProxyTunnel> &u) {
        _tunnels.push(u);
    }

    void remove_tunnel() {
        _tunnels.pop();
    }

    std::shared_ptr<ProxyTunnel> get_least_recent_used_tunnel() {
        return _tunnels.top().lock();
    }

private:

    bool _daemonize();
    bool _setup_coroutine_framework();
    bool _teardown_coroutine_framework();
    bool _setup_listen_socket();
    void _run_loop();

    ProxyConfig _config;
    std::shared_ptr<ProxySocket> _listen_socket;
    std::priority_queue<std::weak_ptr<ProxyTunnel>,
        std::vector<std::weak_ptr<ProxyTunnel>>, ProxyServerTunnelRule> _tunnels;

};

}
}

#endif
