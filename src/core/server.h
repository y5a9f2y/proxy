#ifndef PROXY_CORE_SERVER_H_H_H
#define PROXY_CORE_SERVER_H_H_H

#include <memory>
#include <vector>

#include "config.h"
#include "socket.h"

namespace proxy {
namespace core {

class ProxyTunnel;

class ProxyServer {

public:

    ProxyServer(const ProxyConfig &config) : _config(config) {}

    bool setup();
    bool teardown();
    void run();

    const ProxyConfig &config() const {
        return _config;
    }

private:

    bool _daemonize();
    bool _setup_coroutine_framework();
    bool _teardown_coroutine_framework();
    bool _setup_listen_socket();
    void _run_loop();

    ProxyConfig _config;
    std::shared_ptr<ProxySocket> _listen_socket;
    std::vector<std::shared_ptr<ProxyTunnel>> _tunnels;

};

}
}

#endif
