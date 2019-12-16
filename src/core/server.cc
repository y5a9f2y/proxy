#include <arpa/inet.h>
#include <errno.h>
#include <exception>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdexcept>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <functional>
#include <vector>
#include <string>

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"

#include "core/server.h"
#include "core/stm.h"
#include "core/tunnel.h"

#include "glog/logging.h"

namespace proxy {
namespace core {

ProxyServer *ProxyServerSignalHandler::server = nullptr;

bool ProxyServer::setup() {

    if(!_daemonize()) {
        return false;
    }

    if(!_init_signals()) {
        return false;
    }

    if(!_create_pid_file()) {
        return false;
    }

    if(!_setup_coroutine_framework()) {
        return false;
    }

    if(!_setup_tunnel_gc_loop()) {
        return false;
    }

    if(!_setup_statistic_loop()) {
        return false;
    }

    return true;

}

bool ProxyServer::teardown() {

    if(!_teardown_coroutine_framework()) {
        return false;
    }

    return true;

}

void ProxyServer::run() {

    if(_config.mode() == ProxyServerType::Decryption) {
        _rsa_keypair = proxy::crypto::ProxyCryptoRsa::generate_key_pair();
        if(!_rsa_keypair) {
            LOG(ERROR) << "generate the rsa key pair error";
            return;
        }
    }

    if(!_setup_listen_socket()) {
        return;
    }

    _run_loop();

}

bool ProxyServer::_daemonize() {

    umask(0);

    pid_t pid;
    if((pid = fork()) < 0) {
        LOG(ERROR) << "fork the child process error: " << strerror(errno);
        return false;
    } else if(pid > 0) {
        _exit(0);
    }

    if(setsid() < 0) {
        LOG(ERROR) << "become the leader of the new session error: " << strerror(errno);
        return false;
    }

    if((pid = fork()) < 0) {
        LOG(ERROR) << "fork the child process of the session leader error: " << strerror(errno);
        return false;
    } else if(pid > 0) {
        _exit(0);
    }
    
    if(chdir("/") < 0) {
        LOG(ERROR) << "change the current work directory to / error: " << strerror(errno);
        return false;
    }

    int fd;
    int stdio[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
    if((fd = open("/dev/null", O_RDWR)) < 0) {
        LOG(ERROR) << "open /dev/null error: " << strerror(errno);
        return false;
    }
    for(size_t i = 0; i < sizeof(stdio)/sizeof(stdio[0]); ++i) {
        if(dup2(fd, stdio[i]) < 0) {
            LOG(ERROR) << "redirect fd " << stdio[i] << " to /dev/null error: " << strerror(errno);
            return false;
        }
    }

    return true;

}

bool ProxyServer::_create_pid_file() {

    boost::filesystem::path pidfile =
        boost::filesystem::path(config().log_dir()) / "proxy.pid";

    if(boost::filesystem::exists(pidfile) && !boost::filesystem::is_regular_file(pidfile)) {
        LOG(ERROR) << "the pid file " << pidfile.string() << " exists and is not a regular file";
        return false;
    }
    
    try {
        boost::filesystem::ofstream ofs(pidfile);
        ofs << getpid();
        ofs.close();
    } catch (const std::exception &ex) {
        LOG(ERROR) << "create the pid file " << pidfile.string() << " error: " << ex.what();
        return false;
    }

    return true;

}

bool ProxyServer::_init_signals() {

    std::vector<int> ignore_sigs = {
        SIGPIPE,
        SIGUSR1,
        SIGUSR2,
        SIGCHLD,
        SIGTSTP,
        SIGTTIN,
        SIGALRM,
        SIGTTOU
    };

    std::vector<int> catch_sigs = {
        SIGHUP,
        SIGINT,
        SIGQUIT,
        SIGTERM,
        SIGUSR1,
        SIGUSR2
    };

    struct sigaction ignore_action;
    ignore_action.sa_handler = SIG_IGN;

    for(int sig : ignore_sigs) {
        if(sigaction(sig, &ignore_action, NULL) < 0) {
            LOG(ERROR) << "ignore signal " << sig << " error: " << strerror(errno);
            return false;
        }
    }

    ProxyServerSignalHandler::server = this;

    struct sigaction catch_action;
    catch_action.sa_handler = ProxyServerSignalHandler::server_signal_handler;
    for(int sig : catch_sigs) {
        if(sigaction(sig, &catch_action, NULL) < 0) {
            LOG(ERROR) << "install signal handler of " << sig << " error: " << strerror(errno);
            return false;
        }
    }

    return true;

}

bool ProxyServer::_setup_coroutine_framework() {

    int err;
    if((err = co_framework_init())) {
        LOG(ERROR) << "setup the coroutine framework fail: " << strerror(err);
        return false;
    }
    return true;

}

bool ProxyServer::_teardown_coroutine_framework() {

    if(co_framework_destroy()) {
        LOG(ERROR) << "teardown the coroutine framework fail: " << strerror(errno);
        return false;
    }
    return true;

}

bool ProxyServer::_setup_listen_socket() {

    try {
        _listen_socket = std::make_shared<ProxyTcpSocket>(AF_INET, 0);
    } catch (const std::runtime_error &ex) {
        LOG(ERROR) << "setup the listen socket error: " << ex.what();
        return false;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(_config.local_port());
    if(!inet_aton(_config.local_host().c_str(), &addr.sin_addr)) {
        LOG(ERROR) << "invalid local_host: " << _config.local_host();
        return false;
    }

    if(_listen_socket->bind(reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) < 0) {
        LOG(ERROR) << "bind " << _config.local_host() << ":" << _config.local_port() << " error: "
            << strerror(errno);
        return false;
    }
    _listen_socket->host(_config.local_host());
    _listen_socket->port(_config.local_port());

    if(_listen_socket->listen(_config.listen_backlog()) < 0) {
        LOG(ERROR) << "listen " << _config.local_host() << ":" << _config.local_port() << "error: "
            << strerror(errno);
        return false;
    }

    return true;

}

void *ProxyServer::_tunnel_gc_loop(void *args) {

    ProxyServer *server = reinterpret_cast<ProxyServer *>(args);
    std::list<std::weak_ptr<ProxyTunnel>>::iterator p;
    std::list<std::weak_ptr<ProxyTunnel>>::iterator q;
    bool del;
    while(1) {
        p = server->_tunnels.begin();
        while(p != server->_tunnels.end()) {
            del = false;
            std::shared_ptr<ProxyTunnel> tunnel = (*p).lock();
            if(!tunnel) {
                del = true;
            } else {
                if(static_cast<size_t>(time(NULL) - tunnel->ktime()) >
                    server->_config.max_idle_time()) {
                    del = true;
                }
            }
            if(del) {
                q = p;
            }
            ++p;
            if(del) {
                if(tunnel) {
                    LOG(WARNING) << "[IDLE]close the idle tunnel "
                        << tunnel->ep0_ep1_string();
                    tunnel->close();
                }
                server->_tunnels.erase(q);
            }
        }
        co_usleep(static_cast<long long>(server->_config.statistic_interval()) * 1000000LL);
    }

    return nullptr;

}

bool ProxyServer::_setup_tunnel_gc_loop() {

    co_thread_t *c = nullptr;
    if(!(c = coroutine_create(ProxyServer::_tunnel_gc_loop, reinterpret_cast<void *>(this)))) {
        LOG(ERROR) << "create the tunnel gc coroutine error: " << strerror(errno);
        return false;
    }
    coroutine_setdetachstate(c, COROUTINE_FLAG_NONJOINABLE);
    return true;

}

void *ProxyServer::_statistic_loop(void *args) {

    ProxyServer *server = reinterpret_cast<ProxyServer *>(args);
    long double ep0_ep1_speed;
    long double ep1_ep0_speed;
    size_t ep0_ep1_speed_unit;
    size_t ep1_ep0_speed_unit;
    const std::vector<std::string> UNITS = {
        "B/s",
        "KB/s",
        "MB/s",
        "GB/s",
        "TB/s"
    };

    while(1) {
        if(server->_ts < 0) {
            if((server->_ts = co_get_current_time()) < 0) {
                LOG(ERROR) << "[STATS]init the server timestamp error";
            }
        } else {
            co_time_t now = co_get_current_time();
            if(now < 0) {
                LOG(ERROR) << "[STATS]update the server timestamp error";
            } else {

                ep0_ep1_speed = static_cast<long double>(server->_ep0_ep1_bytes) /
                    (static_cast<long double>(now - server->_ts) / 1.0e6);
                ep1_ep0_speed = static_cast<long double>(server->_ep1_ep0_bytes) /
                    (static_cast<long double>(now - server->_ts) / 1.0e6);
                ep0_ep1_speed_unit = 0;
                ep1_ep0_speed_unit = 0;

                for(size_t i = 0; i < UNITS.size(); ++i) {
                    if((i + 1 == UNITS.size()) || (ep0_ep1_speed-1024.0 < -1e-7)) {
                        ep0_ep1_speed_unit = i;
                        break;
                    }
                    ep0_ep1_speed = ep0_ep1_speed / 1024.0;
                }

                for(size_t i = 0; i < UNITS.size(); ++i) {
                    if((i + 1 == UNITS.size()) || (ep1_ep0_speed-1024.0 < -1e-7)) {
                        ep1_ep0_speed_unit = i;
                        break;
                    }
                    ep1_ep0_speed = ep1_ep0_speed / 1024.0;
                }

                LOG(INFO) << "[STATS]current speed [up:"
                    << ep0_ep1_speed << UNITS[ep0_ep1_speed_unit] << "][down:"
                    << ep1_ep0_speed << UNITS[ep1_ep0_speed_unit] << "]";

                server->_ts = now;
                server->_ep0_ep1_bytes = 0;
                server->_ep1_ep0_bytes = 0;
            }
        }
        co_usleep(static_cast<long long>(server->_config.statistic_interval()) * 1000000LL);
    }

    return nullptr;

}

bool ProxyServer::_setup_statistic_loop() {

    co_thread_t *c = nullptr;
    if(!(c = coroutine_create(ProxyServer::_statistic_loop, reinterpret_cast<void *>(this)))) {
        LOG(ERROR) << "create the statistic coroutine error: " << strerror(errno);
        return false;
    }
    coroutine_setdetachstate(c, COROUTINE_FLAG_NONJOINABLE);
    return true;

}

void ProxyServer::_run_loop() {

    while(true) {

        ProxySocket *fd;

        try {
            fd = _listen_socket->accept();  
        } catch (const std::exception &ex) {
            LOG(ERROR) << "accept a new connection error: " << ex.what();
            continue;
        }

        LOG(INFO) << "receive a connection from " << fd->to_string();

        ProxyStmFlowArgs *args = new ProxyStmFlowArgs{fd, this};

        co_thread_t *c = nullptr;
        if(!(c = coroutine_create(ProxyStm::startup, reinterpret_cast<void *>(args)))) {
            LOG(ERROR) << "create a new coroutine for " << args->fd->to_string() << " error: "
                << strerror(errno);
            continue;
        }

        coroutine_setdetachstate(c, COROUTINE_FLAG_NONJOINABLE);

    }

}

void ProxyServerSignalHandler::server_signal_handler(int signum) {

    switch(signum) {
        case SIGHUP:
            ProxyServerSignalHandler::server->config().reload();
            break;
        case SIGUSR1:
        case SIGUSR2:
            LOG(INFO) << ProxyServerSignalHandler::server->config().to_string();
            break;
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
            LOG(INFO) << "receiving signal " << signum << ", the server is going to stop";
            _exit(signum);
        default:
            break;
    }

}

}
}
