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

#include "core/server.h"
#include "core/stm.h"
#include "core/tunnel.h"

#include "glog/logging.h"

extern "C" {
#include "coroutine/coroutine.h"
}

namespace proxy {
namespace core {

bool ProxyServerTunnelRule::operator()(const std::weak_ptr<ProxyTunnel> &lhs,
        const std::weak_ptr<ProxyTunnel> &rhs) {

    std::shared_ptr<ProxyTunnel> l = lhs.lock();
    std::shared_ptr<ProxyTunnel> r = rhs.lock();

    if(!l) {
        return false;
    }

    if(!r) {
        return true;
    }

    return l->mtime() > r->mtime();

}

bool ProxyServer::setup() {

    if(!_daemonize()) {
        return false;
    }

    if(!_init_signals()) {
        return false;
    }

    if(!_setup_coroutine_framework()) {
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

void ProxyServer::_server_signal_handler(int signum) {

    switch(signum) {
        case SIGHUP:
        case SIGUSR1:
        case SIGUSR2:
            // TODO reload config here
            break;
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
            // TODO gracefully quit here
            break;
        default:
            break;
    }

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

    struct sigaction catch_action;
    catch_action.sa_handler = ProxyServer::_server_signal_handler;
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

}
}
