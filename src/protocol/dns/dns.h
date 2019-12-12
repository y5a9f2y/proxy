#ifndef PROXY_PROTOCOL_DNS_DNS_H_H_H
#define PROXY_PROTOCOL_DNS_DNS_H_H_H

#include <memory>
#include <string>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <resolv.h>

namespace proxy {
namespace protocol {
namespace dns {

class ProxyProtoDnsUnblockResolver {

public:
    using res_state_t = struct __res_state;

public:
    ProxyProtoDnsUnblockResolver() : _rs(nullptr) {}
    bool resolv(const std::string &, std::string &);
    ~ProxyProtoDnsUnblockResolver();

private:
    std::shared_ptr<res_state_t> _rs;
    bool _setup();

};

}
}
}




#endif
