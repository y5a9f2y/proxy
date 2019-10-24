#include "protocol/socks5/socks5.h"

#include "glog/logging.h"

using proxy::core::ProxyStmEvent;
using proxy::core::ProxyTunnel;
using proxy::core::ProxyBuffer;

namespace proxy {
namespace protocol {
namespace socks5 {

const char ProxyProtoSocks5::VERSION = 0x05;

//ProxyStmEvent ProxyProtoSocks5::on_establish(std::shared_ptr<ProxyTunnel> &tunnel) {
//
//    std::shared_ptr<ProxyBuffer> buf;
//   
//    try {
//        buf = std::make_shared<ProxyBuffer>(1024);
//    } catch (const std::exception &ex) {
//        LOG(WARNING) << "get write buffer when on_establish failed: " << ex.what()
//            << "the connection is from " << tunnel->from()->to_string();
//        return ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_FAIL;
//    }
//
//    /****************************************************
//    **          +----+----------+----------+
//    **          |VER | NMETHODS | METHODS  |
//    **          +----+----------+----------+
//    **          | 1  |    1     | 1 to 255 |
//    **          +----+----------+----------+
//    ****************************************************/
//
//    if(2 != tunnel->read_from_eq(2, buf)) {
//        LOG(WARNING) << "get the VER and NMETHODS from " << tunnel->from()->to_string()
//            << " error";
//        return ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_FAIL;
//    }
//
//    // check the protocol version
//    char *verp = buf->get_charp_at(0);
//    if(!verp) {
//        LOG(WARNING) << "get the VER pointer error, the connection is from "
//            << tunnel->from()->to_string();
//        return ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_FAIL;
//    }
//
//    if(*verp != ProxyProtoSocks5::VERSION)  {
//        LOG(WARNING) << "the request from " << tunnel->from()->to_string()
//            << "require socks version " << *verp << ", unsupported";
//        return ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_FAIL;
//    }
//
//    char *nmethodsp = buf->get_charp_at(1);
//    if(!nmethodsp) {
//        LOG(WARNING) << "get the NMETHODS pointer error, the connection is from "
//            << tunnel->from()->to_string();
//        return ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_FAIL;
//    }
//    ssize_t nmethods = static_cast<size_t>(*nmethodsp);
//    if(nmethods != tunnel->read_from_eq(nmethods, buf)) {
//        LOG(WARNING) << "get the METHODS from " << tunnel->from()->to_string() << " error";
//        return ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_FAIL;
//    }
//
//    /****************************************************
//    **                    Methods
//    **      X'00' NO AUTHENTICATION REQUIRED
//    **      X'01' GSSAPI
//    **      X'02' USERNAME/PASSWORD
//    **      X'03' to X'7F' IANA ASSIGNED
//    **      X'80' to X'FE' RESERVED FOR PRIVATE METHODS
//    **      X'FF' NO ACCEPTABLE METHODS
//    ****************************************************/
//
//    bool noauth_on = false;
//    for(size_t i = 0; i < static_cast<size_t>(nmethods); ++i) {
//        char *methodp = buf->get_charp_at(2+i);
//        switch(*methodp) {
//            case 0x00:
//                noauth_on = true;
//                break;
//            default:
//                break;
//        }
//    }
//
//    if(noauth_on) {
//        return ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_OK;
//    }
//
//
//
//    for(size_t i = 0; i < static_cast<size_t>(nmethods); ++i) {
//        char *methodp = buf->get_charp_at(2+i);
//        LOG(WARNING) << "the request from " << tunnel->from()->to_string()
//            << " has methods: " << *methodp;
//    }
//    return ProxyStmEvent::PROXY_STM_EVENT_ESTABLISH_NOACCEPT;
//
//}

}
}
}
