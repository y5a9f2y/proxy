#include <exception>

#include "crypto/aes.h"
#include "protocol/socks5/socks5.h"

#include "glog/logging.h"

using proxy::core::ProxyTunnel;
using proxy::core::ProxyBuffer;

namespace proxy {
namespace protocol {
namespace socks5 {

const char ProxyProtoSocks5::VERSION = 0x05;

bool ProxyProtoSocks5::on_connect(std::shared_ptr<ProxyTunnel> &tunnel) {

    /****************************************************
    **          +----+----------+----------+
    **          |VER | NMETHODS | METHODS  |
    **          +----+----------+----------+
    **          | 1  |    1     | 1 to 255 |
    **          +----+----------+----------+
    ****************************************************/

    unsigned char version;

    if(!tunnel->read_decrypted_byte_from(version)) {
        LOG(ERROR) << "read the socks version from " << tunnel->from()->to_string() << " error";
        return false;
    }

    if(version != ProxyProtoSocks5::VERSION) {
        LOG(ERROR) << "the request from " << tunnel->from()->to_string()
            << " require socks version: " << version;
        return false;
    }

    unsigned char nmethod;

    if(!tunnel->read_decrypted_byte_from(nmethod)) {
        LOG(ERROR) << "read the socks nmethod from " << tunnel->from()->to_string() << " error";
        return false;
    }

    std::string methods;

    if(!tunnel->read_decrypted_string_from(static_cast<size_t>(nmethod), methods)) {
        LOG(ERROR) << "read the socks methods from " << tunnel->from()->to_string() << " error";
        return false;
    }


    /****************************************************
    **                    Methods
    **      X'00' NO AUTHENTICATION REQUIRED
    **      X'01' GSSAPI
    **      X'02' USERNAME/PASSWORD
    **      X'03' to X'7F' IANA ASSIGNED
    **      X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    **      X'FF' NO ACCEPTABLE METHODS
    ****************************************************/

    bool accept = false;
    for(const auto &c : methods) {

        std::string name;

        switch(c) {
            case 0x00:
                accept = true;
                name = "no authentication required";
                break;
            case 0x01:
                name = "gssapi";
                break;
            case 0x02:
                name = "username/password";
                break;
            default:
                name = "unknown";
                break;
        }

        LOG(INFO) << "the connection from " << tunnel->from()->to_string() << " requires " << name;

    }

 
    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;
    try {
        buf0 = std::make_shared<ProxyBuffer>(2);
        buf1 = std::make_shared<ProxyBuffer>(2);
    } catch (const std::exception &ex) {
        LOG(ERROR) << "create the buffer to response the connect request from "
           << tunnel->from()->to_string() << " error: " << ex.what();
        return false;
    }

    buf0->buffer[0] = ProxyProtoSocks5::VERSION;
    if(accept) {
        buf0->buffer[1] = 0x00;
        LOG(INFO) << "the connect request from " << tunnel->from()->to_string() << " success";
    } else {
        buf0->buffer[1] = 0xff;
        LOG(INFO) << "the connect request from " << tunnel->from()->to_string()
            << " fail: no accept method";
    }

    // TODO encrypt here, the tunnel class need to be changed.

    return false;

}

}
}
}
