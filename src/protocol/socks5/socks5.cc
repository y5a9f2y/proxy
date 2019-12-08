#include <exception>
#include <string>

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
    if(!tunnel->read_decrypted_byte_from_ep0(version)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << " read the socks version error";
        return false;
    }
    if(version != ProxyProtoSocks5::VERSION) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << " requires unexpected socks version: " << version;
        return false;
    }

    unsigned char nmethod;
    if(!tunnel->read_decrypted_byte_from_ep0(nmethod)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << " read the socks nmethod error";
        return false;
    }

    std::string methods;
    if(!tunnel->read_decrypted_string_from_ep0(static_cast<size_t>(nmethod), methods)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << " read the socks methods error";
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
        LOG(INFO) << tunnel->ep0_ep1_string() << " requires " << name;
    }

 
    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;
    try {
        buf0 = std::make_shared<ProxyBuffer>(2);
        buf1 = std::make_shared<ProxyBuffer>(2);
    } catch (const std::exception &ex) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << " create the buffer to response the connect request error: " << ex.what();
        return false;
    }

    buf0->buffer[0] = ProxyProtoSocks5::VERSION;
    if(accept) {
        buf0->buffer[1] = 0x00;
        // TODO DELETE
        LOG(INFO) << tunnel->ep0_ep1_string() << " connects successfully";
    } else {
        buf0->buffer[1] = 0xff;
        // TODO DELETE
        LOG(INFO) << tunnel->ep0_ep1_string() << " the connect request fail: no accept method";
    }

    buf0->cur +=2;

    if(!proxy::crypto::ProxyCryptoAes::aes_cfb_encrypt(tunnel->aes_ctx(), buf0, buf1)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": encrypt the socks5 connecting response error";
        return false;
    }

    if(2 != tunnel->write_ep0_eq(2, buf1)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": write back the connecting response error";
        return false;
    }

    return true;

}

bool ProxyProtoSocks5::on_request(std::shared_ptr<ProxyTunnel> &tunnel) {

    /****************************************************
    **   +----+-----+------+------+----------+----------+
    **   |VER | CMD |  RSV | ATYP | DST.ADDR | DST.PORT |
    **   +----+-----+------+------+----------+----------+
    **   | 1  |  1  | 0x00 |  1   | Variable |     2    |
    **   +----+-----+------+------+----------+----------+
    **   VER : 0x05
    **   CMD :
    **      CONNECT: 0x01
    **      BIND: 0x02
    **      UDP ASSOCIATE: 0x03
    **   RSV : 0x00 reserved
    **   ATYPE : address type of following address
    **      IPV4 ADDRESS: 0x01
    **      DOMAIN NAME: 0x03
    **      IPV6 ADDRESS: 0x04
    **   DST.ADDR: desired destination address
    **   DST.PORT: desired destination port in network octet order
    ****************************************************/

    std::string data;
    if(!tunnel->read_decrypted_string_from_ep0(4, data)) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": read the request protocol VER/CMD/RSV/ATYP error";
        return false;
    }

    if(data[0] != ProxyProtoSocks5::VERSION) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": unexpected request VER with: "
            << static_cast<int>(data[0]);
        return false;
    }

    switch(data[1]) {
        case 0x01:
        case 0x02:
        case 0x03:
            break;
        default:
            LOG(ERROR) << tunnel->ep0_ep1_string() << ": unexpected request CMD with: "
                << static_cast<int>(data[1]);
            return false;
    }

    if(data[2] != 0x00) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": unexpected request RSV with: "
            << static_cast<int>(data[2]);
        return false;
    }

    std::string address;
    std::string address_type;

    switch(data[3]) {
        case 0x01:
            address_type = "ipv4";
            if(!tunnel->read_decrypted_string_from_ep0(4, address)) {
                LOG(ERROR) << tunnel->ep0_ep1_string()
                    << ": read the request DST.ADDR(ipv4) error";
                return false;
            }
            //LOG(INFO) << tunnel->ep0_ep1_string() << ": "<< static_cast<size_t>(address[0]) << "."
            //    << static_cast<size_t>(address[1]) << "."
            //    << static_cast<size_t>(address[2]) << "."
            //    << static_cast<size_t>(address[3]);
            break;
        case 0x03:
            address_type = "domain";
            unsigned char len;
            if(!tunnel->read_decrypted_byte_from_ep0(len)) {
                LOG(ERROR) << tunnel->ep0_ep1_string()
                    << ": read the request DST.ADDR(domain) error: read length error";
                return false;
            }
            if(!tunnel->read_decrypted_string_from_ep0(static_cast<size_t>(len), address)) {
                LOG(ERROR) << tunnel->ep0_ep1_string()
                    << ": read the request DST.ADDR(domain) error: read domain name error";
                return false;
            }
            break;
        case 0x04:
            // For the ProxySwitchyOmega, it will handle the ipv6 address as the domain name
            address_type = "ipv6";
            if(!tunnel->read_decrypted_string_from_ep0(16, address)) {
                LOG(ERROR) << tunnel->ep0_ep1_string()
                    << ": read the request DST.ADDR(ipv6) error";
                return false;
            }
            break;
        default:
            LOG(ERROR) << tunnel->ep0_ep1_string() << ": unexpected request ATYPE with: "
                << static_cast<int>(data[3]);
    }


    return true;
}

                
}
}
}
