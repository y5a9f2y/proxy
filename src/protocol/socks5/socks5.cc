#include <exception>
#include <string>
#include <sstream>

#include "crypto/aes.h"
#include "core/socket.h"
#include "protocol/socks5/socks5.h"
#include "protocol/dns/dns.h"

#include "glog/logging.h"

using proxy::core::ProxyTunnel;
using proxy::core::ProxyBuffer;
using proxy::core::ProxyTcpSocket;
using proxy::protocol::dns::ProxyProtoDnsUnblockResolver;

namespace proxy {
namespace protocol {
namespace socks5 {

const char ProxyProtoSocks5::VERSION = 0x05;

bool ProxyProtoSocks5::on_handshake(std::shared_ptr<ProxyTunnel> &tunnel) {

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
    **          +----+--------+
    **          |VER | METHOD |
    **          +----+--------+
    **          | 1  |   1    |
    **          +----+--------+
    ****************************************************/

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

    if(!accept) {
        LOG(ERROR) << "[UNSURPORT]" << tunnel->ep0_ep1_string() << " requires unsupported methods";
        return false;
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
    buf0->buffer[1] = 0x00;
    buf0->cur +=2;

    if(!proxy::crypto::ProxyCryptoAes::aes_cfb_encrypt(tunnel->aes_ctx(), buf0, buf1)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": encrypt the socks5 handshake response error";
        return false;
    }

    if(2 != tunnel->write_ep0_eq(2, buf1)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": write back the handshake response error";
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

    std::string cmd;
    switch(data[1]) {
        case 0x01:
            cmd = "connect";
            break;
        case 0x02:
            cmd = "bind";
            break;
        case 0x03:
            cmd = "udp associate";
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
    std::ostringstream oss;

    // for ipv6 address
    unsigned char n = 0;
    unsigned char p = 0;

    switch(data[3]) {
        case 0x01:
            address_type = "ipv4";
            if(!tunnel->read_decrypted_string_from_ep0(4, address)) {
                LOG(ERROR) << tunnel->ep0_ep1_string()
                    << ": read the request DST.ADDR(ipv4) error";
                return false;
            }
            for(size_t i = 0; i < 4; ++i) {
                if(i) {
                    oss << ".";
                }
                oss << static_cast<size_t>(address[i]);
            }
            address = oss.str();
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
            address_type = "ipv6";
            if(!tunnel->read_decrypted_string_from_ep0(16, address)) {
                LOG(ERROR) << tunnel->ep0_ep1_string()
                    << ": read the request DST.ADDR(ipv6) error";
                return false;
            }
            for(size_t i = 0; i < 16; ++i) {
                if(i && (i % 2 == 0)) {
                    oss << ":";
                }
                n = static_cast<uint8_t>(address[i]);
                for(size_t j = 0; j < 2; ++j) {
                    p = (j == 0) ? (n / 16) : (n % 16); 
                    if(p < 10) {
                        oss << static_cast<char>(p + '0');
                    } else {
                        oss << static_cast<char>(p + 'a');
                    }
                }
            }
            address = oss.str();
            break;
        default:
            LOG(ERROR) << tunnel->ep0_ep1_string() << ": unexpected request ATYPE with: "
                << static_cast<int>(data[3]);
            return false;
    }

    uint16_t port = 0;
    if(!(tunnel->read_decrypted_byte_from_ep0(n) && tunnel->read_decrypted_byte_from_ep0(p))) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": read the request DST.PORT error";
        return false;
    } else {
        port = static_cast<uint16_t>(n) * 256 + static_cast<uint16_t>(p);
    }

    if(data[3] == 0x03) {
        std::string ip;
        {
            struct in_addr domain_addr;
            ProxyProtoDnsUnblockResolver resolver;
            struct in_addr *addrp = resolver.resolv(address);
            if(!addrp) {
                LOG(ERROR) << tunnel->ep0_ep1_string() << ": resolv " << address << " error";
            } else {
                domain_addr = *addrp;
            }
            ip = inet_ntoa(domain_addr);
        }
        LOG(INFO) << tunnel->ep0_ep1_string() << " requests ["
            << address_type << "]" << address << "(" << ip << "):" << port;
        address = ip;
    } else {

        LOG(INFO) << tunnel->ep0_ep1_string() << " requests ["
            << address_type << "]" << address << ":" << port;

        if(data[3] == 0x04) {
            LOG(ERROR) << tunnel->ep0_ep1_string() << ": the ipv6 ATYPE is not supported";
        }

        return false;

    }

    /****************************************************
    **   +----+-----+------+------+----------+----------+
    **   |VER | REP |  RSV | ATYP | BND.ADDR | BND.PORT |
    **   +----+-----+------+------+----------+----------+
    **   | 1  |  1  | 0x00 |  1   | Variable |     2    |
    **   +----+-----+------+------+----------+----------+
    **   VER : 0x05
    **   REP :
    **      succeeded: 0x00
    **      general SOCKS server failure: 0x01
    **      connection not allowed by ruleset: 0x02
    **      network unreachable: 0x03
    **      host unreachable: 0x04
    **      connection refused: 0x05
    **      ttl expired: 0x06
    **      command not supported: 0x07
    **      address type not supported: 0x08
    **      unassigned: 0x09
    **   RSV : 0x00 reserved
    **   ATYPE : address type of following address
    **      ADDRESS: 0x01
    **      DOMAIN NAME: 0x03
    **      IPV6 ADDRESS: 0x04
    **   DST.ADDR: server bound address
    **   DST.PORT: server bound port in network octet order
    ****************************************************/

    switch(data[1]) {
        case 0x01:
            break;
        default:
            LOG(ERROR) << "[UNSURPORT]"<< tunnel->ep0_ep1_string()
                << " requires unsurported command - " << cmd;
            return false;
    }

    try {
        tunnel->ep1(std::make_shared<ProxyTcpSocket>(AF_INET, 0));
        tunnel->ep1()->host(address);
        tunnel->ep1()->port(port);
    } catch(const std::exception &ex) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": create a socket to ep1 error: " << ex.what(); 
        return false;
    }

    try {
        tunnel->ep1()->connect();
    } catch(const std::exception &ex) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": connect to ep1 error: " << ex.what();
        return false;
    }

    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;
    try {
        buf0 = std::make_shared<ProxyBuffer>(10);
        buf1 = std::make_shared<ProxyBuffer>(10);
    } catch(const std::exception &ex) {
        LOG(ERROR) << tunnel->ep0_ep1_string() 
            << ": create the response buffer for connect request error: " << ex.what();
        return false;
    }
    buf0->buffer[0] = ProxyProtoSocks5::VERSION;
    buf0->buffer[1] = 0x00;
    buf0->buffer[2] = 0x00;
    buf0->buffer[3] = 0x01;
    {
        struct in_addr t_in_addr;
        if(!inet_aton(tunnel->ep1()->host().c_str(), &t_in_addr)) {
            LOG(ERROR) << tunnel->ep0_ep1_string() << ": calculate the in_addr structure of "
                << tunnel->ep1()->host() << "error";
            return false;
        }
        uint32_t n = t_in_addr.s_addr;
        for(size_t j = 7; j > 3; --j) {
            buf0->buffer[j] = n % 256;
            n /= 256;
        }
    }
    buf0->buffer[8] = port / 256;
    buf0->buffer[9] = port % 256;
    buf0->cur = 10;

    if(!proxy::crypto::ProxyCryptoAes::aes_cfb_encrypt(tunnel->aes_ctx(), buf0, buf1)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": encrypt the connecting response error";
        return false;
    }

    if(10 != tunnel->write_ep0_eq(10, buf1)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": write back the connecting response error";
        return false;
    }

    return true;
}

                
}
}
}
