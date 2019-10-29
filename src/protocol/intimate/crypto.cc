#include <exception>

#include "errno.h"
#include "string.h"

#include "protocol/intimate/crypto.h"
#include "core/buffer.h"
#include "core/server.h"
#include "glog/logging.h"

using proxy::core::ProxyStmEvent;
using proxy::core::ProxyTunnel;
using proxy::core::ProxyBuffer;

namespace proxy {
namespace protocol {
namespace intimate {

ProxyStmEvent ProxyProtoCryptoNegotiate::on_rsa_pubkey_request(
    std::shared_ptr<ProxyTunnel> &tunnel) {

    /*
    **  the request message type is 0xf,
    **  the length bits is 0xa, 2^10
    **    +------+------+
    **    | TYPE | BITS |
    **    +------+-------
    **    | 0xf  | 0xa  |
    **    +------+------+
    */

    std::shared_ptr<ProxyBuffer> buf;

    try {
        buf = std::make_shared<ProxyBuffer>(4096);
    } catch(const std::exception &ex) {
        LOG(ERROR) << tunnel->to_string() << ": create the buffer for the rsa public key error: "
            << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    buf->buffer[0] = 0xf;
    buf->buffer[1] = 0xa;
    buf->cur = 2;

    if(2 != tunnel->write_to_eq(2, buf)) {
        LOG(ERROR) << tunnel->to_string() << ": send the rsa public key request message error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    buf->clear();

    /*
    ** the response message type is 0xe,
    ** the length is the length of rsa public key(in byte),
    ** the content is the rsa public key
    **    +------+--------+-------------+
    **    | TYPE | LENGTH |   CONTENT   |
    **    +------+----------------------+
    **    | 0xe  | 4byte  | RSA PUB KEY |
    **    +------+--------+-------------+
    */

    if(5 != tunnel->read_to_eq(5, buf)) {
        LOG(ERROR) << tunnel->to_reverse_string() << ": read the meta of the rsa response error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    if(*buf->get_charp_at(0) != 0xe) {
        LOG(ERROR) << tunnel->to_reverse_string() << ": the type of the rsa response error: "
            << (*buf->get_charp_at(0));
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    uint32_t key_len = ntohl(*(reinterpret_cast<uint32_t *>(buf->get_charp_at(1))));
    if(key_len == 0) {
        LOG(ERROR) << tunnel->to_reverse_string() << ": the length of the rsa public key error: 0";
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    ssize_t nread = tunnel->read_to_eq(key_len, buf);
    if(nread < 0 || static_cast<uint32_t>(nread) != key_len) {
        LOG(ERROR) << tunnel->to_reverse_string() << ": read the rsa public key error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    tunnel->rsa_key(std::string(buf->get_charp_at(5), key_len));

    return ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECIEVE;

}

ProxyStmEvent ProxyProtoCryptoNegotiate::on_rsa_pubkey_response(
    std::shared_ptr<ProxyTunnel> &tunnel) {

    /*
    **  the request message type is 0xf,
    **  the length bits is 0xa, 2^10
    **    +------+------+
    **    | TYPE | BITS |
    **    +------+-------
    **    | 0xf  | 0xa  |
    **    +------+------+
    */

    std::shared_ptr<ProxyBuffer> buf;

    try {
        buf = std::make_shared<ProxyBuffer>(4096);
    } catch(const std::exception &ex) {
        LOG(ERROR) << "create the buffer for the rsa response of " << tunnel->from()->to_string()
            << " error: " << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    if(2 != tunnel->read_from_eq(2, buf)) {
        LOG(ERROR) << "read rsa public key request from " << tunnel->from()->to_string()
            << " error: " << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    char ty = *buf->get_charp_at(0);
    if(ty != 0xf) {
        LOG(ERROR) << "the request type of rsa request need to be 0xf, but " << ty
            << "recieved from " << tunnel->from()->to_string();
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    char bits = *buf->get_charp_at(1);
    if(bits != 0xa) {
        LOG(ERROR) << "the exponent of the rsa bit length need to be 0xa, but " << bits
            << "recieved from" << tunnel->from()->to_string();
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    /*
    ** the response message type is 0xe,
    ** the length is the length of rsa public key(in byte),
    ** the content is the rsa public key
    **    +------+--------+-------------+
    **    | TYPE | LENGTH |   CONTENT   |
    **    +------+----------------------+
    **    | 0xe  | 4byte  | RSA PUB KEY |
    **    +------+--------+-------------+
    */

    buf->clear();
    buf->buffer[0] = 0xe;
    uint32_t *p = reinterpret_cast<uint32_t *>(&buf->buffer[1]);

    std::string key = tunnel->server()->rsa_keypair()->pub();
    *p = htonl(static_cast<uint32_t>(key.size()));
    for(size_t i = 0; i < key.size() && i + 5 < buf->size; ++ i) {
        buf->buffer[i+5] = key[i];
    }
    buf->cur = 5 + key.size();
    buf->cur = (buf->cur < buf->size) ? buf->cur : buf->size;

    ssize_t nwrite = tunnel->write_from_eq(buf->cur - buf->start, buf);
    if(nwrite < 0 || static_cast<size_t>(nwrite) != buf->cur - buf->start) {
        LOG(ERROR) << "write the rsa public key to " << tunnel->from()->to_string() << " error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    return ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND;

}

}
}
}
