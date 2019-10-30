#include <exception>

#include "errno.h"
#include "string.h"

#include "protocol/intimate/crypto.h"
#include "core/buffer.h"
#include "core/server.h"
#include "crypto/rsa.h"
#include "crypto/aes.h"
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

    return ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_RECEIVE;

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
            << "received from " << tunnel->from()->to_string();
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    char bits = *buf->get_charp_at(1);
    if(bits != 0xa) {
        LOG(ERROR) << "the exponent of the rsa bit length need to be 0xa, but " << bits
            << "received from" << tunnel->from()->to_string();
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

    size_t towrite = buf->cur - buf->start;
    ssize_t nwrite = tunnel->write_from_eq(towrite, buf);
    if(nwrite < 0 || static_cast<size_t>(nwrite) != towrite) {
        LOG(ERROR) << "write the rsa public key to " << tunnel->from()->to_string() << " error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    return ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND;

}

ProxyStmEvent ProxyProtoCryptoNegotiate::on_aes_key_iv_send(
    std::shared_ptr<ProxyTunnel> &tunnel) {

    /*
    **  C1: the key, which is 32 bytes 
    **  C2: the iv, which is 16bytes
    **   +------+------+
    **   |  C1  |  C2  |
    **   +-------------+
    **   |  key |  iv  |
    **   +------+------+
    **  the data sent is encrypt by the rsa public key, the data is
    **   +----------+-----------+
    **   |  LENGTH  |  CONTENT  |
    **   +----------------------+
    **   |  4bytes  | enc-data  |
    **   +----------+-----------+
    */

    std::shared_ptr<ProxyBuffer> from;
    std::shared_ptr<ProxyBuffer> to;

    try {
        from = std::make_shared<ProxyBuffer>(4096);
        to = std::make_shared<ProxyBuffer>(4096);
    } catch(const std::exception &ex) {
        LOG(ERROR) << tunnel->to_string() << ": create the buffer for aes negotiating error: " 
            << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    std::string key = tunnel->aes_key();
    std::string iv = tunnel->aes_iv();
    for(size_t i = 0; i < key.size(); ++i) {
        from->buffer[from->cur++] = key[i];
    }
    for(size_t i = 0; i < iv.size(); ++i) {
        from->buffer[from->cur++] = iv[i];
    }

    to->cur += 4;
    if(!proxy::crypto::ProxyCryptoRsa::rsa_encrypt(from, to, tunnel->rsa_key())) {
        LOG(ERROR) << tunnel->to_string() << ": encrypt the aes key and iv error";
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    uint32_t *p = reinterpret_cast<uint32_t *>(to->get_charp_at(0));
    *p = htonl(static_cast<uint32_t>(to->cur - 4));


    size_t towrite = to->cur - to->start;
    ssize_t nwrite = tunnel->write_to_eq(towrite, to);
    if(nwrite < 0 || static_cast<size_t>(nwrite) != towrite) {
        LOG(ERROR) << tunnel->to_string() << ": write the aes key and iv to error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    return ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_SEND;

}

ProxyStmEvent ProxyProtoCryptoNegotiate::on_aes_key_iv_receive(
    std::shared_ptr<ProxyTunnel> &tunnel) {

    /*
    **  C1: the key, which is 32 bytes 
    **  C2: the iv, which is 16bytes
    **   +------+------+
    **   |  C1  |  C2  |
    **   +-------------+
    **   |  key |  iv  |
    **   +------+------+
    **  the data sent is encrypt by the rsa public key, the data is
    **   +----------+-----------+
    **   |  LENGTH  |  CONTENT  |
    **   +----------------------+
    **   |  4bytes  | enc-data  |
    **   +----------+-----------+
    */

    std::shared_ptr<ProxyBuffer> from;
    std::shared_ptr<ProxyBuffer> to;

    try {
        from = std::make_shared<ProxyBuffer>(4096);
        to = std::make_shared<ProxyBuffer>(4096);
    } catch(const std::exception &ex) {
        LOG(ERROR) << "create the buffer for aes key and iv receive from"
            << tunnel->from()->to_string() << " error: " << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    if(4 != tunnel->read_from_eq(4, from)) {
        LOG(ERROR) << "read the length of the encrypt data from " << tunnel->from()->to_string()
            << " error: " << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    uint32_t p = ntohl(*reinterpret_cast<uint32_t *>(from->get_charp_at(0)));
    ssize_t nread = tunnel->read_from_eq(static_cast<size_t>(p), from);
    if(nread < 0 || static_cast<uint32_t>(nread) != p) {
        LOG(ERROR) << "read the encrypt data from " << tunnel->from()->to_string()
            << " error: " << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    std::string key = tunnel->server()->rsa_keypair()->pri();
    from->start += 4;

    if(!proxy::crypto::ProxyCryptoRsa::rsa_decrypt(from, to, key)) {
        LOG(ERROR) << "decrypt the aes key and iv from " << tunnel->from()->to_string()
            << " error";
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    if(to->cur - to->start !=
        proxy::crypto::ProxyCryptoAes::AES_KEY_SIZE + proxy::crypto::ProxyCryptoAes::AES_IV_SIZE) {
        LOG(ERROR) << "check the length of aes key and iv from " << tunnel->from()->to_string()
            << " error";
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    tunnel->aes_key(std::string(to->get_charp_at(0), proxy::crypto::ProxyCryptoAes::AES_KEY_SIZE));
    tunnel->aes_iv(std::string(to->get_charp_at(proxy::crypto::ProxyCryptoAes::AES_KEY_SIZE),
        proxy::crypto::ProxyCryptoAes::AES_IV_SIZE));

    return ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_RECEIVE;

}



}
}
}
