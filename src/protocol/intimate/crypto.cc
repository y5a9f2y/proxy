#include <exception>

#include "errno.h"
#include "string.h"

#include "protocol/intimate/crypto.h"
#include "protocol/intimate/ack.h"
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
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": create the buffer for the rsa public key error: " << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    buf->buffer[0] = 0xf;
    buf->buffer[1] = 0xa;
    buf->cur = 2;

    if(2 != tunnel->write_ep1_eq(2, buf)) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": send the rsa public key request message error: " << strerror(errno);
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

    if(5 != tunnel->read_ep1_eq(5, buf)) {
        LOG(ERROR) << tunnel->ep1_ep0_string() << ": read the meta of the rsa response error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    if(*buf->get_charp_at(0) != 0xe) {
        LOG(ERROR) << tunnel->ep1_ep0_string() << ": the type of the rsa response error: "
            << (*buf->get_charp_at(0));
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    uint32_t key_len = ntohl(*(reinterpret_cast<uint32_t *>(buf->get_charp_at(1))));
    if(key_len == 0) {
        LOG(ERROR) << tunnel->ep1_ep0_string() << ": the length of the rsa public key error: 0";
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    ssize_t nread = tunnel->read_ep1_eq(key_len, buf);
    if(nread < 0 || static_cast<uint32_t>(nread) != key_len) {
        LOG(ERROR) << tunnel->ep1_ep0_string() << ": read the rsa public key error: "
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
        LOG(ERROR) << "create the buffer for the rsa response of " << tunnel->ep0()->to_string()
            << " error: " << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    if(2 != tunnel->read_ep0_eq(2, buf)) {
        LOG(ERROR) << "read rsa public key request from " << tunnel->ep0()->to_string()
            << " error: " << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    char ty = *buf->get_charp_at(0);
    if(ty != 0xf) {
        LOG(ERROR) << "the request type of rsa request need to be 0xf, but " << ty
            << "received from " << tunnel->ep0()->to_string();
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    char bits = *buf->get_charp_at(1);
    if(bits != 0xa) {
        LOG(ERROR) << "the exponent of the rsa bit length need to be 0xa, but " << bits
            << "received from" << tunnel->ep0()->to_string();
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
    ssize_t nwrite = tunnel->write_ep0_eq(towrite, buf);
    if(nwrite < 0 || static_cast<size_t>(nwrite) != towrite) {
        LOG(ERROR) << "write the rsa public key to " << tunnel->ep0()->to_string() << " error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_RSA_NEGOTIATING_FAIL;
    }

    tunnel->rsa_key(key);

    return ProxyStmEvent::PROXY_STM_EVENT_RSA_PUBKEY_SEND;

}

ProxyStmEvent ProxyProtoCryptoNegotiate::on_aes_key_iv_send(
    std::shared_ptr<ProxyTunnel> &tunnel, ProxyProtoCryptoNegotiateDirect d) {

    /*
    **  C1/C3: the key, which is 32 bytes 
    **  C2/C4: the iv, which is 16 bytes
    **   +------+------+------+------+
    **   |  C1  |  C2  |  C3  |  C4  |
    **   +-------------+------+------+
    **   |  key |  iv  |  key |  iv  |
    **   +------+------+------+------+
    **  the data sent is encrypt by the rsa public key, the data is
    **   +----------+-----------+
    **   |  LENGTH  |  CONTENT  |
    **   +----------------------+
    **   |  4bytes  | enc-data  |
    **   +----------+-----------+
    */

    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;

    try {
        buf0 = std::make_shared<ProxyBuffer>(4096);
        buf1 = std::make_shared<ProxyBuffer>(4096);
    } catch(const std::exception &ex) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": create the buffer for aes negotiating error: " 
            << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    std::string key = tunnel->aes_key();
    for(size_t i = 0; i < key.size(); ++i) {
        buf0->buffer[buf0->cur++] = key[i];
    }

    std::string iv = tunnel->aes_iv();
    for(size_t i = 0; i < iv.size(); ++i) {
        buf0->buffer[buf0->cur++] = iv[i];
    }

    key = tunnel->aes_key_peer();
    for(size_t i = 0; i < key.size(); ++i) {
        buf0->buffer[buf0->cur++] = key[i];
    }

    iv = tunnel->aes_iv_peer();
    for(size_t i = 0; i < iv.size(); ++i) {
        buf0->buffer[buf0->cur++] = iv[i];
    }

    buf1->cur += 4;
    if(!proxy::crypto::ProxyCryptoRsa::rsa_encrypt(buf0, buf1, tunnel->rsa_key())) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": encrypt the aes key and iv error";
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    uint32_t *p = reinterpret_cast<uint32_t *>(buf1->get_charp_at(0));
    *p = htonl(static_cast<uint32_t>(buf1->cur - 4));


    size_t towrite = buf1->cur - buf1->start;

    ssize_t nwrite = 0;
    if(d == ProxyProtoCryptoNegotiateDirect::PROXY_PROTO_CRYPTO_NEGOTIATE_EP0) {
        nwrite = tunnel->write_ep0_eq(towrite, buf1);
    } else {
        nwrite = tunnel->write_ep1_eq(towrite, buf1);
    }
    if(nwrite < 0 || static_cast<size_t>(nwrite) != towrite) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": write the aes key and iv to error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    /* receive ack here */
    bool ack = false;
    if(d == ProxyProtoCryptoNegotiateDirect::PROXY_PROTO_CRYPTO_NEGOTIATE_EP0) {
        ack = ProxyProtoAck::on_ack_receive(tunnel, ProxyProtoAckDirect::PROXY_PROTO_ACK_EP0);
    } else {
        ack = ProxyProtoAck::on_ack_receive(tunnel, ProxyProtoAckDirect::PROXY_PROTO_ACK_EP1);
    }
    if(!ack) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": receive ack after sending aes key and iv error";
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    return ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_SEND;

}

ProxyStmEvent ProxyProtoCryptoNegotiate::on_aes_key_iv_receive(
    std::shared_ptr<ProxyTunnel> &tunnel, ProxyProtoCryptoNegotiateDirect d) {

    /*
    **  C1/C3: the key, which is 32 bytes 
    **  C2/C4: the iv, which is 16 bytes
    **   +------+------+------+------+
    **   |  C1  |  C2  |  C3  |  C4  |
    **   +-------------+------+------+
    **   |  key |  iv  |  key |  iv  |
    **   +------+------+------+------+
    **  the data sent is encrypt by the rsa public key, the data is
    **   +----------+-----------+
    **   |  LENGTH  |  CONTENT  |
    **   +----------------------+
    **   |  4bytes  | enc-data  |
    **   +----------+-----------+
    */

    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;

    try {
        buf0 = std::make_shared<ProxyBuffer>(4096);
        buf1 = std::make_shared<ProxyBuffer>(4096);
    } catch(const std::exception &ex) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": create the buffer for aes negotating error: "
            << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    ssize_t nread_length = 0;
    if(d == ProxyProtoCryptoNegotiateDirect::PROXY_PROTO_CRYPTO_NEGOTIATE_EP0) {
        nread_length = tunnel->read_ep0_eq(4, buf0);
    } else {
        nread_length = tunnel->read_ep1_eq(4, buf0);
    }
    if(4 != nread_length) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": read the length of the encrypt data error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    uint32_t p = ntohl(*reinterpret_cast<uint32_t *>(buf0->get_charp_at(0)));

    ssize_t nread = 0;
    if(d == ProxyProtoCryptoNegotiateDirect::PROXY_PROTO_CRYPTO_NEGOTIATE_EP0) {
        nread = tunnel->read_ep0_eq(static_cast<size_t>(p), buf0);
    } else {
        nread = tunnel->read_ep1_eq(static_cast<size_t>(p), buf0);
    }
    if(nread < 0 || static_cast<uint32_t>(nread) != p) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": read the encrypt aes key and iv error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    std::string key = tunnel->server()->rsa_keypair()->pri();
    buf0->start += 4;

    if(!proxy::crypto::ProxyCryptoRsa::rsa_decrypt(buf0, buf1, key)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": decrypt the aes key and iv error";
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    if(buf1->cur - buf1->start != 2 * proxy::crypto::ProxyCryptoAes::AES_KEY_SIZE +
        2 * proxy::crypto::ProxyCryptoAes::AES_IV_SIZE) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": check the length of aes key and iv error";
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    tunnel->aes_key_peer(std::string(buf1->get_charp_at(0),
        proxy::crypto::ProxyCryptoAes::AES_KEY_SIZE));

    tunnel->aes_iv_peer(std::string(buf1->get_charp_at(proxy::crypto::ProxyCryptoAes::AES_KEY_SIZE),
        proxy::crypto::ProxyCryptoAes::AES_IV_SIZE));

    tunnel->aes_ctx_peer_setup(proxy::crypto::ProxyCryptoAesContextType::AES_CONTEXT_DECRYPT_TYPE);

    tunnel->aes_key(std::string(buf1->get_charp_at(proxy::crypto::ProxyCryptoAes::AES_KEY_SIZE +
        proxy::crypto::ProxyCryptoAes::AES_IV_SIZE), proxy::crypto::ProxyCryptoAes::AES_KEY_SIZE));

    tunnel->aes_iv(std::string(buf1->get_charp_at(2 * proxy::crypto::ProxyCryptoAes::AES_KEY_SIZE +
        proxy::crypto::ProxyCryptoAes::AES_IV_SIZE), proxy::crypto::ProxyCryptoAes::AES_IV_SIZE));

    tunnel->aes_ctx_setup(proxy::crypto::ProxyCryptoAesContextType::AES_CONTEXT_ENCRYPT_TYPE);

    bool ack;
    if(d == ProxyProtoCryptoNegotiateDirect::PROXY_PROTO_CRYPTO_NEGOTIATE_EP0) {
        ack = ProxyProtoAck::on_ack_send(tunnel, ProxyProtoAckDirect::PROXY_PROTO_ACK_EP0);
    } else {
        ack = ProxyProtoAck::on_ack_send(tunnel, ProxyProtoAckDirect::PROXY_PROTO_ACK_EP1);
    }

    if(!ack) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": send ack after receiving aes key and iv error";
        return ProxyStmEvent::PROXY_STM_EVENT_AES_NEGOTIATING_FAIL;
    }

    return ProxyStmEvent::PROXY_STM_EVENT_AES_KEY_RECEIVE;

}


}
}
}
