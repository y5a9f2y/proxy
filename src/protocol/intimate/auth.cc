#include <exception>

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "core/server.h"
#include "protocol/intimate/auth.h"
#include "core/buffer.h"
#include "core/config.h"
#include "crypto/aes.h"
#include "glog/logging.h"


using proxy::core::ProxyStmEvent;
using proxy::core::ProxyTunnel;
using proxy::core::ProxyBuffer;
using proxy::core::ProxyConfig;


namespace proxy {
namespace protocol {
namespace intimate {

ProxyStmEvent ProxyProtoAuthenticate::on_identification_send(
    std::shared_ptr<ProxyTunnel> &tunnel) {

    /*
    **   All of the following data is encryped by aes-256-ctr
    **   +----------+-----------+----------+-----------+
    **   |   ULEN   |  CONTENT  |   PLEN   |  CONTENT  |
    **   +----------------------+----------+-----------+
    **   |  4bytes  |  username |  4bytes  |  password |
    **   +----------+-----------+----------+-----------+
    */

    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;

    size_t alloc_bsize = 8 + ProxyConfig::USERNAME_MAX_LENGTH + ProxyConfig::PASSWORD_MAX_LENGTH;

    try {
        buf0 = std::make_shared<ProxyBuffer>(alloc_bsize); 
        buf1 = std::make_shared<ProxyBuffer>(alloc_bsize);
    } catch(const std::exception &ex) {
        LOG(ERROR) << tunnel->to_string() 
            << ": create the buffer from authentication error: " << ex.what();
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    const std::string &user = tunnel->server()->config().username();
    const std::string &pass = tunnel->server()->config().password();
    uint32_t *ulenp = reinterpret_cast<uint32_t *>(&buf0->buffer[0]);
    uint32_t *plenp = reinterpret_cast<uint32_t *>(&buf0->buffer[4 + user.size()]);
    size_t ulen = user.size();
    size_t plen = pass.size();
    *ulenp = htonl(static_cast<uint32_t>(ulen));
    *plenp = htonl(static_cast<uint32_t>(plen));

    for(size_t i = 0; i < ulen; ++i) {
        buf0->buffer[i+4] = user[i];
    }

    for(size_t i = 0; i < plen; ++i) {
        buf0->buffer[i+8+ulen] = pass[i];
    }

    buf0->cur = 8 + ulen + plen;

    if(!proxy::crypto::ProxyCryptoAes::aes_cfb_encrypt(tunnel->aes_ctx(), buf0, buf1)) {
        LOG(ERROR) << tunnel->to_string() << ": encrypt the authentication message error";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    if(buf0->cur != buf1->cur) {
        LOG(ERROR) << tunnel->to_string()
            << ": the length of the encrypted identification data is wrong";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    size_t towrite = buf1->cur;
    ssize_t nwrite = tunnel->write_to_eq(towrite, buf1);
    if(nwrite < 0 || towrite != static_cast<size_t>(nwrite)) {
        LOG(ERROR) << tunnel->to_string() << ": send the encrypted identification data error: "
            << strerror(errno);
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_OK;

}

ProxyStmEvent ProxyProtoAuthenticate::on_identification_receive(
    std::shared_ptr<ProxyTunnel> &tunnel) {

    /*
    **   All of the following data is encryped by aes-256-ctr
    **   +----------+-----------+----------+-----------+
    **   |   ULEN   |  CONTENT  |   PLEN   |  CONTENT  |
    **   +----------------------+----------+-----------+
    **   |  4bytes  |  username |  4bytes  |  password |
    **   +----------+-----------+----------+-----------+
    */

    uint32_t ulen;
    if(!tunnel->read_decrypted_4bytes_from(ulen)) {
        LOG(ERROR) << "read the length of the username from "  << tunnel->from()->to_string()
            << " error";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }
    if(ulen > ProxyConfig::USERNAME_MAX_LENGTH) {
        LOG(ERROR) << "the length of the username from " << tunnel->from()->to_string()
            << " too long: " << ulen;
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    LOG(INFO) << "the received length of the username from " << tunnel->from()->to_string()
        << " is: " << ulen;

    std::string username;
    if(!tunnel->read_decrypted_string_from(ulen, username)) {
        LOG(ERROR) << "read the username from " << tunnel->from()->to_string()
            << " error";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    LOG(INFO) << "the received username from " << tunnel->from()->to_string() << " is: "
        << username;

    uint32_t plen;
    if(!tunnel->read_decrypted_4bytes_from(plen)) {
        LOG(ERROR) << "read the length of the password from " << tunnel->from()->to_string()
            << " error";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }
    if(plen > ProxyConfig::PASSWORD_MAX_LENGTH) {
        LOG(ERROR) << "the length of the password from " << tunnel->from()->to_string()
            << " too long: " << plen;
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    LOG(INFO) << "the received length of the password from " << tunnel->from()->to_string()
        << " is: " << plen;

    std::string password;
    if(!tunnel->read_decrypted_string_from(plen, password)) {
        LOG(ERROR) << "read the password from " << tunnel->from()->to_string()
            << " error";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    LOG(INFO) << "the received password from " << tunnel->from()->to_string() << " is: "
        << password;

    if(tunnel->server()->config().username() != username || 
        tunnel->server()->config().password() != password) {
        LOG(ERROR) << "authenticating from " << tunnel->from()->to_string()
            << " error: wrong ugi(" << username << ", " << password << ")";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_OK;

}

}
}
}
