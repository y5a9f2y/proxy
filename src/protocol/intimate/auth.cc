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
        LOG(ERROR) << tunnel->ep0_ep1_string()
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
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": encrypt the authentication message error";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    if(buf0->cur != buf1->cur) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": the length of the encrypted identification data is wrong";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    size_t towrite = buf1->cur;
    ssize_t nwrite = tunnel->write_ep1_eq(towrite, buf1);
    if(nwrite < 0 || towrite != static_cast<size_t>(nwrite)) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << ": send the encrypted identification data error: " << strerror(errno);
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
    if(!tunnel->read_decrypted_4bytes_from_ep0(ulen)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": read the length of the username error";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }
    if(ulen > ProxyConfig::USERNAME_MAX_LENGTH) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": the length of the username too long: " << ulen;
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    // TODO DELETE
    LOG(INFO) << tunnel->ep0_ep1_string() << ": the received length of the username is: " << ulen;

    std::string username;
    if(!tunnel->read_decrypted_string_from_ep0(ulen, username)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": read the username error";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    // TODO DELETE
    LOG(INFO) << tunnel->ep0_ep1_string() << ": the received username is: " << username;

    uint32_t plen;
    if(!tunnel->read_decrypted_4bytes_from_ep0(plen)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": read the length of the password error";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }
    if(plen > ProxyConfig::PASSWORD_MAX_LENGTH) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": the length of the password too long: " << plen;
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    // TODO DELETE
    LOG(INFO) << tunnel->ep0_ep1_string() << ": the received length of the password is: " << plen;

    std::string password;
    if(!tunnel->read_decrypted_string_from_ep0(plen, password)) {
        LOG(ERROR) << tunnel->ep0_ep1_string() << ": read the password error";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    // TODO DELETE
    LOG(INFO) << tunnel->ep0_ep1_string() << ": the received password is: " << password;

    if(tunnel->server()->config().username() != username || 
        tunnel->server()->config().password() != password) {
        LOG(ERROR) << tunnel->ep0_ep1_string()
            << " authenticates error with username[" << username << "] and password["
            << password << "]";
        return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_FAIL;
    }

    return ProxyStmEvent::PROXY_STM_EVENT_AUTHENTICATING_OK;

}

}
}
}
