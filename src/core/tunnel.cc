#include <exception>

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "core/tunnel.h"
#include "core/server.h"

#include "glog/logging.h"

namespace proxy {
namespace core {

ssize_t ProxyTunnel::read_ep0_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    _update_ktime();
    return _ep0->read_eq(n, buffer);
}

ssize_t ProxyTunnel::write_ep0_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    _update_ktime();
    return _ep0->write_eq(n, buffer);
}

ssize_t ProxyTunnel::read_ep1_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    _update_ktime();
    return _ep1->read_eq(n, buffer);
}

ssize_t ProxyTunnel::write_ep1_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    _update_ktime();
    return _ep1->write_eq(n, buffer);
}

bool ProxyTunnel::_read_decrypted_byte(unsigned char &data, bool flag) {
    
    // flag:
    //     if true, read the ep0 (endpoint0)
    //     else, read the ep1 (endpoint1)
    
    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;

    try {
        buf0 = std::make_shared<ProxyBuffer>(1);
        buf1 = std::make_shared<ProxyBuffer>(1);
    } catch(const std::exception &ex) {
        LOG(ERROR) << "create the buffer to read decrypted byte error";
        return false;
    }

    if(flag) {
        if(1 != read_ep0_eq(1, buf0)) {
            LOG(ERROR) << "read 1 byte from the ep0 error: " << strerror(errno);
            return false;
        }
    } else {
        if(1 != read_ep1_eq(1, buf0)) {
            LOG(ERROR) << "read 1 byte from the ep1 error: " << strerror(errno);
            return false;
        }
    }

    if(!proxy::crypto::ProxyCryptoAes::aes_cfb_decrypt(_aes_ctx_peer, buf0, buf1)) {
        LOG(ERROR) << "decrypt the received 1 byte error";
        return false;
    }

    data = static_cast<unsigned char>(buf1->buffer[0]);

    return true;

}

bool ProxyTunnel::read_decrypted_byte_from_ep0(unsigned char &data) {
    return _read_decrypted_byte(data, true);
}

bool ProxyTunnel::read_decrypted_byte_from_ep1(unsigned char &data) {
    return _read_decrypted_byte(data, false);
}

bool ProxyTunnel::_read_decrypted_4bytes(uint32_t &data, bool flag) {

    // flag:
    //     if true, read the ep0 (endpoint0)
    //     else, read the ep1 (endpoint1)
    
    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;

    try {
        buf0 = std::make_shared<ProxyBuffer>(4);
        buf1 = std::make_shared<ProxyBuffer>(4);
    } catch(const std::exception &ex) {
        LOG(ERROR) << "create the buffer to read decrypted 4bytes error";
        return false;
    }

    if(flag) {
        if(4 != read_ep0_eq(4, buf0)) {
            LOG(ERROR) << "read 4 bytes from the ep0 error: " << strerror(errno);
            return false;
        }
    } else {
        if(4 != read_ep1_eq(4, buf0)) {
            LOG(ERROR) << "read 4 bytes from the ep1 error: " << strerror(errno);
            return false;
        }
    }

    if(!proxy::crypto::ProxyCryptoAes::aes_cfb_decrypt(_aes_ctx_peer, buf0, buf1)) {
        LOG(ERROR) << "decrypt the received 4 bytes error";
        return false;
    }

    uint32_t *p = reinterpret_cast<uint32_t *>(buf1->get_charp_at(0));
    data = ntohl(*p);

    return true;

}

bool ProxyTunnel::read_decrypted_4bytes_from_ep0(uint32_t &data) {
    return _read_decrypted_4bytes(data, true);
}

bool ProxyTunnel::read_decrypted_4bytes_from_ep1(uint32_t &data) {
    return _read_decrypted_4bytes(data, false);
}

bool ProxyTunnel::_read_decrypted_string(size_t toread, std::string &data, bool flag) {

    // flag:
    //     if true, read the ep0 (endpoint0)
    //     else, read the ep1 (endpoint1)
    
    std::shared_ptr<ProxyBuffer> buf0;
    std::shared_ptr<ProxyBuffer> buf1;

    try {
        buf0 = std::make_shared<ProxyBuffer>(toread);
        buf1 = std::make_shared<ProxyBuffer>(toread);
    } catch(const std::exception &ex) {
        LOG(ERROR) << "create the buffer to read decrypted string error";
        return false;
    }

    ssize_t nread;
    if(flag) {
        nread = read_ep0_eq(toread, buf0);
    } else {
        nread = read_ep1_eq(toread, buf0);
    }

    if(nread < 0 || static_cast<size_t>(nread) != toread) {
        if(flag) {
            LOG(ERROR) << "read the string from the ep0 error: " << strerror(errno);
        } else {
            LOG(ERROR) << "read the string from the ep1 error: " << strerror(errno);
        }
        return false;
    }

    if(!proxy::crypto::ProxyCryptoAes::aes_cfb_decrypt(_aes_ctx_peer, buf0, buf1)) {
        LOG(ERROR) << "decrypt the received string error";
        return false;
    }

    data = std::string(buf1->buffer, buf1->cur);

    return true;
}

bool ProxyTunnel::read_decrypted_string_from_ep0(size_t n, std::string &data) {
    return _read_decrypted_string(n, data, true);
}

bool ProxyTunnel::read_decrypted_string_from_ep1(size_t n, std::string &data) {
    return _read_decrypted_string(n, data, false);
}

}
}
