#include <exception>

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "core/tunnel.h"
#include "core/server.h"

#include "glog/logging.h"

namespace proxy {
namespace core {

ssize_t ProxyTunnel::read_from_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    return _from->read_eq(n, buffer);
}

ssize_t ProxyTunnel::write_from_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    return _from->write_eq(n, buffer);
}

ssize_t ProxyTunnel::read_to_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    return _to->read_eq(n, buffer);
}

ssize_t ProxyTunnel::write_to_eq(size_t n, std::shared_ptr<ProxyBuffer> &buffer) {
    return _to->write_eq(n, buffer);
}

bool ProxyTunnel::_read_decrypted_byte(unsigned char &data, bool flag) {
    
    // flag:
    //     if true, read the from-endpoint
    //     else, read the to-endpoint
    
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
        if(1 != read_from_eq(1, buf0)) {
            LOG(ERROR) << "read 1 byte from the from-endpoint error: " << strerror(errno);
            return false;
        }
    } else {
        if(1 != read_to_eq(1, buf0)) {
            LOG(ERROR) << "read 1 byte from the to-endpoint error: " << strerror(errno);
            return false;
        }
    }

    if(!proxy::crypto::ProxyCryptoAes::aes_cfb_decrypt(_aes_ctx, buf0, buf1)) {
        LOG(ERROR) << "decrypt the received 1 byte error";
        return false;
    }

    data = static_cast<unsigned char>(buf1->buffer[0]);

    return true;

}

bool ProxyTunnel::read_decrypted_byte_from(unsigned char &data) {
    return _read_decrypted_byte(data, true);
}

bool ProxyTunnel::read_decrypted_byte_to(unsigned char &data) {
    return _read_decrypted_byte(data, false);
}

bool ProxyTunnel::_read_decrypted_4bytes(uint32_t &data, bool flag) {

    // flag:
    //     if true, read the from-endpoint
    //     else, read the to-endpoint
    
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
        if(4 != read_from_eq(4, buf0)) {
            LOG(ERROR) << "read 4 bytes from the from-endpoint error: " << strerror(errno);
            return false;
        }
    } else {
        if(4 != read_to_eq(4, buf0)) {
            LOG(ERROR) << "read 4 bytes from the to-endpoint error: " << strerror(errno);
            return false;
        }
    }

    if(!proxy::crypto::ProxyCryptoAes::aes_cfb_decrypt(_aes_ctx, buf0, buf1)) {
        LOG(ERROR) << "decrypt the received 4 bytes error";
        return false;
    }

    uint32_t *p = reinterpret_cast<uint32_t *>(buf1->get_charp_at(0));
    data = ntohl(*p);

    return true;

}

bool ProxyTunnel::read_decrypted_4bytes_from(uint32_t &data) {
    return _read_decrypted_4bytes(data, true);
}

bool ProxyTunnel::read_decrypted_4bytes_to(uint32_t &data) {
    return _read_decrypted_4bytes(data, false);
}

bool ProxyTunnel::_read_decrypted_string(size_t toread, std::string &data, bool flag) {

    // flag:
    //     if true, read the from-endpoint
    //     else, read the to-endpoint
    
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
        nread = read_from_eq(toread, buf0);
    } else {
        nread = read_to_eq(toread, buf0);
    }

    if(nread < 0 || static_cast<size_t>(nread) != toread) {
        if(flag) {
            LOG(ERROR) << "read the string from the from-endpoint error: " << strerror(errno);
        } else {
            LOG(ERROR) << "read the string from the to-endpoint error: " << strerror(errno);
        }
        return false;
    }

    if(!proxy::crypto::ProxyCryptoAes::aes_cfb_decrypt(_aes_ctx, buf0, buf1)) {
        LOG(ERROR) << "decrypt the received string error";
        return false;
    }

    data = std::string(buf1->buffer, buf1->cur);

    return true;
}

bool ProxyTunnel::read_decrypted_string_from(size_t n, std::string &data) {
    return _read_decrypted_string(n, data, true);
}

bool ProxyTunnel::read_decrypted_string_to(size_t n, std::string &data) {
    return _read_decrypted_string(n, data, false);
}

}
}
